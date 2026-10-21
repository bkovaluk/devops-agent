"""Triage Lambda: turn a batch of signals into investigation jobs, without a model.

Per distinct signal, in order: parse (signals.py), settle it at its source (a CloudWatch
alarm's config, resource keys and tags; a Datadog monitor read back and verified),
opt-out, repeat, cooldown, link. The signals left count toward the signal rate: while it
runs above the storm rate, one storm finding groups them and only the signal that opened
the storm is investigated. Otherwise what remains is one job per signal, or one incident
job when the batch is a storm; each job passes the budgets and goes to the work queue
under a pre-allocated finding id. A priority 1 or 2 job the budgets refuse goes back to
the alarms queue with a delay and is triaged again while its signal stands; a priority 3
or 4 job is recorded once per resource key an hour as skipped over budget. Every
decision emits a metric and a log line (decisions.py).

A signal is about one account (accounts.py). A member account's alarm is read through
its read-only role, its keys are scoped by the account, and its signals have their own
signal rate, storm and jobs; with member accounts each account also has its own share of
the budgets. A signal whose account the agent may not read is dropped.
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache, partial
from typing import Any, Literal

import boto3
from aws_lambda_powertools import Logger
from botocore.exceptions import ClientError

from devops_agent.accounts import (
    AccountAccessError,
    AccountSession,
    alarm_origin,
    function_partition,
    is_member,
    monitor_account,
    open_session,
    own_account,
    refusal,
    session_name,
)
from devops_agent.active import active_job, claim_keys, link_alarm, release_keys
from devops_agent.catalog import load_catalog
from devops_agent.config import TriageSettings, get_triage_settings
from devops_agent.datadog import DatadogClient, DatadogError, datadog_client
from devops_agent.decisions import Decision, record_decision
from devops_agent.findings import (
    build_triage_finding,
    closed_in_cooldown,
    open_investigation_for_alarm,
    record_recurrence,
    store_finding,
)
from devops_agent.gate import (
    consume_account_daily_budget,
    consume_account_hourly_budget,
    consume_account_p1_overflow,
    consume_daily_budget,
    consume_datadog_share,
    consume_hourly_budget,
    consume_p1_overflow,
    daily_tokens,
    hourly_count,
    refund_account_daily_budget,
    refund_account_hourly_budget,
    refund_account_p1_overflow,
    refund_daily_budget,
    refund_datadog_share,
    refund_hourly_budget,
    refund_p1_overflow,
)
from devops_agent.models import (
    AlarmStateChangeEvent,
    FindingKind,
    InvestigationJob,
    Severity,
    SignalRef,
    scoped_key,
)
from devops_agent.severity import (
    alarm_tags,
    env_floor,
    floor_for_priority,
    priority,
    rank,
    severity_floor,
)
from devops_agent.signals import (
    MAX_SIGNAL_TAGS,
    Signal,
    alarm_event,
    datadog_keys,
    monitor_signal_name,
    parse_signal,
    tag_list,
    tag_pairs,
)
from devops_agent.storm import (
    Storm,
    active_storm,
    claim_storm,
    count_on_storm,
    end_storm,
    record_rate,
    set_storm_head,
)
from devops_agent.tools import (
    ToolError,
    consumer_functions,
    describe_alarm,
    primary_key,
    queue_arn,
    stream_arn,
)
from devops_agent.verify import verify_monitor

logger = Logger(service="devops-agent")
logging.getLogger("botocore").setLevel(logging.WARNING)

MAX_INCIDENT_ALARMS = 50
OPEN_FINDING_PAGE = 50
OPEN_FINDING_PAGES = 2
# Settling a signal takes a few calls; stop with this much time left and let SQS
# redeliver the rest.
DEADLINE_RESERVE_SECONDS = 20.0
# Finding ids derive from the SQS message id, so a redelivered record writes the same
# finding (a conditional put no-op) and emits the same job id.
_FINDING_ID_NAMESPACE = uuid.UUID("5d1f4f0e-8a51-4a9c-9a43-2b1f0f6f0a77")
# SQS's longest message delay. A budget-deferred signal is triaged again after it.
DEFERRED_RETRY_DELAY_SECONDS = 900
# Top-level fields triage adds to an event it sends back to the alarms queue: the retry
# count, and the finding id the signal's deferral was recorded under.
RETRY_FIELD = "devops_agent_retry"
DEFERRED_ID_FIELD = "devops_agent_finding_id"
# Jobs of this priority and below are skipped, not deferred, when the budgets refuse.
SKIPPED_PRIORITY = 3


@dataclass(frozen=True)
class AlarmReaders:
    """The clients that read an alarm, its tags and its consumer chain, in its account."""

    cloudwatch: Any
    lambda_: Any
    sqs: Any
    kinesis: Any

    @classmethod
    def of(cls, session: AccountSession) -> AlarmReaders:
        return cls(
            cloudwatch=session.client("cloudwatch"),
            lambda_=session.client("lambda"),
            sqs=session.client("sqs"),
            kinesis=session.client("kinesis"),
        )


@dataclass(frozen=True)
class TriageClients:
    """Triage's clients on the agent's own credentials. ``sqs`` also sends jobs and
    retries to the agent's queues; ``sts`` reaches member accounts."""

    cloudwatch: Any
    lambda_: Any
    sqs: Any
    kinesis: Any
    sts: Any
    table: Any

    @property
    def readers(self) -> AlarmReaders:
        return AlarmReaders(self.cloudwatch, self.lambda_, self.sqs, self.kinesis)


@lru_cache(maxsize=1)
def triage_clients(region: str, table_name: str) -> TriageClients:
    return TriageClients(
        cloudwatch=boto3.client("cloudwatch", region_name=region),
        lambda_=boto3.client("lambda", region_name=region),
        sqs=boto3.client("sqs", region_name=region),
        kinesis=boto3.client("kinesis", region_name=region),
        sts=boto3.client("sts", region_name=region),
        table=boto3.resource("dynamodb", region_name=region).Table(table_name),
    )


@dataclass
class _Accounts:
    """The accounts of one invocation: the agent's own (empty when unknown outside
    Lambda), and the alarm readers of each member account, opened on first use and kept
    for this invocation only."""

    clients: TriageClients
    settings: TriageSettings
    own: str
    partition: str
    name: str
    seconds_left: Callable[[], float]
    opened: dict[str, AlarmReaders] = field(default_factory=dict)

    def scope(self, account_id: str) -> str:
        """The account a signal's keys are scoped by: a member account, else none."""
        return account_id if is_member(account_id, self.own) else ""

    def readers(self, account_id: str) -> AlarmReaders:
        if not is_member(account_id, self.own):
            return self.clients.readers
        if account_id not in self.opened:
            session = open_session(
                account_id,
                own=self.own,
                settings=self.settings,
                sts=self.clients.sts,
                partition=self.partition,
                name=self.name,
                seconds_left=self.seconds_left(),
            )
            self.opened[account_id] = AlarmReaders.of(session)
        return self.opened[account_id]


@dataclass
class _Candidate:
    """One distinct signal in the batch and the SQS messages that carried it.

    ``body`` is the event as received, without the retry fields. ``retry`` counts the
    times the signal was sent back after a budget deferral, and ``deferred_id`` is the
    finding its deferral was recorded under. Settling fills ``keys`` (scoped by the
    member account in ``scope``), ``floor`` and ``tags`` and the signal's priority.
    """

    signal: Signal
    message_ids: list[str]
    body: dict[str, Any] = field(default_factory=dict)
    retry: int = 0
    deferred_id: str | None = None
    keys: list[str] = field(default_factory=list)
    floor: Severity = Severity.LOW
    tags: dict[str, str] = field(default_factory=dict)
    scope: str = ""

    @property
    def name(self) -> str:
        return self.signal.name

    @property
    def account_id(self) -> str:
        return self.signal.account_id

    @property
    def ref(self) -> SignalRef:
        return self.signal.as_ref()

    @property
    def finding_id(self) -> str:
        return str(uuid.uuid5(_FINDING_ID_NAMESPACE, self.message_ids[0]))

    @property
    def deferral_id(self) -> str:
        """The id a deferral of this signal is recorded under: the first one's, on a retry."""
        return self.deferred_id or self.finding_id

    def settle(self, keys: list[str], floor: Severity, tags: dict[str, str], scope: str) -> None:
        self.scope = scope
        self.keys = [scoped_key(key, scope) for key in keys]
        self.floor = floor
        self.tags = tags
        self.signal = self.signal.model_copy(
            update={"priority": priority(floor), "resource_keys": self.keys}
        )


@dataclass(frozen=True)
class _Follower:
    """A signal sharing ``key`` with a job planned earlier in the same batch."""

    candidate: _Candidate
    key: str


@dataclass(frozen=True)
class _Job:
    kind: Literal[FindingKind.ALARM, FindingKind.INCIDENT]
    signals: list[_Candidate]
    floor: Severity
    followers: list[_Follower] = field(default_factory=list)

    @property
    def head(self) -> _Candidate:
        return self.signals[0]

    @property
    def priority(self) -> int:
        return priority(self.floor)

    @property
    def finding_id(self) -> str:
        return self.head.finding_id

    @property
    def deferral_id(self) -> str:
        return self.head.deferral_id

    @property
    def account_id(self) -> str:
        return self.head.account_id

    @property
    def keys(self) -> list[str]:
        return list(dict.fromkeys(key for signal in self.signals for key in signal.keys))

    @property
    def everyone(self) -> list[_Candidate]:
        return [*self.signals, *(follower.candidate for follower in self.followers)]

    @property
    def message_ids(self) -> list[str]:
        return [message_id for signal in self.everyone for message_id in signal.message_ids]


def _decide(
    decision: Decision,
    settings: TriageSettings,
    candidate: _Candidate,
    message: str,
    **fields: Any,
) -> None:
    record_decision(
        decision,
        settings.environment,
        candidate.ref,
        message,
        per_account=settings.multi_account,
        **fields,
    )


def _retry_fields(body: Any) -> tuple[dict[str, Any], int, str | None]:
    """The event without the retry fields, its retry count and its deferred finding id."""
    if not isinstance(body, dict):
        return {}, 0, None
    event = {
        key: value for key, value in body.items() if key not in (RETRY_FIELD, DEFERRED_ID_FIELD)
    }
    retry = body.get(RETRY_FIELD)
    deferred_id = body.get(DEFERRED_ID_FIELD)
    return (
        event,
        retry if isinstance(retry, int) and not isinstance(retry, bool) and retry > 0 else 0,
        deferred_id if isinstance(deferred_id, str) and deferred_id else None,
    )


def _distinct_signals(records: Sequence[dict[str, Any]]) -> list[_Candidate]:
    candidates: dict[str, _Candidate] = {}
    for record in records:
        try:
            body = json.loads(record.get("body") or "")
        except ValueError:
            logger.info("ignored: record body is not JSON")
            continue
        raw, retry, deferred_id = _retry_fields(body)
        signal = parse_signal(raw)
        if signal is None:
            continue
        identity = f"{signal.account_id}/{signal.identity}"
        known = candidates.get(identity)
        if known is None:
            candidates[identity] = _Candidate(
                signal, [record["messageId"]], raw, retry, deferred_id
            )
            continue
        known.message_ids.append(record["messageId"])
        known.retry = max(known.retry, retry)
        known.deferred_id = known.deferred_id or deferred_id
    return list(candidates.values())


def _alarm_config(readers: AlarmReaders, alarm_name: str) -> dict[str, Any] | None:
    try:
        return describe_alarm(readers.cloudwatch, alarm_name)
    except ToolError:
        logger.info("alarm no longer exists", extra={"alarm_name": alarm_name})
    except ClientError as exc:
        logger.warning(
            "alarm config unavailable, keying by alarm name",
            extra={
                "alarm_name": alarm_name,
                "error_code": exc.response.get("Error", {}).get("Code"),
            },
        )
    return None


def _consumer_keys(readers: AlarmReaders, namespace: str, dimensions: dict[str, str]) -> list[str]:
    """The keys of the Lambdas consuming the queue or stream an alarm watches."""
    try:
        if namespace == "AWS/SQS" and (queue := dimensions.get("QueueName")):
            source_arn = queue_arn(readers.sqs, queue)
        elif namespace == "AWS/Kinesis" and (stream := dimensions.get("StreamName")):
            source_arn = stream_arn(readers.kinesis, stream)
        else:
            return []
        functions = consumer_functions(readers.lambda_, source_arn)
    except (ClientError, ToolError) as exc:
        logger.warning("consumer chain unavailable", extra={"error": type(exc).__name__})
        return []
    return [f"AWS/Lambda:FunctionName={function}" for function in functions]


def _keys(readers: AlarmReaders, alarm_name: str, config: dict[str, Any] | None) -> list[str]:
    primary = primary_key(config) if config else None
    if primary is None:
        return [f"alarm:{alarm_name}"]
    key, namespace, dimensions = primary
    return list(dict.fromkeys([key, *_consumer_keys(readers, namespace, dimensions)]))


def resource_keys(readers: AlarmReaders, alarm_name: str) -> list[str]:
    """The alarm's resource key, then its consumer chain's keys, in the alarm's account."""
    return _keys(readers, alarm_name, _alarm_config(readers, alarm_name))


def _instant(value: Any) -> datetime | None:
    """A timestamp as UTC to the millisecond; None when it cannot be read."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    at = (value if value.tzinfo else value.replace(tzinfo=UTC)).astimezone(UTC)
    return at.replace(microsecond=at.microsecond // 1000 * 1000)


def same_episode(config: dict[str, Any] | None, event: AlarmStateChangeEvent) -> bool:
    """True when the alarm is still in ALARM from the transition the event reported."""
    if config is None or config.get("StateValue") != "ALARM":
        return False
    transitioned = _instant(config.get("StateTransitionedTimestamp"))
    return transitioned is not None and transitioned == _instant(event.detail.state.timestamp)


def _tags(cloudwatch: Any, alarm_arn: str) -> dict[str, str]:
    if not alarm_arn:
        return {}
    try:
        return alarm_tags(cloudwatch, alarm_arn)
    except ClientError as exc:
        logger.warning(
            "alarm tags unavailable, using env floor",
            extra={"error_code": exc.response.get("Error", {}).get("Code")},
        )
        return {}


def opted_out(tags: dict[str, str]) -> bool:
    """True when the signal carries the catalog's opt-out tag, key and value in any case."""
    opt_out = load_catalog().agent.opt_out_tag
    return any(
        key.lower() == opt_out.key.lower() and value.strip().lower() == opt_out.value.lower()
        for key, value in tags.items()
    )


def _store(clients: TriageClients, settings: TriageSettings, now: datetime, **fields: Any) -> bool:
    """Store a triage finding once. False when one with its id is already stored."""
    return store_finding(
        clients.table, build_triage_finding(env=settings.environment, now=now, **fields)
    )


def _refuse_account(settings: TriageSettings, candidate: _Candidate, reason: str) -> bool:
    """Drop a signal whose account the agent may not read: a decision, no finding."""
    _decide(
        "skipped_account",
        settings,
        candidate,
        "dropped: account not investigated",
        reason=reason,
    )
    return True


def _settle_alarm(accounts: _Accounts, settings: TriageSettings, candidate: _Candidate) -> bool:
    """Keys, tags and floor of a CloudWatch alarm, read in its account. True when the
    alarm needs no job.

    An alarm from an account or region the agent may not read is dropped, and so is one
    whose member role refuses to be assumed; only a transient AssumeRole failure fails
    the record for SQS to retry. A retried alarm no longer in the ALARM episode it was
    deferred in is dropped too: it went back to OK, or its newer episode came with its
    own event.
    """
    signal = candidate.signal
    reason = alarm_origin(signal) or refusal(
        signal.account_id, signal.region, accounts.own, settings
    )
    if reason is not None:
        return _refuse_account(settings, candidate, reason)
    try:
        readers = accounts.readers(signal.account_id)
    except AccountAccessError as exc:
        if exc.transient:
            raise
        return _refuse_account(settings, candidate, str(exc))
    event = alarm_event(signal)
    config = _alarm_config(readers, candidate.name)
    if candidate.retry and not same_episode(config, event):
        _decide(
            "skipped_unverified",
            settings,
            candidate,
            "dropped: deferred alarm left its ALARM episode",
            retry=candidate.retry,
        )
        return True
    keys = _keys(readers, candidate.name, config)
    tags = _tags(readers.cloudwatch, event.alarm_arn)
    candidate.settle(keys, severity_floor(tags), tags, accounts.scope(signal.account_id))
    return False


def _settle_monitor(
    accounts: _Accounts,
    settings: TriageSettings,
    datadog: DatadogClient | None,
    candidate: _Candidate,
) -> bool:
    """Verify a Datadog signal and key it from the monitor. True when it is dropped.

    Keys, priority, account and opt-out tags come from the monitor Datadog returns, never
    from the payload; only the group, verified to be alerting, comes from the
    notification. The account is the monitor's account tag, else the agent's own.
    """
    signal = candidate.signal
    if datadog is None:
        _warn_missing_datadog_keys()
    verdict = verify_monitor(datadog, signal, settings.environment, priority(env_floor()))
    if verdict.monitor is None or verdict.reason is not None:
        if verdict.misrouted:
            logger.warning(
                "misrouted: Datadog monitor of another env",
                extra={"monitor_id": signal.ref.get("monitor_id")},
            )
        _decide(
            "skipped_unverified",
            settings,
            candidate,
            "dropped: Datadog signal not verified",
            reason=verdict.reason,
            monitor_id=signal.ref.get("monitor_id"),
        )
        return True
    monitor_tags = tag_list(verdict.monitor.get("tags"))
    query = str(verdict.monitor.get("query") or "")
    monitor_name = verdict.monitor.get("name")
    subject = (
        monitor_name
        if isinstance(monitor_name, str) and monitor_name
        else f"Datadog monitor {signal.ref['monitor_id']}"
    )
    account_id, problem = monitor_account(
        tag_pairs(monitor_tags), settings.datadog_account_tag, accounts.own
    )
    candidate.signal = signal.model_copy(
        update={
            "name": monitor_signal_name(subject, str(signal.ref.get("group"))),
            "subject": subject,
            "account_id": account_id,
            "region": settings.aws_region,
            "ref": {
                **signal.ref,
                "query": query,
                "monitor_type": str(verdict.monitor.get("type") or ""),
                "monitor_tags": monitor_tags[:MAX_SIGNAL_TAGS],
            },
        }
    )
    reason = problem or refusal(account_id, settings.aws_region, accounts.own, settings)
    if reason is not None:
        return _refuse_account(settings, candidate, reason)
    keys = datadog_keys(
        int(signal.ref["monitor_id"]),
        str(signal.ref.get("group")),
        signal.ref.get("group_tags", []),
        monitor_tags,
        query,
    )
    candidate.settle(
        keys,
        floor_for_priority(verdict.priority),
        tag_pairs(monitor_tags),
        accounts.scope(account_id),
    )
    return False


@lru_cache(maxsize=1)
def _warn_missing_datadog_keys() -> None:
    """Once per cold start: without keys every Datadog signal is dropped unverified."""
    logger.warning("Datadog keys not configured: Datadog signals are dropped as skipped_unverified")


def _settle(
    accounts: _Accounts,
    settings: TriageSettings,
    datadog: DatadogClient | None,
    candidate: _Candidate,
    now: datetime,
) -> bool:
    """Settle one signal at its source, then opt-out, repeat, cooldown and link. True when
    the signal needs no job."""
    if candidate.signal.source == "cloudwatch":
        dropped = _settle_alarm(accounts, settings, candidate)
    else:
        dropped = _settle_monitor(accounts, settings, datadog, candidate)
    return dropped or _settle_shared(accounts.clients, settings, candidate, now)


def _settle_shared(
    clients: TriageClients, settings: TriageSettings, candidate: _Candidate, now: datetime
) -> bool:
    ref = candidate.ref
    log_keys = {"alarm_name": candidate.name, "severity_floor": candidate.floor.value}

    if opted_out(candidate.tags):
        _store(
            clients,
            settings,
            now,
            signal=ref,
            resource_key=candidate.keys[0],
            floor=candidate.floor,
            kind=FindingKind.SKIPPED,
            finding_id=candidate.finding_id,
            title=f"Skipped: {candidate.name}",
            summary=f"{candidate.name} {ref.fired} and was not investigated: opted out by tag.",
        )
        _decide("opted_out", settings, candidate, "skipped: opted out by tag", **log_keys)
        return True

    repeat = open_investigation_for_alarm(
        clients.table, candidate.keys[0], candidate.name, OPEN_FINDING_PAGE, OPEN_FINDING_PAGES
    )
    if repeat is not None and repeat["finding_id"] == candidate.finding_id:
        logger.info("redelivered: signal already investigated", extra=log_keys)
        return True
    if repeat is not None and rank(Severity(repeat["severity_floor"])) >= rank(candidate.floor):
        record_recurrence(clients.table, str(repeat["finding_id"]), now)
        _decide("cooldown", settings, candidate, "repeat: counted on unclosed finding", **log_keys)
        return True
    if repeat is None:
        closed = closed_in_cooldown(
            clients.table,
            candidate.keys[0],
            ref.arn,
            now,
            alarm_cooldown=timedelta(minutes=settings.alarm_cooldown_minutes),
            resource_cooldown=timedelta(minutes=settings.resource_cooldown_minutes),
            limit=OPEN_FINDING_PAGE,
        )
        if closed is not None:
            record_recurrence(clients.table, str(closed["finding_id"]), now)
            _decide(
                "cooldown",
                settings,
                candidate,
                "repeat: counted on finding closed within its cooldown",
                **log_keys,
            )
            return True

    active = active_job(clients.table, candidate.keys, now)
    if active is not None and active[1] == candidate.finding_id:
        logger.info("redelivered: job already emitted", extra=log_keys)
        return True
    if active is not None and link_alarm(clients.table, active[0], candidate.name, now):
        key, job_id = active
        _store_linked(clients, settings, candidate, job_id, key, now)
        _decide(
            "linked",
            settings,
            candidate,
            "linked: running investigation covers the resource",
            **log_keys,
        )
        return True
    return False


def _store_linked(
    clients: TriageClients,
    settings: TriageSettings,
    candidate: _Candidate,
    job_id: str,
    key: str,
    now: datetime,
    *,
    finding_id: str | None = None,
) -> None:
    ref = candidate.ref
    _store(
        clients,
        settings,
        now,
        signal=ref,
        resource_key=candidate.keys[0],
        floor=candidate.floor,
        kind=FindingKind.LINKED,
        finding_id=finding_id or candidate.finding_id,
        linked_to=job_id,
        title=f"Linked: {candidate.name}",
        summary=(
            f"{candidate.name} {ref.fired} while investigation {job_id} covered {key}; it is "
            "recorded on that finding."
        ),
    )


def _by_priority(candidates: list[_Candidate]) -> list[_Candidate]:
    return sorted(candidates, key=lambda candidate: -rank(candidate.floor))


def plan_jobs(candidates: list[_Candidate], storm_threshold: int) -> list[_Job]:
    """Distinct jobs for the signals left after linking, per account, highest floor first.

    A job reads one account, so signals of different accounts never share one. Within an
    account, a signal sharing any key with one planned before it follows that signal's
    job, and when storm_threshold or more jobs remain they become one incident job.
    """
    accounts: dict[str, list[_Candidate]] = {}
    for candidate in candidates:
        accounts.setdefault(candidate.account_id, []).append(candidate)
    return [job for group in accounts.values() for job in _account_jobs(group, storm_threshold)]


def _account_jobs(candidates: list[_Candidate], storm_threshold: int) -> list[_Job]:
    leaders: list[_Candidate] = []
    owners: dict[str, _Candidate] = {}
    followers: dict[str, list[_Follower]] = {}
    for candidate in _by_priority(candidates):
        shared = next((key for key in candidate.keys if key in owners), None)
        if shared is not None:
            followers[owners[shared].finding_id].append(_Follower(candidate, shared))
            continue
        leaders.append(candidate)
        followers[candidate.finding_id] = []
        owners.update(dict.fromkeys(candidate.keys, candidate))
    if len(leaders) < storm_threshold:
        return [
            _Job(FindingKind.ALARM, [leader], leader.floor, followers[leader.finding_id])
            for leader in leaders
        ]
    return [
        _Job(
            FindingKind.INCIDENT,
            leaders,
            leaders[0].floor,
            [follower for leader in leaders for follower in followers[leader.finding_id]],
        )
    ]


@dataclass(frozen=True)
class Dispatched:
    """What became of a job: the record it is under, and whether it was sent.

    ``record`` is the job's finding id when sent, else its deferral, over-budget or the
    concurrent owner's finding id; ``outcome`` says which, for the storm finding.
    """

    record: str
    emitted: bool
    outcome: str


@dataclass(frozen=True)
class _Refusal:
    """Why the budgets refuse a job."""

    reason: str


def _reserve_start(settings: TriageSettings) -> int:
    """The hourly count from which priority 3 and 4 jobs are refused."""
    return math.floor(settings.hourly_budget * (1 - settings.reserve_fraction) + 1e-9)


def _policy_refusal(
    clients: TriageClients, settings: TriageSettings, job: _Job, now: datetime
) -> _Refusal | None:
    """Refusals that move no counter: the low floor rule, the priority reserve and the
    daily token budget."""
    if job.priority >= SKIPPED_PRIORITY:
        count = hourly_count(clients.table, now)
        if job.floor is Severity.LOW and count * 2 >= settings.hourly_budget:
            return _Refusal("the hourly investigation budget is half spent and the floor is low")
        if count >= _reserve_start(settings):
            return _Refusal("the rest of the hourly budget is kept for priority 1 and 2")
    if daily_tokens(clients.table, now) >= settings.daily_token_budget:
        return _Refusal("daily token budget reached")
    return None


@dataclass
class _Charges:
    """The counters a job moved, so a refusal or a failed send takes them all back."""

    refunds: list[Callable[[Any, datetime], None]] = field(default_factory=list)

    def refund(self, table: Any, now: datetime) -> None:
        for refund in reversed(self.refunds):
            refund(table, now)
        self.refunds.clear()


def _charge(
    clients: TriageClients, settings: TriageSettings, job: _Job, now: datetime
) -> _Charges | _Refusal:
    """Count the job against its budgets. Why it is refused, with nothing kept counted.

    The hourly budget (and, for a Datadog job, the Datadog share of it, and with member
    accounts the job's account's share) comes first; a priority 1 job past any of them
    takes the day's priority 1 overflow instead, and with member accounts its account's
    share of that overflow too. The daily budget, and with member accounts the account's
    share of it, applies to every job.
    """
    table = clients.table
    account = job.account_id
    charges = _Charges([refund_hourly_budget])
    reason: str | None = None
    if not consume_hourly_budget(table, settings.hourly_budget, now):
        reason = "the hourly investigation budget is spent"
    elif job.head.signal.source == "datadog":
        charges.refunds.append(refund_datadog_share)
        if not consume_datadog_share(table, settings.datadog_hourly_share, now):
            reason = "the Datadog share of the hourly budget is spent"
    if reason is None and settings.multi_account:
        charges.refunds.append(partial(refund_account_hourly_budget, account_id=account))
        if not consume_account_hourly_budget(table, settings.account_hourly_budget, now, account):
            reason = f"account {account}'s share of the hourly budget is spent"
    if reason is not None:
        charges.refund(table, now)
        if job.priority != 1:
            return _Refusal(reason)
        charges.refunds.append(refund_p1_overflow)
        if not consume_p1_overflow(table, settings.p1_daily_overflow, now):
            charges.refund(table, now)
            return _Refusal(f"{reason} and so is the priority 1 overflow")
        if settings.multi_account:
            charges.refunds.append(partial(refund_account_p1_overflow, account_id=account))
            if not consume_account_p1_overflow(
                table, settings.account_p1_daily_overflow, now, account
            ):
                charges.refund(table, now)
                return _Refusal(f"{reason} and so is account {account}'s priority 1 overflow")
    charges.refunds.append(refund_daily_budget)
    if not consume_daily_budget(table, settings.daily_budget, now):
        charges.refund(table, now)
        return _Refusal("the daily investigation budget is spent")
    if settings.multi_account:
        charges.refunds.append(partial(refund_account_daily_budget, account_id=account))
        if not consume_account_daily_budget(table, settings.account_daily_budget, now, account):
            charges.refund(table, now)
            return _Refusal(f"account {account}'s share of the daily budget is spent")
    return charges


def _store_grouped(
    clients: TriageClients,
    settings: TriageSettings,
    job: _Job,
    incident_id: str,
    now: datetime,
    *,
    emitted: bool,
) -> None:
    for candidate in job.signals[1:]:
        _store(
            clients,
            settings,
            now,
            signal=candidate.ref,
            resource_key=candidate.keys[0],
            floor=candidate.floor,
            kind=FindingKind.GROUPED,
            finding_id=candidate.finding_id if emitted else candidate.deferral_id,
            incident_id=incident_id,
            title=f"Grouped: {candidate.name}",
            summary=(
                f"{candidate.name} {candidate.ref.fired} in a storm of {len(job.signals)} "
                f"alarms, recorded together as incident {incident_id}."
            ),
        )


def _store_followers(
    clients: TriageClients, settings: TriageSettings, job: _Job, now: datetime, *, emitted: bool
) -> None:
    """Linked findings for the job's followers; an emitted job's active items list them.

    A deferred job's followers link to its deferral and keep their own deferral ids, so a
    retried deferral writes nothing new.
    """
    for follower in job.followers:
        candidate = follower.candidate
        if emitted:
            link_alarm(clients.table, follower.key, candidate.name, now)
            _store_linked(clients, settings, candidate, job.finding_id, follower.key, now)
        else:
            _store_linked(
                clients,
                settings,
                candidate,
                job.deferral_id,
                follower.key,
                now,
                finding_id=candidate.deferral_id,
            )


def _membership(job: _Job) -> dict[str, Any]:
    if job.kind is not FindingKind.INCIDENT:
        return {}
    return {
        "member_alarms": [candidate.name for candidate in job.signals[:MAX_INCIDENT_ALARMS]],
        "alarm_count": len(job.signals),
    }


def _subject(job: _Job) -> str:
    if job.kind is FindingKind.INCIDENT:
        return f"storm of {len(job.signals)} alarms"
    return job.head.name


def _defer(
    clients: TriageClients, settings: TriageSettings, job: _Job, reason: str, now: datetime
) -> None:
    """Record the deferral once per episode: a retry's ids are its first deferral's."""
    subject = _subject(job)
    _store(
        clients,
        settings,
        now,
        signal=job.head.ref,
        resource_key=job.head.keys[0],
        floor=job.floor,
        kind=FindingKind.DEFERRED,
        finding_id=job.deferral_id,
        title=f"Deferred: {subject}",
        summary=f"The {subject} {job.head.ref.fired} and was not investigated: {reason}.",
        **_membership(job),
    )
    _store_grouped(clients, settings, job, job.deferral_id, now, emitted=False)
    _store_followers(clients, settings, job, now, emitted=False)


def _retry_later(
    clients: TriageClients, settings: TriageSettings, job: _Job, log_keys: dict[str, Any]
) -> None:
    """Send each of a budget-deferred job's signals back to the alarms queue, delayed.

    Each carries its retry count and the id its deferral was recorded under. Past
    MAX_DEFERRED_RETRIES the signal is left to its next firing.
    """
    for candidate in job.everyone:
        if candidate.retry >= settings.max_deferred_retries:
            logger.warning(
                "deferred: retries exhausted",
                extra={**log_keys, "alarm_name": candidate.name, "retry": candidate.retry},
            )
            continue
        body = {
            **candidate.body,
            RETRY_FIELD: candidate.retry + 1,
            DEFERRED_ID_FIELD: candidate.deferral_id,
        }
        clients.sqs.send_message(
            QueueUrl=settings.alarms_queue_url,
            MessageBody=json.dumps(body),
            DelaySeconds=DEFERRED_RETRY_DELAY_SECONDS,
        )
        logger.info(
            "deferred: sent back for retry",
            extra={**log_keys, "alarm_name": candidate.name, "retry": candidate.retry + 1},
        )


def _skip_over_budget(
    clients: TriageClients,
    settings: TriageSettings,
    job: _Job,
    reason: str,
    now: datetime,
    log_keys: dict[str, Any],
) -> Dispatched:
    """Record a priority 3 or 4 job the budgets refuse, once per resource key an hour."""
    key = job.head.keys[0]
    finding_id = str(
        uuid.uuid5(_FINDING_ID_NAMESPACE, f"over-budget#{key}#{now.strftime('%Y-%m-%dT%H')}")
    )
    subject = _subject(job)
    _store(
        clients,
        settings,
        now,
        signal=job.head.ref,
        resource_key=key,
        floor=job.floor,
        kind=FindingKind.SKIPPED,
        finding_id=finding_id,
        title=f"Skipped: {subject}",
        summary=(
            f"The {subject} {job.head.ref.fired} and was not investigated: over budget, {reason}."
        ),
        **_membership(job),
    )
    for candidate in job.everyone:
        _decide(
            "skipped_budget",
            settings,
            candidate,
            "skipped: over budget",
            **{**log_keys, "reason": reason},
        )
    return Dispatched(finding_id, False, f"was skipped over budget ({reason})")


def _refuse(
    clients: TriageClients,
    settings: TriageSettings,
    job: _Job,
    refusal: _Refusal,
    now: datetime,
    log_keys: dict[str, Any],
) -> Dispatched:
    """Defer a priority 1 or 2 job and send it back for retry; skip any other."""
    if job.priority >= SKIPPED_PRIORITY:
        return _skip_over_budget(clients, settings, job, refusal.reason, now, log_keys)
    _defer(clients, settings, job, refusal.reason, now)
    for candidate in job.everyone:
        _decide(
            "deferred",
            settings,
            candidate,
            "deferred: investigation budget",
            **{**log_keys, "reason": refusal.reason},
        )
    _retry_later(clients, settings, job, log_keys)
    return Dispatched(job.deferral_id, False, f"was deferred ({refusal.reason})")


def _link_to_owner(
    clients: TriageClients,
    settings: TriageSettings,
    job: _Job,
    key: str,
    owner_id: str,
    now: datetime,
) -> None:
    """Another invocation's job holds a key of this one: every signal links to it."""
    for candidate in job.everyone:
        link_alarm(clients.table, key, candidate.name, now)
        _store_linked(clients, settings, candidate, owner_id, key, now)
        _decide("linked", settings, candidate, "linked: a concurrent job holds the resource")


def _record_members(
    clients: TriageClients, settings: TriageSettings, job: _Job, now: datetime
) -> None:
    """Grouped and follower findings of a sent job. Logged, never failed: the job is out."""
    try:
        if job.kind is FindingKind.INCIDENT:
            _store_grouped(clients, settings, job, job.finding_id, now, emitted=True)
        _store_followers(clients, settings, job, now, emitted=True)
    except Exception as exc:
        logger.error(
            "member findings not stored for a sent job",
            extra={"finding_id": job.finding_id, "error": type(exc).__name__},
        )


def _job_message(job: _Job) -> InvestigationJob:
    listed = job.signals[:MAX_INCIDENT_ALARMS]
    return InvestigationJob(
        finding_id=job.finding_id,
        kind=job.kind,
        signals=[candidate.ref for candidate in listed],
        alarms=[
            alarm_event(candidate.signal)
            for candidate in listed
            if candidate.signal.source == "cloudwatch"
        ],
        alarm_count=len(job.signals),
        keys=job.keys,
        floor=job.floor,
        account_id=job.account_id,
        region=job.head.signal.region,
    )


def _record_sent(settings: TriageSettings, job: _Job, log_keys: dict[str, Any]) -> None:
    _decide("investigated", settings, job.head, "job emitted", **log_keys)
    for candidate in job.signals[1:]:
        _decide("storm_grouped", settings, candidate, "grouped: storm in one batch", **log_keys)
    for follower in job.followers:
        _decide("linked", settings, follower.candidate, "linked: shares a key in the batch")


def dispatch(
    clients: TriageClients, settings: TriageSettings, job: _Job, now: datetime
) -> Dispatched:
    """Budgets and emit for one job."""
    finding_id = job.finding_id
    log_keys = {
        "alarm_name": job.head.name,
        "account_id": job.account_id,
        "kind": job.kind.value,
        "alarm_count": len(job.signals),
        "follower_count": len(job.followers),
        "finding_id": finding_id,
    }
    refusal = _policy_refusal(clients, settings, job, now)
    if refusal is not None:
        return _refuse(clients, settings, job, refusal, now, log_keys)

    keys = job.keys
    conflict = claim_keys(clients.table, keys, finding_id, now)
    if conflict is not None:
        key, owner_id = conflict
        _link_to_owner(clients, settings, job, key, owner_id, now)
        return Dispatched(owner_id, False, f"was linked to the running investigation {owner_id}")

    charged = _charge(clients, settings, job, now)
    if isinstance(charged, _Refusal):
        release_keys(clients.table, keys, finding_id, now)
        return _refuse(clients, settings, job, charged, now, log_keys)

    try:
        clients.sqs.send_message(
            QueueUrl=settings.work_queue_url,
            MessageBody=_job_message(job).model_dump_json(by_alias=True),
        )
    except Exception:
        charged.refund(clients.table, now)
        release_keys(clients.table, keys, finding_id, now)
        raise
    _record_members(clients, settings, job, now)
    _record_sent(settings, job, {**log_keys, "key_count": len(keys)})
    return Dispatched(finding_id, True, f"is investigated as {finding_id}")


def _storm_id(head: _Candidate) -> str:
    return str(uuid.uuid5(_FINDING_ID_NAMESPACE, f"storm#{head.deferral_id}"))


def storm_window(
    clients: TriageClients,
    settings: TriageSettings,
    pending: list[_Candidate],
    now: datetime,
    scope: str = "",
) -> Storm | None:
    """Count the batch's first firings and return the open storm, opening or ending it.

    ``pending`` are the signals of one member account (``scope``) or of the agent's own.
    A deferred signal sent back for retry is not counted again. A storm opens when the
    previous and the current 5-minute bucket both hold more than ``storm_rate`` signals,
    with the highest-priority signal of the batch as its head. It ends once a full bucket
    holds ``storm_rate`` or fewer.
    """
    if not pending:
        return None
    fresh = sum(1 for candidate in pending if not candidate.retry)
    rate = record_rate(clients.table, fresh, now, scope)
    storm = active_storm(clients.table, now, scope)
    if storm is not None and rate.previous <= settings.storm_rate:
        end_storm(clients.table, storm, now)
        logger.info("storm over", extra={"storm_id": storm.storm_id, "rate": rate.previous})
        return None
    if storm is None and min(rate.previous, rate.current) > settings.storm_rate:
        head = _by_priority(pending)[0]
        storm = claim_storm(clients.table, Storm(_storm_id(head), head.deferral_id, scope), now)
        logger.warning(
            "storm opened",
            extra={
                "storm_id": storm.storm_id,
                "account_id": head.account_id,
                "previous": rate.previous,
                "current": rate.current,
            },
        )
    return storm


def _record_storm_head(
    clients: TriageClients,
    settings: TriageSettings,
    storm: Storm,
    head: _Candidate,
    dispatched: Dispatched,
    now: datetime,
) -> None:
    """The storm finding, pointing at what became of its head; a retried head updates it."""
    summary = (
        f"Signals arrived faster than {settings.storm_rate} per 5 minutes for two buckets in "
        f"a row. {head.name} {dispatched.outcome}; priority 1 and 2 signals still go through "
        "the budgets, the rest are counted here until the rate falls."
    )
    stored = _store(
        clients,
        settings,
        now,
        signal=head.ref,
        resource_key=head.keys[0],
        floor=head.floor,
        kind=FindingKind.STORM,
        finding_id=storm.storm_id,
        linked_to=dispatched.record,
        alarm_count=1,
        source_counts={head.signal.source: 1},
        resource_counts={head.keys[0]: 1},
        title=f"Storm: more than {settings.storm_rate} signals per 5 minutes",
        summary=summary,
    )
    if not stored:
        set_storm_head(clients.table, storm.storm_id, dispatched.record, summary)


def _group_into_storm(
    clients: TriageClients,
    settings: TriageSettings,
    storm: Storm,
    candidate: _Candidate,
    now: datetime,
) -> None:
    ref = candidate.ref
    stored = _store(
        clients,
        settings,
        now,
        signal=ref,
        resource_key=candidate.keys[0],
        floor=candidate.floor,
        kind=FindingKind.GROUPED,
        finding_id=candidate.finding_id,
        incident_id=storm.storm_id,
        title=f"Grouped: {candidate.name}",
        summary=f"{candidate.name} {ref.fired} during a storm, recorded on storm {storm.storm_id}.",
    )
    if stored and not count_on_storm(
        clients.table, storm.storm_id, ref.source, candidate.keys[0], now
    ):
        logger.warning("storm finding not stored yet", extra={"storm_id": storm.storm_id})
    _decide("storm_grouped", settings, candidate, "grouped: storm", storm_id=storm.storm_id)


def _dispatch_storm_head(
    clients: TriageClients,
    settings: TriageSettings,
    storm: Storm,
    head: _Candidate,
    now: datetime,
) -> list[str]:
    try:
        dispatched = dispatch(clients, settings, _Job(FindingKind.ALARM, [head], head.floor), now)
        _record_storm_head(clients, settings, storm, head, dispatched, now)
    except Exception as exc:
        logger.error(
            "storm head dispatch failed",
            extra={"alarm_name": head.name, "error": type(exc).__name__},
        )
        return list(head.message_ids)
    return []


def storm_dispatch(
    clients: TriageClients,
    settings: TriageSettings,
    storm: Storm,
    pending: list[_Candidate],
    now: datetime,
) -> list[str]:
    """Dispatch the storm's head when it is in this batch, then every priority 1 or 2
    signal through the budgets as usual; group the rest onto the storm.

    The head goes first: the storm finding must exist before members are counted on it.
    Returns the message ids that failed.
    """
    failures: list[str] = []
    rest: list[_Candidate] = []
    for candidate in pending:
        if candidate.deferral_id == storm.head_id:
            failures.extend(_dispatch_storm_head(clients, settings, storm, candidate, now))
        else:
            rest.append(candidate)
    urgent = [candidate for candidate in rest if candidate.signal.priority < SKIPPED_PRIORITY]
    failures.extend(_dispatch_planned(clients, settings, urgent, now))
    for candidate in rest:
        if candidate.signal.priority < SKIPPED_PRIORITY:
            continue
        try:
            _group_into_storm(clients, settings, storm, candidate, now)
        except Exception as exc:
            logger.error(
                "storm grouping failed",
                extra={"alarm_name": candidate.name, "error": type(exc).__name__},
            )
            failures.extend(candidate.message_ids)
    return failures


def _dispatch_planned(
    clients: TriageClients, settings: TriageSettings, pending: list[_Candidate], now: datetime
) -> list[str]:
    failures: list[str] = []
    for job in plan_jobs(pending, settings.storm_threshold):
        try:
            dispatch(clients, settings, job, now)
        except Exception as exc:
            logger.error(
                "dispatch failed",
                extra={"alarm_name": job.head.name, "error": type(exc).__name__},
            )
            failures.extend(job.message_ids)
    return failures


def _seconds_left(context: Any) -> Callable[[], float]:
    remaining = getattr(context, "get_remaining_time_in_millis", None)
    if remaining is None:
        return lambda: math.inf
    return lambda: remaining() / 1000


def _scopes(pending: list[_Candidate]) -> dict[str, list[_Candidate]]:
    """The settled signals by the member account their keys are scoped by."""
    scopes: dict[str, list[_Candidate]] = {}
    for candidate in pending:
        scopes.setdefault(candidate.scope, []).append(candidate)
    return scopes


def _dispatch(
    clients: TriageClients, settings: TriageSettings, pending: list[_Candidate], now: datetime
) -> list[str]:
    """Storm mode or planned jobs for one scope's signals; the message ids that failed."""
    scope = pending[0].scope
    try:
        storm = storm_window(clients, settings, pending, now, scope)
    except Exception as exc:
        logger.error("signal rate unavailable", extra={"error": type(exc).__name__})
        return [message_id for rest in pending for message_id in rest.message_ids]
    if storm is not None:
        return storm_dispatch(clients, settings, storm, pending, now)
    return _dispatch_planned(clients, settings, pending, now)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    settings = get_triage_settings()
    logger.setLevel(settings.log_level)
    clients = triage_clients(settings.aws_region, settings.findings_table)
    datadog = datadog_client(settings)
    now = datetime.now(UTC)

    seconds_left = _seconds_left(context)
    accounts = _Accounts(
        clients=clients,
        settings=settings,
        own=own_account(context, settings, clients.sts),
        partition=function_partition(context),
        name=session_name("devops-agent-triage", str(getattr(context, "aws_request_id", ""))),
        seconds_left=seconds_left,
    )
    failures: list[str] = []
    pending: list[_Candidate] = []
    candidates = _distinct_signals(event.get("Records", []))
    # After one failed Datadog read, the invocation's other Datadog signals fail without a
    # call, so an outage costs one call per invocation; SQS redelivers them.
    datadog_down = False
    for index, candidate in enumerate(candidates):
        if seconds_left() < DEADLINE_RESERVE_SECONDS:
            unsettled = candidates[index:]
            logger.warning("stopped for time", extra={"unsettled_count": len(unsettled)})
            failures.extend(message_id for rest in unsettled for message_id in rest.message_ids)
            break
        if datadog_down and candidate.signal.source == "datadog":
            failures.extend(candidate.message_ids)
            continue
        try:
            if not _settle(accounts, settings, datadog, candidate, now):
                pending.append(candidate)
        except DatadogError as exc:
            datadog_down = True
            logger.error("Datadog monitor read failed", extra={"error": str(exc)})
            failures.extend(candidate.message_ids)
        except Exception as exc:
            logger.error(
                "triage failed", extra={"alarm_name": candidate.name, "error": type(exc).__name__}
            )
            failures.extend(candidate.message_ids)

    for scoped in _scopes(pending).values():
        failures.extend(_dispatch(clients, settings, scoped, now))

    logger.info(
        "batch triaged",
        extra={
            "record_count": len(event.get("Records", [])),
            "job_candidates": len(pending),
            "failure_count": len(failures),
        },
    )
    return {"batchItemFailures": [{"itemIdentifier": message_id} for message_id in failures]}
