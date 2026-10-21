"""Finding assembly and the findings-table writes."""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from devops_agent.models import (
    Action,
    Checked,
    ContextSummary,
    Effort,
    Evidence,
    Finding,
    FindingKind,
    Hypothesis,
    InvestigationJob,
    ReportedFinding,
    Severity,
    SignalRef,
)
from devops_agent.redact import redact
from devops_agent.severity import final_severity
from devops_agent.tools import READ_ONLY_TOOLS

if TYPE_CHECKING:
    from devops_agent.agent import Investigation

OPEN_FINDING_RETENTION_DAYS = 90
# A review tool that closes a finding resets ttl to closed_at plus this.
CLOSED_FINDING_RETENTION_DAYS = 365
USEFUL_SOURCE_RETENTION_DAYS = 90
SNAPSHOT_RETENTION_DAYS = 90
MAX_USEFUL_SOURCES = 10
# A person closed these and said what the finding was; only they reach the model.
REVIEWED_RESOLUTIONS = frozenset({"confirmed", "false_positive"})
# The tool trail stored on a finding keeps at most this many calls.
MAX_TOOL_TRAIL = 50
INVESTIGATION_KINDS = frozenset({FindingKind.ALARM.value, FindingKind.INCIDENT.value})


def _expires(now: datetime, days: int = OPEN_FINDING_RETENTION_DAYS) -> int:
    return int((now + timedelta(days=days)).timestamp())


def _subject(job: InvestigationJob) -> str:
    if job.kind is FindingKind.INCIDENT:
        return f"the storm of {job.alarm_count} alarms starting with {job.signal.name}"
    return job.signal.name


def _membership(job: InvestigationJob) -> dict[str, Any]:
    """An incident's member signals (bounded like the job's listing) and its full count."""
    if job.kind is not FindingKind.INCIDENT:
        return {}
    return {
        "member_alarms": [signal.name for signal in job.signals],
        "alarm_count": job.alarm_count,
    }


def _signal_fields(signal: SignalRef) -> dict[str, Any]:
    return {
        "source": signal.source,
        "account_id": signal.account_id or None,
        "region": signal.region or None,
        "alarm_name": signal.name,
        "alarm_arn": signal.arn,
        "alarm_reason": redact(signal.reason) or None,
        "alarm_time": signal.observed_at,
    }


def _look_directly(signal: SignalRef) -> Action:
    if signal.source == "datadog":
        return Action(
            kind="read",
            text=(
                f"Open the monitor {signal.subject} (id {signal.ref.get('monitor_id')}) in "
                "Datadog and check its group, metric and recent changes."
            ),
        )
    return Action(
        kind="read",
        text=(
            f"Open the alarm {signal.name} in the CloudWatch console and check its metric "
            "and recent changes."
        ),
    )


def _trail_fields(investigation: Investigation) -> dict[str, Any]:
    """The investigation's tool calls without their outputs."""
    return {
        "tools_used": list(dict.fromkeys(investigation.tool_calls)),
        "tool_call_count": len(investigation.tool_calls),
        "sources_with_data": list(
            dict.fromkeys(step.tool for step in investigation.trail if step.status == "data")
        ),
        "tool_trail": list(investigation.trail[:MAX_TOOL_TRAIL]),
    }


def _cited(steps: Sequence[int], trail: set[int]) -> list[int]:
    return [step for step in steps if step in trail]


def _reasoning_fields(report: ReportedFinding, trail_steps: set[int]) -> dict[str, Any]:
    """The report's evidence and reasoning, citing only steps on the stored trail."""
    return {
        "evidence": [
            Evidence(kind=item.kind, detail=item.detail, steps=_cited(item.steps, trail_steps))
            for item in report.evidence
        ],
        "checked": [
            Checked(text=item.text, steps=_cited(item.steps, trail_steps))
            for item in report.checked
        ],
        "confidence": report.confidence,
        "confidence_reason": report.confidence_reason,
        "hypotheses": [
            Hypothesis(text=item.text, state=item.state, steps=_cited(item.steps, trail_steps))
            for item in report.hypotheses
        ],
    }


def _action_fields(actions: Sequence[Action]) -> dict[str, Any]:
    return {
        "actions": list(actions),
        "suggested_actions": [action.line for action in actions],
    }


def build_finding(
    *,
    env: str,
    job: InvestigationJob,
    investigation: Investigation,
    now: datetime,
    linked_alarms: Sequence[str] = (),
    previous_finding_id: str | None = None,
    context_summary: ContextSummary | None = None,
    prior_finding_ids: Sequence[str] = (),
    error: str | None = None,
) -> Finding:
    """The finding for one investigation; an unreported one becomes an incomplete finding.

    ``prior_finding_ids`` are the reviewed prior findings the model was shown. ``error``
    is the class name of the exception that ended the run, never its message.
    """
    common: dict[str, Any] = {
        "finding_id": job.finding_id,
        "created_at": now.isoformat(),
        "env": env,
        "kind": job.kind,
        **_signal_fields(job.signal),
        "account_id": job.account_id or None,
        "region": job.region or None,
        "resource_key": job.resource_key,
        "linked_alarms": list(linked_alarms),
        "previous_finding_id": previous_finding_id,
        "context_summary": context_summary,
        "severity_floor": job.floor,
        **_membership(job),
        **_trail_fields(investigation),
        "prior_finding_ids": list(prior_finding_ids),
        "steps": investigation.steps,
        "model_id": investigation.model_id,
        "tokens_used": investigation.tokens_used,
        "weighted_tokens": investigation.weighted_tokens,
        "run": investigation.run,
        "ttl": _expires(now),
    }
    report = investigation.report
    if report is None:
        subject = _subject(job)
        outcome = (
            f"failed with {error}" if error else f"did not finish after {investigation.steps} steps"
        )
        return Finding(
            **common,
            severity=job.floor,
            proposed_severity=None,
            title=f"Investigation incomplete: {subject}",
            summary=(
                f"The investigation of {subject} {outcome} and reported no finding. Look at "
                f"the {'monitor' if job.signal.source == 'datadog' else 'alarm'} directly."
            ),
            likely_cause="Not determined.",
            evidence=[],
            **_action_fields([_look_directly(job.signal)]),
            fix_effort=Effort.UNKNOWN,
            fix_effort_reason="",
            outcome="incomplete",
        )
    return Finding(
        **common,
        severity=final_severity(job.floor, report.severity),
        proposed_severity=report.severity,
        title=report.title,
        summary=report.summary,
        likely_cause=report.likely_cause,
        **_reasoning_fields(report, {step.step for step in common["tool_trail"]}),
        **_action_fields(report.actions),
        fix_effort=report.fix_effort,
        fix_effort_reason=report.fix_effort_reason,
        error_signature=report.error_signature,
        outcome="reported",
    )


def build_triage_finding(
    *,
    env: str,
    kind: FindingKind,
    signal: SignalRef,
    resource_key: str,
    floor: Severity,
    now: datetime,
    title: str,
    summary: str,
    finding_id: str | None = None,
    incident_id: str | None = None,
    linked_to: str | None = None,
    member_alarms: Sequence[str] = (),
    alarm_count: int | None = None,
    source_counts: dict[str, int] | None = None,
    resource_counts: dict[str, int] | None = None,
) -> Finding:
    """A finding triage records for a signal it does not send to an investigation."""
    return Finding(
        finding_id=finding_id or str(uuid.uuid4()),
        created_at=now.isoformat(),
        env=env,
        kind=kind,
        **_signal_fields(signal),
        resource_key=resource_key,
        incident_id=incident_id,
        linked_to=linked_to,
        member_alarms=list(member_alarms),
        alarm_count=alarm_count,
        source_counts=source_counts or {},
        resource_counts=resource_counts or {},
        severity=floor,
        severity_floor=floor,
        proposed_severity=None,
        title=title,
        summary=summary,
        likely_cause="Not investigated.",
        evidence=[],
        suggested_actions=[],
        fix_effort=Effort.UNKNOWN,
        fix_effort_reason="",
        steps=0,
        model_id="",
        outcome="triaged",
        ttl=_expires(now),
    )


def to_item(finding: Finding) -> dict[str, Any]:
    """The DynamoDB item for a finding. Numbers are Decimal; DynamoDB rejects floats."""
    item: dict[str, Any] = json.loads(finding.model_dump_json(), parse_float=Decimal)
    item["pk"] = f"finding#{finding.finding_id}"
    return item


def finding_exists(table: Any, finding_id: str) -> bool:
    return "Item" in table.get_item(Key={"pk": f"finding#{finding_id}"}, ProjectionExpression="pk")


def store_finding(table: Any, finding: Finding) -> bool:
    """Put the finding once. False when a finding with its id is already stored."""
    try:
        table.put_item(Item=to_item(finding), ConditionExpression="attribute_not_exists(pk)")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise
    return True


def store_snapshot(table: Any, finding_id: str, attribute: dict[str, str], now: datetime) -> None:
    """Put the snap# item for a stored finding; ``attribute`` is from encode_snapshot."""
    table.put_item(
        Item={
            "pk": f"snap#{finding_id}",
            "finding_id": finding_id,
            "created_at": now.isoformat(),
            "ttl": _expires(now, SNAPSHOT_RETENTION_DAYS),
            **attribute,
        }
    )


def record_recurrence(table: Any, finding_id: str, now: datetime) -> None:
    """Count one more firing of the alarm on its unclosed finding."""
    table.update_item(
        Key={"pk": f"finding#{finding_id}"},
        UpdateExpression="ADD recurrence_count :one SET last_seen_at = :now",
        ConditionExpression="attribute_exists(pk)",
        ExpressionAttributeValues={":one": 1, ":now": now.isoformat()},
    )


def prior_findings(table: Any, resource_key: str, limit: int) -> list[dict[str, Any]]:
    """The newest findings on a resource key, any status and kind, newest first."""
    response = table.query(
        IndexName="by_resource",
        KeyConditionExpression="resource_key = :key",
        ExpressionAttributeValues={":key": resource_key},
        ScanIndexForward=False,
        Limit=limit,
    )
    items: list[dict[str, Any]] = response.get("Items", [])
    return items


def _closed_at(item: dict[str, Any]) -> datetime | None:
    for value in (item.get("resolved_at"), item.get("created_at")):
        if value:
            try:
                at = datetime.fromisoformat(str(value))
            except ValueError:
                continue
            return at if at.tzinfo else at.replace(tzinfo=UTC)
    return None


def closed_in_cooldown(
    table: Any,
    resource_key: str,
    alarm_arn: str,
    now: datetime,
    *,
    alarm_cooldown: timedelta,
    resource_cooldown: timedelta,
    limit: int,
) -> dict[str, Any] | None:
    """The newest investigation closed within its cooldown on the resource key.

    An alarm or incident finding counts when it was closed (``resolved_at``, else
    ``created_at``) within ``alarm_cooldown`` and is on the same alarm ARN, or within
    ``resource_cooldown`` on any alarm. Reads the newest ``limit`` findings on the key.
    """
    for item in prior_findings(table, resource_key, limit):
        if item.get("status") != "closed" or item.get("kind") not in INVESTIGATION_KINDS:
            continue
        closed_at = _closed_at(item)
        if closed_at is None:
            continue
        same_alarm = bool(alarm_arn) and item.get("alarm_arn") == alarm_arn
        window = max(alarm_cooldown, resource_cooldown) if same_alarm else resource_cooldown
        if now - closed_at <= window:
            return item
    return None


def is_reviewed(item: dict[str, Any]) -> bool:
    """True when a person closed a reported finding as confirmed or as a false positive.

    A finding stored without ``outcome`` counts as reported.
    """
    return (
        item.get("status") == "closed"
        and item.get("resolution") in REVIEWED_RESOLUTIONS
        and item.get("outcome", "reported") == "reported"
    )


def _sources_key(resource_key: str) -> dict[str, str]:
    return {"pk": f"obs#{resource_key}"}


def useful_sources(table: Any, resource_key: str) -> list[dict[str, Any]]:
    """The tool calls that returned data in earlier investigations of a key, newest first."""
    item = table.get_item(Key=_sources_key(resource_key)).get("Item") or {}
    entries: list[dict[str, Any]] = item.get("entries", [])
    return entries


def record_useful_sources(
    table: Any, resource_key: str, sources: Sequence[dict[str, Any]], now: datetime
) -> None:
    """Put this investigation's useful calls ahead of the stored ones, keeping the newest.

    ``sources`` are {tool, input} in call order; a repeated call keeps its newest entry.
    A stored entry of a tool that does not exist is dropped.
    """
    at = now.isoformat()
    merged: dict[str, dict[str, Any]] = {}
    fresh = [{**source, "at": at} for source in reversed(sources)]
    tools = {tool.name for tool in READ_ONLY_TOOLS}
    stored = [entry for entry in useful_sources(table, resource_key) if entry.get("tool") in tools]
    for entry in fresh + stored:
        identity = json.dumps([entry.get("tool"), entry.get("input")], sort_keys=True, default=str)
        merged.setdefault(identity, entry)
    table.update_item(
        Key=_sources_key(resource_key),
        UpdateExpression="SET entries = :entries, #ttl = :ttl",
        ExpressionAttributeNames={"#ttl": "ttl"},
        ExpressionAttributeValues={
            ":entries": list(merged.values())[:MAX_USEFUL_SOURCES],
            ":ttl": _expires(now, USEFUL_SOURCE_RETENTION_DAYS),
        },
    )


def open_investigation_for_alarm(
    table: Any, resource_key: str, alarm_name: str, page_size: int, max_pages: int
) -> dict[str, Any] | None:
    """The newest unclosed, reported investigation of the alarm on its primary resource key.

    An open finding and one a person acknowledged count alike. Only alarm and incident
    findings with outcome reported count; triage-written and incomplete findings never
    stand in for an investigation.
    """
    kwargs: dict[str, Any] = {
        "IndexName": "by_resource",
        "KeyConditionExpression": "resource_key = :key",
        "FilterExpression": (
            "alarm_name = :alarm AND #status IN (:open, :acknowledged) "
            "AND #kind IN (:alarm_kind, :incident_kind) AND #outcome = :reported"
        ),
        "ExpressionAttributeNames": {"#status": "status", "#kind": "kind", "#outcome": "outcome"},
        "ExpressionAttributeValues": {
            ":key": resource_key,
            ":alarm": alarm_name,
            ":open": "open",
            ":acknowledged": "acknowledged",
            ":alarm_kind": FindingKind.ALARM.value,
            ":incident_kind": FindingKind.INCIDENT.value,
            ":reported": "reported",
        },
        "ScanIndexForward": False,
        "Limit": page_size,
    }
    for _ in range(max_pages):
        response = table.query(**kwargs)
        items: list[dict[str, Any]] = response.get("Items", [])
        if items:
            return items[0]
        if "LastEvaluatedKey" not in response:
            return None
        kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
    return None
