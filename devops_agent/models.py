"""Event and finding models."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ALARM_STATE_CHANGE = "CloudWatch Alarm State Change"
DATADOG_ALERT = "Datadog Alert Notification"

# A resource key scoped to a member account: "<12-digit account id>|<key>". Every key
# starts with a CloudWatch namespace, "alarm:" or "datadog:", and a namespace cannot hold
# "|", so an unscoped key never looks scoped.
_SCOPED_KEY = re.compile(r"^(\d{12})\|(.+)$", re.DOTALL)


def scoped_key(key: str, account_id: str) -> str:
    """The key of a resource in a member account; the agent's own keys stay as they are."""
    return f"{account_id}|{key}" if account_id else key


def local_key(key: str) -> str:
    """A resource key without its account scope."""
    match = _SCOPED_KEY.match(key)
    return match.group(2) if match else key


class Severity(StrEnum):
    """Finding severity, ordered critical > high > medium > low."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Signal priority by severity: 1 is the most urgent.
SEVERITY_PRIORITY: dict[Severity, int] = {
    Severity.CRITICAL: 1,
    Severity.HIGH: 2,
    Severity.MEDIUM: 3,
    Severity.LOW: 4,
}

SignalSource = Literal["cloudwatch", "datadog"]


class Effort(StrEnum):
    """Estimated effort to fix, ordered low < medium < high < very_high.

    unknown means the evidence does not show a cause; it has no rank and sorts apart.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int | None:
        return None if self is Effort.UNKNOWN else list(Effort).index(self)

    @property
    def label(self) -> str:
        return self.value.replace("_", " ")


EFFORT_DEFINITIONS: dict[Effort, str] = {
    Effort.LOW: "a config change, restart, rollback or timeout bump, under an hour",
    Effort.MEDIUM: "a small code or Terraform fix, about a day",
    Effort.HIGH: "a real change across a service, several days",
    Effort.VERY_HIGH: "a design or multi-team change, a week or more",
    Effort.UNKNOWN: "the evidence does not show a cause",
}

MAX_EFFORT_REASON_CHARS = 200


MAX_ERROR_SIGNATURE_CHARS = 200

MAX_CONFIDENCE_REASON_CHARS = 200
MAX_HYPOTHESES = 8
MAX_HYPOTHESIS_CHARS = 200

Confidence = Literal["high", "medium", "low"]
CONFIDENCE_LEVELS: tuple[Confidence, ...] = ("high", "medium", "low")
HypothesisState = Literal["likely", "ruled_out", "unverified"]
HYPOTHESIS_STATES: tuple[HypothesisState, ...] = ("likely", "ruled_out", "unverified")

MAX_CHECKED = 6
MAX_CHECKED_CHARS = 300
MAX_ACTIONS = 6
MAX_ACTION_TEXT_CHARS = 200
MAX_ACTION_DETAIL_CHARS = 400
MAX_ACTION_COMMAND_CHARS = 500

ActionKind = Literal["change", "code", "read", "approval"]
ACTION_KINDS: tuple[ActionKind, ...] = ("change", "code", "read", "approval")
ACTION_KIND_DEFINITIONS: dict[ActionKind, str] = {
    "change": "a change to a live system (redrive, purge, scale, config)",
    "code": "a code or config fix in a repo",
    "read": (
        "a read the agent is denied (message bodies, object contents, secrets) that a "
        "person must do"
    ),
    "approval": "needs someone's sign-off",
}

StopReason = Literal["chose", "turn_limit", "token_budget", "time", "no_report", "model_error"]


class FindingKind(StrEnum):
    """What produced a finding: an investigation, or a triage decision not to run one.

    alarm and incident findings come from an investigation; grouped, linked, deferred,
    skipped and storm findings are written by triage without a model. A skipped finding is
    a signal opted out by its DevOpsAgent=off tag, or a priority 3 or 4 signal the budgets
    refused. A storm finding counts the signals triage grouped while the signal rate ran
    above its storm threshold.
    """

    ALARM = "alarm"
    INCIDENT = "incident"
    GROUPED = "grouped"
    LINKED = "linked"
    DEFERRED = "deferred"
    SKIPPED = "skipped"
    STORM = "storm"


class AlarmState(BaseModel):
    value: str
    reason: str = ""
    timestamp: str | None = None


class AlarmDetail(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    alarm_name: str = Field(alias="alarmName")
    state: AlarmState


class AlarmStateChangeEvent(BaseModel):
    """EventBridge "CloudWatch Alarm State Change" event."""

    model_config = ConfigDict(populate_by_name=True)

    detail_type: str = Field(alias="detail-type")
    account: str = ""
    region: str = ""
    time: str = ""
    resources: list[str] = Field(default_factory=list)
    detail: AlarmDetail

    @property
    def alarm_name(self) -> str:
        return self.detail.alarm_name

    @property
    def alarm_arn(self) -> str:
        return self.resources[0] if self.resources else ""

    @property
    def is_alarm(self) -> bool:
        return self.detail_type == ALARM_STATE_CHANGE and self.detail.state.value == "ALARM"

    @property
    def entered_at(self) -> str | None:
        """When the alarm entered ALARM, as ISO 8601 UTC; None when the event has no time."""
        for value in (self.detail.state.timestamp, self.time):
            if value:
                try:
                    return datetime.fromisoformat(value).astimezone(UTC).isoformat()
                except ValueError:
                    continue
        return None


class SignalRef(BaseModel):
    """What a job or a triage finding is about: one CloudWatch alarm or Datadog monitor group.

    ``name`` identifies the signal to people and to the findings table (an alarm name, or a
    monitor name with its group). ``ref`` holds the source's own identifiers: the alarm ARN,
    account, region and state reason, or the monitor id, group, group tags, query, type,
    states and evaluation time. ``priority`` runs from 1 (critical) to 4 (low).
    ``account_id`` and ``region`` are where the signal's resource lives: an alarm event's
    account and region, or for a Datadog signal what triage settles from the monitor.
    """

    source: SignalSource
    name: str = Field(min_length=1)
    subject: str
    observed_at: str | None = None
    priority: int = Field(default=4, ge=1, le=4)
    account_id: str = ""
    region: str = ""
    ref: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def for_alarm(cls, event: AlarmStateChangeEvent, floor: Severity) -> SignalRef:
        return cls(
            source="cloudwatch",
            name=event.alarm_name,
            subject=event.alarm_name,
            observed_at=event.entered_at,
            priority=SEVERITY_PRIORITY[floor],
            account_id=event.account,
            region=event.region,
            ref={
                "alarm_arn": event.alarm_arn,
                "account": event.account,
                "region": event.region,
                "reason": event.detail.state.reason,
            },
        )

    @property
    def identity(self) -> str:
        """Stable across firings of the same alarm or monitor group: the alarm name, or
        ``datadog:monitor/<id>/<group>``."""
        if self.source == "cloudwatch":
            return self.name
        return f"datadog:monitor/{self.ref.get('monitor_id')}/{self.ref.get('group', '*')}"

    @property
    def arn(self) -> str:
        """The alarm ARN, or a monitor group's identity; findings store it as alarm_arn."""
        if self.source == "cloudwatch":
            return str(self.ref.get("alarm_arn") or "")
        return self.identity

    @property
    def reason(self) -> str:
        return str(self.ref.get("reason") or "")

    @property
    def fired(self) -> str:
        """The signal's transition, for summaries: entered ALARM, or the monitor's state."""
        if self.source == "cloudwatch":
            return "entered ALARM"
        return f"went to {self.ref.get('dest_state') or 'Alert'}"


def _step_numbers(value: Any) -> list[int]:
    """The distinct integers in a cited-steps value, in order; anything else is dropped."""
    if not isinstance(value, list):
        return []
    return list(
        dict.fromkeys(
            item for item in value if isinstance(item, int) and not isinstance(item, bool)
        )
    )


def _clamped(value: Any, limit: int) -> Any:
    return value[:limit] if isinstance(value, str) else value


class Evidence(BaseModel):
    """One fact a finding rests on; ``steps`` are the trail steps it came from.

    Empty ``steps`` means the fact came from the context bundle, not a tool call.
    """

    kind: str
    detail: str
    steps: list[int] = Field(default_factory=list)

    @field_validator("steps", mode="before")
    @classmethod
    def _steps(cls, value: Any) -> list[int]:
        return _step_numbers(value)


class Hypothesis(BaseModel):
    """A working hypothesis, its final state and the trail steps that tested it."""

    text: str
    state: HypothesisState = "unverified"
    steps: list[int] = Field(default_factory=list)

    @field_validator("text", mode="before")
    @classmethod
    def _text(cls, value: Any) -> Any:
        return _clamped(value, MAX_HYPOTHESIS_CHARS)

    @field_validator("state", mode="before")
    @classmethod
    def _state(cls, value: Any) -> HypothesisState:
        return value if value in HYPOTHESIS_STATES else "unverified"

    @field_validator("steps", mode="before")
    @classmethod
    def _steps(cls, value: Any) -> list[int]:
        return _step_numbers(value)


class Checked(BaseModel):
    """A fact the agent verified with its tools; ``steps`` are the trail steps showing it."""

    text: str
    steps: list[int] = Field(default_factory=list)

    @field_validator("text", mode="before")
    @classmethod
    def _text(cls, value: Any) -> Any:
        return _clamped(value, MAX_CHECKED_CHARS)

    @field_validator("steps", mode="before")
    @classmethod
    def _steps(cls, value: Any) -> list[int]:
        return _step_numbers(value)


def _optional_text(value: Any, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


class Action(BaseModel):
    """Something only a person can do; ``command`` is the exact CLI or console command.

    An unknown ``kind`` becomes change.
    """

    kind: ActionKind = "change"
    text: str
    detail: str | None = None
    command: str | None = None

    @field_validator("kind", mode="before")
    @classmethod
    def _kind(cls, value: Any) -> ActionKind:
        return value if value in ACTION_KINDS else "change"

    @field_validator("text", mode="before")
    @classmethod
    def _text(cls, value: Any) -> Any:
        return _clamped(value, MAX_ACTION_TEXT_CHARS)

    @field_validator("detail", mode="before")
    @classmethod
    def _detail(cls, value: Any) -> str | None:
        return _optional_text(value, MAX_ACTION_DETAIL_CHARS)

    @field_validator("command", mode="before")
    @classmethod
    def _command(cls, value: Any) -> str | None:
        return _optional_text(value, MAX_ACTION_COMMAND_CHARS)

    @property
    def line(self) -> str:
        """The action as one line of text: its text, then its command when it has one."""
        return f"{self.text}: {self.command}" if self.command else self.text


def _usable_items(value: Any, limit: int) -> list[Any]:
    """At most ``limit`` items that have text; malformed ones are dropped."""
    if not isinstance(value, list):
        return []
    usable = [
        item for item in value if isinstance(item, dict) and isinstance(item.get("text"), str)
    ]
    return usable[:limit]


class ReportedFinding(BaseModel):
    """The structured input of the model's report_finding call.

    The reasoning fields (confidence, its reason, hypotheses, checked facts, cited steps)
    and the actions never fail a report on their details: unknown values become null,
    unverified or change, long text is cut, extras dropped. A report without ``actions``
    that carries ``suggested_actions`` text gets each line as a change action.
    """

    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    likely_cause: str
    evidence: list[Evidence] = Field(default_factory=list)
    checked: list[Checked] = Field(default_factory=list)
    actions: list[Action]
    severity: Severity
    fix_effort: Effort
    fix_effort_reason: str = Field(max_length=MAX_EFFORT_REASON_CHARS)
    error_signature: str | None = Field(default=None, max_length=MAX_ERROR_SIGNATURE_CHARS)
    confidence: Confidence | None = None
    confidence_reason: str | None = None
    hypotheses: list[Hypothesis] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _suggested_actions(cls, data: Any) -> Any:
        if not isinstance(data, dict) or "actions" in data:
            return data
        suggested = data.get("suggested_actions")
        if not isinstance(suggested, list):
            return data
        return {
            **data,
            "actions": [
                {"kind": "change", "text": text} for text in suggested if isinstance(text, str)
            ],
        }

    @field_validator("checked", mode="before")
    @classmethod
    def _checked(cls, value: Any) -> list[Any]:
        return _usable_items(value, MAX_CHECKED)

    @field_validator("actions", mode="before")
    @classmethod
    def _actions(cls, value: Any) -> Any:
        return _usable_items(value, MAX_ACTIONS) if isinstance(value, list) else value

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence(cls, value: Any) -> Confidence | None:
        return value if value in CONFIDENCE_LEVELS else None

    @field_validator("confidence_reason", mode="before")
    @classmethod
    def _confidence_reason(cls, value: Any) -> str | None:
        return value[:MAX_CONFIDENCE_REASON_CHARS] if isinstance(value, str) else None

    @field_validator("hypotheses", mode="before")
    @classmethod
    def _hypotheses(cls, value: Any) -> list[Any]:
        return _usable_items(value, MAX_HYPOTHESES)


class InvestigationJob(BaseModel):
    """A work-queue message: one signal, or a storm of signals, to investigate.

    Triage pre-allocates ``finding_id``; the finding is stored under it exactly once.
    ``keys`` are the resource keys the job holds ``active#`` items for, primary first,
    scoped by account for a member account (see accounts.py). ``signals`` lists the job's
    signals, the one it is about first; ``alarms`` holds the CloudWatch events among them,
    in the same order. A job written without ``signals`` gets them from its alarms.
    ``account_id`` and ``region`` say where every signal of the job lives; a job written
    without them takes its first signal's, else its alarm event's.
    """

    finding_id: str = Field(min_length=1)
    kind: Literal[FindingKind.ALARM, FindingKind.INCIDENT]
    signals: list[SignalRef] = Field(default_factory=list)
    alarms: list[AlarmStateChangeEvent] = Field(default_factory=list)
    alarm_count: int = Field(ge=1)
    keys: list[str] = Field(min_length=1)
    floor: Severity
    account_id: str = ""
    region: str = ""

    @model_validator(mode="after")
    def _signals(self) -> InvestigationJob:
        if not self.signals:
            self.signals = [SignalRef.for_alarm(event, self.floor) for event in self.alarms]
        if not self.signals:
            raise ValueError("a job needs at least one signal")
        alarm = self.alarm
        self.account_id = (
            self.account_id or self.signals[0].account_id or (alarm.account if alarm else "")
        )
        self.region = self.region or self.signals[0].region or (alarm.region if alarm else "")
        return self

    @property
    def signal(self) -> SignalRef:
        return self.signals[0]

    @property
    def alarm(self) -> AlarmStateChangeEvent | None:
        """The CloudWatch event of the signal the job is about; None for a Datadog signal."""
        if self.signal.source != "cloudwatch" or not self.alarms:
            return None
        return self.alarms[0]

    @property
    def resource_key(self) -> str:
        return self.keys[0]

    @property
    def local_keys(self) -> list[str]:
        """The keys as the resources' own account names them, without an account scope."""
        return [local_key(key) for key in self.keys]

    @property
    def local_resource_key(self) -> str:
        return local_key(self.keys[0])


class ContextSummary(BaseModel):
    """What the precomputed context bundle held, for evaluation; never its content.

    ``sections`` maps each bundle section to available, unavailable, skipped or
    not_applicable; ``counts`` holds the number of items an available section listed.
    """

    sections: dict[str, str]
    counts: dict[str, int]
    chars: int
    truncated: bool


Resolution = Literal["confirmed", "false_positive", "wrong", "dismissed"]


class ToolCallDescriptor(BaseModel):
    """What one tool call read, in the same shape for every tool.

    ``label`` is ``<provider>.<service>.<action>``; ``subject`` names the resource read,
    redacted and cut, when the input names one. Every tool produces ``kind``
    ``evidence``; ``lookup`` (a read of a catalog, not the account) is accepted too.
    ``refused`` is the short reason a policy refused the call (its step's status is
    ``error``). A reader of the findings table can render a trail step from this alone.
    """

    provider: Literal["aws", "datadog", "github"]
    service: str
    action: str
    label: str
    subject: str | None = None
    kind: Literal["evidence", "lookup"] = "evidence"
    refused: str | None = None


class ToolTrailStep(BaseModel):
    """One tool call of an investigation: what was asked and whether it returned data.

    ``input`` is the redacted input summary and ``args`` the redacted, size-capped input
    arguments; a tool's output is never kept here. ``call`` describes the call; a stored
    step may lack it.
    """

    step: int = Field(ge=1)
    tool: str
    status: Literal["data", "empty", "error"]
    input: str
    args: dict[str, Any] = Field(default_factory=dict)
    call: ToolCallDescriptor | None = None


class RunSummary(BaseModel):
    """How an investigation ended and what it spent.

    ``stop_reason`` is chose when the model reported on its own; turn_limit,
    token_budget or time when that limit forced the reporting turn (or, for time, ended
    the run before one); no_report when the forced turn gave no valid report; and
    model_error when a model call failed or returned nothing.
    """

    stop_reason: StopReason
    turns: int
    max_turns: int
    duration_seconds: float
    weighted_tokens: int
    token_budget: int


class Finding(BaseModel):
    """A recorded investigation outcome, as stored in the findings table.

    ``suggested_actions`` is each action as one line of text, for Slack. A review tool sets
    ``resolution``, ``resolved_at`` and ``resolved_by`` when a person closes the finding;
    the agent writes them empty. ``source`` is where the signal came from; for a Datadog
    signal ``alarm_name`` is the monitor name with its group and ``alarm_arn`` its
    ``datadog:monitor/<id>/<group>`` identity. A storm finding counts its signals in
    ``alarm_count``, ``source_counts`` and ``resource_counts`` (by primary resource key).
    ``account_id`` and ``region`` are where the signal's resource lives; null when unknown.
    """

    finding_id: str
    created_at: str
    env: str
    source: SignalSource = "cloudwatch"
    account_id: str | None = None
    region: str | None = None
    alarm_name: str
    alarm_arn: str
    severity: Severity
    severity_floor: Severity
    proposed_severity: Severity | None
    title: str
    summary: str
    likely_cause: str
    evidence: list[Evidence]
    checked: list[Checked] = Field(default_factory=list)
    actions: list[Action] = Field(default_factory=list)
    suggested_actions: list[str]
    fix_effort: Effort
    fix_effort_reason: str
    status: Literal["open"] = "open"
    steps: int
    model_id: str
    outcome: Literal["reported", "incomplete", "triaged"]
    ttl: int
    kind: FindingKind = FindingKind.ALARM
    resource_key: str
    incident_id: str | None = None
    linked_to: str | None = None
    linked_alarms: list[str] = Field(default_factory=list)
    recurrence_count: int = 0
    last_seen_at: str | None = None
    previous_finding_id: str | None = None
    error_signature: str | None = None
    confidence: Confidence | None = None
    confidence_reason: str | None = None
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    member_alarms: list[str] = Field(default_factory=list)
    alarm_count: int | None = None
    source_counts: dict[str, int] = Field(default_factory=dict)
    resource_counts: dict[str, int] = Field(default_factory=dict)
    context_summary: ContextSummary | None = None
    alarm_reason: str | None = None
    alarm_time: str | None = None
    tools_used: list[str] = Field(default_factory=list)
    tool_call_count: int | None = None
    sources_with_data: list[str] = Field(default_factory=list)
    tool_trail: list[ToolTrailStep] = Field(default_factory=list)
    prior_finding_ids: list[str] = Field(default_factory=list)
    tokens_used: int = 0
    weighted_tokens: int = 0
    run: RunSummary | None = None
    resolution: Resolution | None = None
    resolved_at: str | None = None
    resolved_by: str | None = None
