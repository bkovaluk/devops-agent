"""Signals: what triage works on, whichever source raised it.

The alarms queue carries EventBridge events from two sources: CloudWatch "Alarm State
Change" events, and Datadog monitor notifications delivered through Datadog's partner
event bus. ``parse_signal`` dispatches on the event's ``detail-type`` to that source's
parser; each returns a ``Signal`` or None when the event is not one to triage. Everything
after parsing (opt-out, repeat, cooldown, links, storms, budgets) is the same for both.

A parser reads only the payload. A CloudWatch event names no severity, so its priority
is the lowest until triage reads the alarm's tags; a Datadog payload is untrusted until
triage reads the monitor back, which settles its priority, tags and resource keys.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from aws_lambda_powertools import Logger
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from devops_agent.catalog import load_catalog
from devops_agent.models import (
    ALARM_STATE_CHANGE,
    DATADOG_ALERT,
    AlarmStateChangeEvent,
    Severity,
    SignalRef,
)

logger = Logger(service="devops-agent", child=True)

# Monitor states a notification is triaged in; Warn counts only for priority 1, once the
# monitor is read back.
ALERTING_STATES = frozenset({"Alert", "Warn"})
_ALERT_TYPE_STATES = {"error": "Alert", "warning": "Warn"}
# A simple (ungrouped) monitor's only group.
SIMPLE_GROUP = "*"
MAX_SIGNAL_TAGS = 50
_EPOCH_MILLISECONDS = 10**12
_BY_BRACES = re.compile(r"\bby\s*\{([^}]*)\}", re.IGNORECASE)
_BY_CALL = re.compile(r"\.by\(([^)]*)\)", re.IGNORECASE)


class Signal(SignalRef):
    """A parsed signal: its reference plus the env it names, its resource keys and the
    event it came from (``raw``, the EventBridge event as received)."""

    env: str = ""
    resource_keys: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)

    def as_ref(self) -> SignalRef:
        return SignalRef.model_validate(self.model_dump(include=set(SignalRef.model_fields)))


def alarm_event(signal: Signal) -> AlarmStateChangeEvent:
    """The CloudWatch event a cloudwatch signal was parsed from."""
    return AlarmStateChangeEvent.model_validate(signal.raw)


def tag_list(value: Any) -> list[str]:
    """Datadog tags as a list of strings: a list, or one comma-separated string."""
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def tag_pairs(tags: Iterable[str]) -> dict[str, str]:
    """``key:value`` tags as a dict, keys lowercased; the first value of a key wins."""
    pairs: dict[str, str] = {}
    for tag in tags:
        key, sep, value = tag.partition(":")
        if sep and key.strip() and value.strip():
            pairs.setdefault(key.strip().lower(), value.strip())
    return pairs


def datadog_priority(value: Any) -> int | None:
    """A monitor priority (1 to 5) as a signal priority (1 to 4); None when unset."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return min(value, 4)


def group_keys(query: str) -> list[str]:
    """The tag keys a multi-alert monitor groups by, from its ``by {...}`` or ``.by(...)``."""
    keys = [key for match in _BY_BRACES.finditer(query) for key in match.group(1).split(",")]
    keys += [key for match in _BY_CALL.finditer(query) for key in match.group(1).split(",")]
    cleaned = (key.strip().strip("'\"").strip().lower() for key in keys)
    return list(dict.fromkeys(key for key in cleaned if key))


def datadog_keys(
    monitor_id: int, group: str, group_tags: Iterable[str], tags: Iterable[str], query: str
) -> list[str]:
    """The resource key of a monitor group, in the scheme CloudWatch alarms key by.

    An ECS service (a ``service`` tag on a monitor tagged or querying ``source:ecs``) keys
    as ``AWS/ECS:ServiceName=<service>``: the ECS service name is the Datadog service. Any
    other group keys as ``datadog:monitor=<id>/<group>``. The group's own tags win over
    the monitor's.
    """
    tag_set = [*group_tags, *tags]
    on_ecs = "source:ecs" in {tag.lower() for tag in tag_set} or "source:ecs" in query.lower()
    if (service := tag_pairs(tag_set).get("service")) and on_ecs:
        return [f"AWS/ECS:ServiceName={service}"]
    return [f"datadog:monitor={monitor_id}/{group or SIMPLE_GROUP}"]


def _object(value: Any) -> Any:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


class _Monitor(BaseModel):
    id: int | None = None
    name: str = ""
    type: str = ""
    query: str = ""
    tags: list[str] = Field(default_factory=list)
    priority: int | None = None

    @field_validator("id", mode="before")
    @classmethod
    def _id(cls, value: Any) -> int | None:
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    @field_validator("name", "type", "query", mode="before")
    @classmethod
    def _strings(cls, value: Any) -> str:
        return _text(value)

    @field_validator("tags", mode="before")
    @classmethod
    def _tags(cls, value: Any) -> list[str]:
        return tag_list(value)

    @field_validator("priority", mode="before")
    @classmethod
    def _priority(cls, value: Any) -> int | None:
        return datadog_priority(value)


class _Result(BaseModel):
    result_ts: float | None = None
    evaluation_ts: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("result_ts", "evaluation_ts", mode="before")
    @classmethod
    def _timestamp(cls, value: Any) -> float | None:
        return value if isinstance(value, int | float) and not isinstance(value, bool) else None

    @field_validator("metadata", mode="before")
    @classmethod
    def _metadata(cls, value: Any) -> Any:
        return _object(value)


class _States(BaseModel):
    source_state: str = ""
    dest_state: str = ""

    @field_validator("source_state", "dest_state", mode="before")
    @classmethod
    def _strings(cls, value: Any) -> str:
        return _text(value)


class _Transition(BaseModel):
    trans_name: str = ""

    @field_validator("trans_name", mode="before")
    @classmethod
    def _strings(cls, value: Any) -> str:
        return _text(value)


class _Meta(BaseModel):
    monitor: _Monitor = Field(default_factory=_Monitor)
    result: _Result = Field(default_factory=_Result)
    transition: _Transition = Field(default_factory=_Transition)
    states: _States = Field(default_factory=_States)

    @field_validator("monitor", "result", "transition", "states", mode="before")
    @classmethod
    def _objects(cls, value: Any) -> Any:
        return _object(value)


class _Detail(BaseModel):
    alert_type: str = ""
    tags: list[str] = Field(default_factory=list)
    meta: _Meta = Field(default_factory=_Meta)

    @field_validator("alert_type", mode="before")
    @classmethod
    def _strings(cls, value: Any) -> str:
        return _text(value)

    @field_validator("tags", mode="before")
    @classmethod
    def _tags(cls, value: Any) -> list[str]:
        return tag_list(value)

    @field_validator("meta", mode="before")
    @classmethod
    def _meta(cls, value: Any) -> Any:
        return _object(value)


class DatadogNotification(BaseModel):
    """A Datadog "Alert Notification" event from the partner event bus.

    Every field is optional and a field of the wrong type reads as empty; fields not
    named here are ignored.
    """

    model_config = ConfigDict(populate_by_name=True)

    detail_type: str = Field(alias="detail-type")
    source: str = ""
    time: str = ""
    detail: _Detail = Field(default_factory=_Detail)

    @field_validator("source", "time", mode="before")
    @classmethod
    def _strings(cls, value: Any) -> str:
        return _text(value)

    @field_validator("detail", mode="before")
    @classmethod
    def _detail(cls, value: Any) -> Any:
        return _object(value)


def _epoch(value: float | None) -> str | None:
    if value is None or value <= 0:
        return None
    seconds = value / 1000 if value >= _EPOCH_MILLISECONDS else value
    try:
        return datetime.fromtimestamp(seconds, UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _event_time(value: str) -> str | None:
    try:
        return datetime.fromisoformat(value).astimezone(UTC).isoformat() if value else None
    except ValueError:
        return None


def monitor_group(query: str, tags: Iterable[str], metadata: dict[str, Any]) -> list[str]:
    """The group tags of a notification, in the order the monitor's query groups by.

    A simple monitor has none. The tags come from the event's tags, then from string
    entries of the result metadata.
    """
    keys = group_keys(query)
    pairs = {
        **tag_pairs(f"{key}:{value}" for key, value in metadata.items() if isinstance(value, str)),
        **tag_pairs(tags),
    }
    return [f"{key}:{pairs[key]}" for key in keys if key in pairs]


def monitor_signal_name(subject: str, group: str) -> str:
    """A monitor group's signal name: the monitor name, with its group when grouped."""
    if group == SIMPLE_GROUP:
        return subject
    return f"{subject} ({group or 'unknown group'})"


def _dest_state(detail: _Detail) -> str:
    return detail.meta.states.dest_state or _ALERT_TYPE_STATES.get(detail.alert_type, "")


def datadog_monitor(event: dict[str, Any]) -> Signal | None:
    """The signal of a monitor notification entering Alert or Warn, else None."""
    try:
        parsed = DatadogNotification.model_validate(event)
    except ValidationError:
        logger.info("ignored: unreadable Datadog notification")
        return None
    detail = parsed.detail
    monitor = detail.meta.monitor
    if monitor.id is None:
        logger.info("ignored: Datadog notification names no monitor")
        return None
    dest_state = _dest_state(detail)
    if dest_state not in ALERTING_STATES:
        logger.info(
            "ignored: monitor not entering Alert or Warn",
            extra={"monitor_id": monitor.id, "state": dest_state},
        )
        return None
    grouped = bool(group_keys(monitor.query))
    group_tags = monitor_group(monitor.query, detail.tags, detail.meta.result.metadata)
    group = ",".join(group_tags) if grouped else SIMPLE_GROUP
    subject = monitor.name or f"Datadog monitor {monitor.id}"
    result = detail.meta.result
    return Signal(
        source="datadog",
        name=monitor_signal_name(subject, group),
        subject=subject,
        observed_at=_epoch(result.evaluation_ts)
        or _epoch(result.result_ts)
        or _event_time(parsed.time),
        priority=monitor.priority or 4,
        env=tag_pairs(detail.tags).get("env", ""),
        resource_keys=datadog_keys(
            monitor.id, group, group_tags, [*monitor.tags, *detail.tags], monitor.query
        ),
        ref={
            "monitor_id": monitor.id,
            "group": group,
            "group_tags": group_tags,
            "query": monitor.query,
            "monitor_type": monitor.type,
            "monitor_tags": monitor.tags[:MAX_SIGNAL_TAGS],
            "event_tags": detail.tags[:MAX_SIGNAL_TAGS],
            "source_state": detail.meta.states.source_state,
            "dest_state": dest_state,
            "transition": detail.meta.transition.trans_name,
        },
        raw=event,
    )


def cloudwatch_alarm(event: dict[str, Any]) -> Signal | None:
    """The signal of an alarm entering ALARM, else None; alarms the catalog excludes (scaling
    alarms, the agent's own) are None."""
    try:
        parsed = AlarmStateChangeEvent.model_validate(event)
    except ValidationError:
        logger.info(
            "ignored: not an alarm state change", extra={"detail_type": event.get("detail-type")}
        )
        return None
    if not parsed.is_alarm:
        logger.info(
            "ignored: not entering ALARM",
            extra={"detail_type": parsed.detail_type, "state": parsed.detail.state.value},
        )
        return None
    if parsed.alarm_name.startswith(tuple(load_catalog().agent.exclude_alarm_prefixes)):
        logger.info("ignored: excluded alarm", extra={"alarm_name": parsed.alarm_name})
        return None
    ref = SignalRef.for_alarm(parsed, Severity.LOW)
    return Signal(**ref.model_dump(), raw=event)


SignalParser = Callable[[dict[str, Any]], Signal | None]

PARSERS: dict[str, SignalParser] = {
    ALARM_STATE_CHANGE: cloudwatch_alarm,
    DATADOG_ALERT: datadog_monitor,
}


def parse_signal(event: Any) -> Signal | None:
    """The signal an alarms-queue event carries, or None when it is not one to triage."""
    detail_type = event.get("detail-type") if isinstance(event, dict) else None
    parser = PARSERS.get(detail_type) if isinstance(detail_type, str) else None
    if parser is None or not isinstance(event, dict):
        logger.info("ignored: not a known signal", extra={"detail_type": detail_type})
        return None
    return parser(event)
