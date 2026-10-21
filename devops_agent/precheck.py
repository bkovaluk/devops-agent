"""Precomputed incident context: fixed reads gathered by code before the first model call.

Each section is read independently; a failed read is recorded as unavailable and the
rest still run. The whole precheck has a wall-time budget, and the rendered bundle is
redacted and capped before it reaches the model.
"""

from __future__ import annotations

import json
import math
import statistics
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

from aws_lambda_powertools import Logger
from botocore.exceptions import ClientError

from devops_agent.models import ContextSummary, InvestigationJob
from devops_agent.notes import SERVICE_NOTES, ServiceNote
from devops_agent.redact import redact_value
from devops_agent.tools import (
    AlarmInput,
    InstanceInput,
    LogsQueryInput,
    MetricInput,
    ToolContext,
    ToolError,
    database_events,
    describe_instance,
    find_log_sources,
    firing_alarms,
    get_alarm,
    lookup_changes,
    metric_points,
    offered_tools,
    primary_key,
    project_firing_alarm,
    query_logs,
)

logger = Logger(service="devops-agent", child=True)

PRECHECK_BUDGET_SECONDS = 60.0
MAX_CONTEXT_CHARS = 12_000
ALARM_HISTORY_HOURS = 24
METRIC_WINDOW_HOURS = 3
BASELINE_DAYS = 7
METRIC_PERIOD_SECONDS = 300
MAX_PATTERN_GROUPS = 3
PATTERN_LEAD_MINUTES = 15
MAX_PATTERN_MINUTES = 60
MAX_PATTERN_CHARS = 300
CHANGE_MINUTES = 360
MAX_CHANGES = 20
MAX_SIBLINGS = 10
MAX_NOTE_ENTRIES = 3
MAX_NOTE_CHARS = 1_000
DATABASE_NAMESPACES = frozenset({"AWS/RDS", "AWS/DocDB"})
PATTERN_QUERY = (
    "filter @message like /(?i)(error|exception|fail|timeout|denied)/ "
    "| pattern @message | sort @sampleCount desc | limit 10"
)
TRUNCATED_MARKER = "\n[context cut at the size cap]"

Status = Literal["available", "unavailable", "skipped", "not_applicable"]


class _Unavailable(Exception):
    """A section that could not be read for a reason the code knows."""


class _NotApplicable(Exception):
    """A section that does not apply to this alarm."""


DATADOG_SIGNAL = "the signal is a Datadog monitor"


@dataclass(frozen=True)
class _Section:
    name: str
    status: Status
    content: Any
    count: int | None = None


@dataclass(frozen=True)
class IncidentContext:
    text: str
    summary: ContextSummary


def _failure(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code") or "ClientError")
    if isinstance(exc, _Unavailable):
        return str(exc)
    return type(exc).__name__


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _stats(values: Sequence[float]) -> dict[str, float] | None:
    if not values:
        return None
    return {
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "p50": round(statistics.median(values), 4),
        "last": round(values[-1], 4),
    }


def _average_stats(days: Sequence[dict[str, float]]) -> dict[str, float] | None:
    if not days:
        return None
    return {name: round(sum(day[name] for day in days) / len(days), 4) for name in days[0]}


class _Precheck:
    def __init__(
        self,
        ctx: ToolContext,
        job: InvestigationJob,
        now: datetime,
        past_sources: Callable[[], list[dict[str, Any]]],
        clock: Callable[[], float],
        notes: Sequence[ServiceNote],
    ) -> None:
        self._ctx = ctx
        self._job = job
        self._now = now
        self._past_sources = past_sources
        self._clock = clock
        self._notes = notes
        self._started = clock()
        self._alarm: dict[str, Any] | None = None
        self._log_groups: list[str] = []

    def _out_of_time(self) -> bool:
        return self._clock() - self._started >= PRECHECK_BUDGET_SECONDS

    def run(self) -> list[_Section]:
        steps: list[tuple[str, Callable[[], tuple[Any, int]]]] = [
            ("alarm", self._read_alarm),
            ("metric", self._read_metric),
            ("log_sources", self._read_log_sources),
            ("log_patterns", self._read_log_patterns),
            ("changes", self._read_changes),
            ("siblings", self._read_siblings),
            ("database_events", self._read_database_events),
            ("instance", self._read_instance),
            ("service_notes", self._read_service_notes),
            ("sources_last_time", self._read_past_sources),
        ]
        return [self._section(name, step) for name, step in steps]

    def _section(self, name: str, step: Callable[[], tuple[Any, int]]) -> _Section:
        if self._out_of_time():
            return _Section(name, "skipped", "skipped: precheck time budget spent")
        try:
            content, count = step()
        except _NotApplicable as exc:
            return _Section(name, "not_applicable", f"not applicable: {exc}")
        except Exception as exc:
            logger.warning("precheck section unavailable", extra={"section": name})
            return _Section(name, "unavailable", f"unavailable: {_failure(exc)}")
        return _Section(name, "available", content, count)

    def _alarm_name(self) -> str:
        """The CloudWatch alarm the job is about; a Datadog signal has none."""
        if self._job.alarm is None:
            raise _NotApplicable(f"{DATADOG_SIGNAL}; the opening message describes it")
        return self._job.alarm.alarm_name

    def _read_alarm(self) -> tuple[Any, int]:
        result = get_alarm(AlarmInput(alarm_name=self._alarm_name()), self._ctx)
        self._alarm = result["alarm"]
        since = self._now - timedelta(hours=ALARM_HISTORY_HOURS)
        history = [
            item
            for item in result["history"]
            if item.get("type") == "StateUpdate"
            and (at := _parse_time(item.get("time"))) is not None
            and at >= since
        ]
        return {**result, "history": history}, len(history)

    def _read_metric(self) -> tuple[Any, int]:
        self._alarm_name()
        alarm = self._alarm
        if alarm is None:
            raise _Unavailable("alarm config not read")
        if alarm.get("alarm_rule") or alarm.get("metrics"):
            raise _NotApplicable("composite or metric-math alarm; read its metrics with get_metric")
        if not alarm.get("namespace") or not alarm.get("metric_name"):
            raise _NotApplicable("the alarm watches no single metric")
        params = MetricInput(
            namespace=alarm["namespace"],
            metric_name=alarm["metric_name"],
            dimensions=alarm.get("dimensions") or {},
            stat=alarm.get("statistic") or "Average",
            period_seconds=max(int(alarm.get("period") or 0), METRIC_PERIOD_SECONDS),
        )
        window = timedelta(hours=METRIC_WINDOW_HOURS)
        start = self._now - timedelta(days=BASELINE_DAYS) - window
        max_points = math.ceil((self._now - start).total_seconds() / params.period_seconds) + 1
        status, points = metric_points(self._ctx.cloudwatch, params, start, self._now, max_points)

        def in_window(days_back: int) -> list[float]:
            end = self._now - timedelta(days=days_back)
            return [value for ts, value in points if end - window < ts <= end]

        current = in_window(0)
        baseline_days = [
            stats
            for days_back in range(1, BASELINE_DAYS + 1)
            if (stats := _stats(in_window(days_back))) is not None
        ]
        content = {
            "namespace": params.namespace,
            "metric_name": params.metric_name,
            "dimensions": params.dimensions,
            "stat": params.stat,
            "period_seconds": params.period_seconds,
            "window_hours": METRIC_WINDOW_HOURS,
            "status": status or "NoData",
            "now": _stats(current),
            "baseline": _average_stats(baseline_days),
            "baseline_days_with_data": len(baseline_days),
        }
        return content, len(current)

    def _read_log_sources(self) -> tuple[Any, int]:
        if self._job.alarm is None:
            raise _NotApplicable(f"{DATADOG_SIGNAL}; search its logs with the Datadog tools")
        result = find_log_sources(AlarmInput(alarm_name=self._alarm_name()), self._ctx)
        self._log_groups = [source["log_group"] for source in result["sources"]]
        return result, len(self._log_groups)

    def _pattern_minutes(self) -> int:
        entered = _parse_time(self._job.signal.observed_at)
        if entered is None:
            return MAX_PATTERN_MINUTES
        since = math.ceil((self._now - entered).total_seconds() / 60) + PATTERN_LEAD_MINUTES
        return max(1, min(since, MAX_PATTERN_MINUTES))

    def _read_log_patterns(self) -> tuple[Any, int]:
        groups = self._log_groups[:MAX_PATTERN_GROUPS]
        if not groups:
            raise _NotApplicable("no log sources found")
        minutes = self._pattern_minutes()
        results: list[dict[str, Any]] = []
        count = 0
        for group in groups:
            if self._out_of_time():
                results.append({"log_group": group, "patterns": "skipped: time budget spent"})
                continue
            try:
                result = query_logs(
                    LogsQueryInput(
                        log_group=group,
                        query=PATTERN_QUERY,
                        start=self._now - timedelta(minutes=minutes),
                        end=self._now,
                    ),
                    self._ctx,
                )
            except Exception as exc:
                results.append({"log_group": group, "patterns": f"unavailable: {_failure(exc)}"})
                continue
            patterns = [
                {
                    "pattern": row.get("@pattern", "")[:MAX_PATTERN_CHARS],
                    "count": row.get("@sampleCount"),
                }
                for row in result["rows"]
            ]
            count += len(patterns)
            results.append({"log_group": group, "status": result["status"], "patterns": patterns})
        return {"window_minutes": minutes, "query": PATTERN_QUERY, "groups": results}, count

    def _read_changes(self) -> tuple[Any, int]:
        start = self._now - timedelta(minutes=CHANGE_MINUTES)
        result = lookup_changes(self._ctx.cloudtrail, start, self._now, MAX_CHANGES)
        return {"window_minutes": CHANGE_MINUTES, **result}, int(result["count"])

    def _read_siblings(self) -> tuple[Any, int]:
        own = {signal.name for signal in self._job.signals}
        keys = set(self._job.local_keys)
        others, more = firing_alarms(self._ctx.cloudwatch, self._job.signal.name)
        matches: list[dict[str, Any]] = []
        for alarm in others:
            name = alarm.get("AlarmName")
            if name in own:
                continue
            primary = primary_key(alarm)
            key = primary[0] if primary else f"alarm:{name}"
            if key in keys:
                matches.append({**project_firing_alarm(alarm), "resource_key": key})
        shown = matches[:MAX_SIBLINGS]
        content = {
            "keys": self._job.local_keys,
            "alarms": shown,
            "truncated": len(matches) > MAX_SIBLINGS or more,
        }
        return content, len(shown)

    def _read_database_events(self) -> tuple[Any, int]:
        namespace, _, dimension = self._job.local_resource_key.partition(":")
        name, _, identifier = dimension.partition("=")
        if namespace not in DATABASE_NAMESPACES or not identifier:
            raise _NotApplicable("the primary resource is not an RDS or DocumentDB database")
        source_type = "db-cluster" if name == "DBClusterIdentifier" else "db-instance"
        events = database_events(self._ctx, identifier, source_type)
        return {"identifier": identifier, **events}, len(events["items"])

    def _read_instance(self) -> tuple[Any, int]:
        namespace, _, dimension = self._job.local_resource_key.partition(":")
        name, _, instance_id = dimension.partition("=")
        if namespace != "AWS/EC2" or name != "InstanceId" or not instance_id:
            raise _NotApplicable("the primary resource is not an EC2 instance")
        try:
            instance = describe_instance(InstanceInput(instance_id=instance_id), self._ctx)
        except ToolError as exc:
            raise _Unavailable(str(exc)) from None
        return instance, 1

    def _read_service_notes(self) -> tuple[Any, int]:
        names = [signal.name.lower() for signal in self._job.signals]
        targets = [*names, self._job.local_resource_key.lower()]
        matched = [
            note
            for note in self._notes
            if any(part in target for part in note.match for target in targets)
        ]
        if not matched:
            raise _NotApplicable("no service note matches the alarm or its resource")
        entries: list[dict[str, Any]] = []
        chars = 0
        truncated = len(matched) > MAX_NOTE_ENTRIES
        for note in matched[:MAX_NOTE_ENTRIES]:
            lines: list[str] = []
            for line in note.notes:
                if chars + len(line) > MAX_NOTE_CHARS:
                    truncated = True
                    break
                lines.append(line)
                chars += len(line)
            if not lines:
                break
            entries.append({"service": note.service, "notes": lines})
        return {"entries": entries, "truncated": truncated}, len(entries)

    def _read_past_sources(self) -> tuple[Any, int]:
        """The stored useful calls of tools this run offers; a stored call of a tool that
        is gone or not configured would point the model at a call it cannot make."""
        offered = {tool.name for tool in offered_tools(self._ctx)}
        entries = [entry for entry in self._past_sources() if entry.get("tool") in offered]
        return entries, len(entries)


def _render(sections: Sequence[_Section]) -> tuple[str, bool]:
    # Redacted before the cut: a secret split at the cap is no longer recognizable.
    text = "\n\n".join(
        f"## {section.name}\n{json.dumps(redact_value(section.content), default=str)}"
        for section in sections
    )
    if len(text) <= MAX_CONTEXT_CHARS:
        return text, False
    return text[: MAX_CONTEXT_CHARS - len(TRUNCATED_MARKER)] + TRUNCATED_MARKER, True


def build_context(
    ctx: ToolContext,
    job: InvestigationJob,
    now: datetime,
    past_sources: Callable[[], list[dict[str, Any]]],
    clock: Callable[[], float] = time.monotonic,
    notes: Sequence[ServiceNote] = SERVICE_NOTES,
) -> IncidentContext:
    """The context bundle for a job and a summary of what it held."""
    sections = _Precheck(ctx, job, now, past_sources, clock, notes).run()
    text, truncated = _render(sections)
    summary = ContextSummary(
        sections={section.name: section.status for section in sections},
        counts={
            section.name: section.count
            for section in sections
            if section.status == "available" and section.count is not None
        },
        chars=len(text),
        truncated=truncated,
    )
    return IncidentContext(text, summary)
