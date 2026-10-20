"""Finding assembly and the stored item shape."""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from devops_agent.active import claim_keys, link_alarm, release_keys
from devops_agent.agent import Investigation, investigate
from devops_agent.config import Settings
from devops_agent.findings import (
    MAX_TOOL_TRAIL,
    OPEN_FINDING_RETENTION_DAYS,
    build_finding,
    build_triage_finding,
    closed_in_cooldown,
    finding_exists,
    is_reviewed,
    open_investigation_for_alarm,
    prior_findings,
    record_recurrence,
    record_useful_sources,
    store_finding,
    store_snapshot,
    to_item,
)
from devops_agent.gate import (
    add_daily_tokens,
    consume_daily_budget,
    consume_datadog_share,
    consume_hourly_budget,
    consume_p1_overflow,
)
from devops_agent.models import (
    AlarmStateChangeEvent,
    Effort,
    FindingKind,
    InvestigationJob,
    ReportedFinding,
    Severity,
    SignalRef,
    ToolTrailStep,
)
from devops_agent.redact import REDACTED, redact_finding
from devops_agent.storm import Storm, claim_storm, record_rate
from devops_agent.tools import ToolContext
from tests.conftest import (
    ALARM_ARN,
    ALARM_NAME,
    FUNCTION_KEY,
    FakeBedrock,
    FakeTable,
    alarm_event,
    client_error,
    converse_response,
    datadog_job,
    has_float,
    job,
    report,
    tool_use,
)

NOW = datetime(2026, 9, 29, 14, 5, tzinfo=UTC)
FIELDS = {
    "pk",
    "finding_id",
    "created_at",
    "env",
    "source",
    "alarm_name",
    "alarm_arn",
    "severity",
    "severity_floor",
    "proposed_severity",
    "title",
    "summary",
    "likely_cause",
    "evidence",
    "checked",
    "actions",
    "suggested_actions",
    "fix_effort",
    "fix_effort_reason",
    "status",
    "steps",
    "model_id",
    "outcome",
    "ttl",
    "kind",
    "resource_key",
    "incident_id",
    "linked_to",
    "linked_alarms",
    "recurrence_count",
    "last_seen_at",
    "previous_finding_id",
    "error_signature",
    "confidence",
    "confidence_reason",
    "hypotheses",
    "member_alarms",
    "alarm_count",
    "source_counts",
    "resource_counts",
    "context_summary",
    "alarm_reason",
    "alarm_time",
    "tools_used",
    "tool_call_count",
    "sources_with_data",
    "tool_trail",
    "prior_finding_ids",
    "tokens_used",
    "weighted_tokens",
    "run",
    "resolution",
    "resolved_at",
    "resolved_by",
}


def _signal() -> SignalRef:
    return SignalRef.for_alarm(AlarmStateChangeEvent.model_validate(alarm_event()), Severity.HIGH)


def _job(floor: Severity = Severity.HIGH) -> InvestigationJob:
    return job(floor=floor, finding_id="f-1")


def _reported(severity: str, **overrides: Any) -> Investigation:
    body = ReportedFinding.model_validate(report(severity, **overrides)["toolUse"]["input"])
    return Investigation("reported", body, 3, "model-a", ("get_metric",))


def test_reported_finding_takes_higher_of_floor_and_proposal() -> None:
    finding = build_finding(env="prod", job=_job(), investigation=_reported("low"), now=NOW)
    assert finding.severity is Severity.HIGH
    assert finding.proposed_severity is Severity.LOW
    assert finding.outcome == "reported"
    assert finding.alarm_arn == ALARM_ARN


def test_incomplete_finding_uses_alarm_name_and_floor() -> None:
    investigation = Investigation("incomplete", None, 10, "model-a", ())
    finding = build_finding(
        env="staging", job=_job(Severity.MEDIUM), investigation=investigation, now=NOW
    )
    assert finding.outcome == "incomplete"
    assert finding.severity is Severity.MEDIUM
    assert finding.proposed_severity is None
    assert ALARM_NAME in finding.title
    assert "did not finish" in finding.summary
    assert finding.fix_effort is Effort.UNKNOWN
    assert finding.fix_effort_reason == ""


def test_reported_finding_keeps_fix_effort_and_redacts_its_reason() -> None:
    investigation = _reported(
        "high",
        fix_effort="very_high",
        fix_effort_reason="Rotate key AKIAABCDEFGHIJKLMNOP across five services.",
    )
    finding = build_finding(env="prod", job=_job(), investigation=investigation, now=NOW)
    assert finding.fix_effort is Effort.VERY_HIGH
    assert "AKIAABCDEFGHIJKLMNOP" in finding.fix_effort_reason

    redacted = redact_finding(finding)
    assert redacted.fix_effort is Effort.VERY_HIGH
    assert redacted.fix_effort_reason == f"Rotate key {REDACTED} across five services."


def test_finding_expires_after_open_retention() -> None:
    finding = build_finding(env="prod", job=_job(), investigation=_reported("high"), now=NOW)
    assert OPEN_FINDING_RETENTION_DAYS == 90
    assert finding.ttl == int(NOW.timestamp()) + 90 * 86400


def test_item_shape_has_all_fields_and_no_floats() -> None:
    finding = build_finding(
        env="prod",
        job=_job(),
        investigation=_reported("critical"),
        now=NOW,
    )
    item = to_item(finding)
    assert set(item) == FIELDS
    assert item["pk"] == f"finding#{finding.finding_id}"
    assert item["status"] == "open"
    assert item["created_at"] == NOW.isoformat()
    assert item["evidence"] == [
        {"kind": "metric", "detail": "Errors 0 -> 120 at 14:02", "steps": []}
    ]
    assert item["fix_effort"] == "low"
    assert type(item["ttl"]) is int
    assert item["ttl"] == finding.ttl
    assert not has_float(item)


def test_store_finding_is_a_conditional_put() -> None:
    table = FakeTable()
    finding = build_finding(env="prod", job=_job(), investigation=_reported("high"), now=NOW)
    assert store_finding(table, finding)
    assert table.puts[0]["ConditionExpression"] == "attribute_not_exists(pk)"
    assert f"finding#{finding.finding_id}" in table.items
    assert finding_exists(table, finding.finding_id)


def test_store_finding_twice_is_a_no_op() -> None:
    table = FakeTable()
    first = build_finding(env="prod", job=_job(), investigation=_reported("high"), now=NOW)
    second = build_finding(env="prod", job=_job(), investigation=_reported("low"), now=NOW)
    assert store_finding(table, first)
    assert not store_finding(table, second)
    assert table.items["finding#f-1"]["proposed_severity"] == "high"


def test_finding_carries_the_job_id_kind_key_and_links() -> None:
    finding = build_finding(
        env="prod",
        job=_job(),
        investigation=_reported("high", error_signature="KeyError in handler.py:process"),
        now=NOW,
        linked_alarms=["other-alarm"],
        previous_finding_id="f-0",
    )
    assert finding.finding_id == "f-1"
    assert finding.kind is FindingKind.ALARM
    assert finding.resource_key == FUNCTION_KEY
    assert finding.linked_alarms == ["other-alarm"]
    assert finding.previous_finding_id == "f-0"
    assert finding.error_signature == "KeyError in handler.py:process"
    assert finding.recurrence_count == 0


def test_incomplete_incident_names_the_storm() -> None:
    storm = job("a", "b", kind=FindingKind.INCIDENT, alarm_count=7)
    investigation = Investigation("incomplete", None, 0, "model-a", ())
    finding = build_finding(
        env="prod", job=storm, investigation=investigation, now=NOW, error="RuntimeError"
    )
    assert finding.kind is FindingKind.INCIDENT
    assert finding.alarm_name == "a"
    assert "storm of 7 alarms" in finding.title
    assert "failed with RuntimeError" in finding.summary


def test_triage_finding_is_uninvestigated_with_the_floor() -> None:
    finding = build_triage_finding(
        env="prod",
        kind=FindingKind.LINKED,
        signal=_signal(),
        resource_key=FUNCTION_KEY,
        floor=Severity.MEDIUM,
        now=NOW,
        title="Linked",
        summary="Linked to f-1.",
        linked_to="f-1",
    )
    item = to_item(finding)
    assert set(item) == FIELDS
    assert item["kind"] == "linked"
    assert item["linked_to"] == "f-1"
    assert item["outcome"] == "triaged"
    assert item["severity"] == item["severity_floor"] == "medium"
    assert item["fix_effort"] == "unknown"
    assert item["steps"] == 0
    assert item["ttl"] == int(NOW.timestamp()) + 90 * 86400


def test_record_recurrence_counts_on_the_finding() -> None:
    table = FakeTable()
    finding = build_finding(env="prod", job=_job(), investigation=_reported("high"), now=NOW)
    store_finding(table, finding)
    record_recurrence(table, "f-1", NOW)
    record_recurrence(table, "f-1", NOW)
    item = table.items["finding#f-1"]
    assert item["recurrence_count"] == 2
    assert item["last_seen_at"] == NOW.isoformat()


def _stored(table: FakeTable, finding_id: str, created_at: str, **fields: Any) -> None:
    table.items[f"finding#{finding_id}"] = {
        "pk": f"finding#{finding_id}",
        "finding_id": finding_id,
        "created_at": created_at,
        "status": "open",
        "alarm_name": ALARM_NAME,
        "resource_key": FUNCTION_KEY,
        **fields,
    }


def test_prior_findings_query_by_resource_newest_first() -> None:
    table = FakeTable()
    for day in range(1, 6):
        _stored(table, f"f-{day}", f"2026-09-0{day}T00:00:00+00:00", status="resolved")
    _stored(table, "other", "2026-09-09T00:00:00+00:00", resource_key="AWS/SQS:QueueName=q")
    items = prior_findings(table, FUNCTION_KEY, 3)
    assert [item["finding_id"] for item in items] == ["f-5", "f-4", "f-3"]
    [query] = table.queries
    assert query["IndexName"] == "by_resource"
    assert query["KeyConditionExpression"] == "resource_key = :key"
    assert query["ScanIndexForward"] is False
    assert query["Limit"] == 3


def _investigation(table: FakeTable, finding_id: str, created_at: str, **fields: Any) -> None:
    _stored(table, finding_id, created_at, kind="alarm", outcome="reported", **fields)


def test_open_investigation_lookup_queries_the_resource_partition() -> None:
    table = FakeTable()
    _investigation(table, "mine", "2026-09-01T00:00:00+00:00")
    for n in range(3):
        _investigation(table, f"x-{n}", f"2026-09-02T00:00:0{n}+00:00", alarm_name="other")
    found = open_investigation_for_alarm(table, FUNCTION_KEY, ALARM_NAME, 2, 2)
    assert found is not None
    assert found["finding_id"] == "mine"
    assert [q["IndexName"] for q in table.queries] == ["by_resource", "by_resource"]
    query = table.queries[0]
    assert query["KeyConditionExpression"] == "resource_key = :key"
    assert query["ExpressionAttributeValues"][":key"] == FUNCTION_KEY
    assert query["ScanIndexForward"] is False
    assert query["Limit"] == 2
    assert table.queries[1]["ExclusiveStartKey"] == {"position": 2}


def test_open_investigation_lookup_stops_after_max_pages() -> None:
    table = FakeTable()
    _investigation(table, "mine", "2026-09-01T00:00:00+00:00")
    for n in range(4):
        _investigation(table, f"x-{n}", f"2026-09-02T00:00:0{n}+00:00", alarm_name="other")
    assert open_investigation_for_alarm(table, FUNCTION_KEY, ALARM_NAME, 2, 2) is None
    assert len(table.queries) == 2


@pytest.mark.parametrize(
    "fields",
    [
        {"kind": "alarm", "outcome": "reported", "status": "closed"},
        {"kind": "alarm", "outcome": "incomplete"},
        {"kind": "deferred", "outcome": "triaged"},
        {"kind": "linked", "outcome": "triaged"},
        {"kind": "grouped", "outcome": "triaged"},
        {"kind": "skipped", "outcome": "triaged"},
    ],
)
def test_only_open_reported_investigations_count(fields: dict[str, Any]) -> None:
    table = FakeTable()
    _stored(table, "f-1", "2026-09-01T00:00:00+00:00", **fields)
    assert open_investigation_for_alarm(table, FUNCTION_KEY, ALARM_NAME, 50, 2) is None


def test_acknowledged_investigation_counts_as_unclosed() -> None:
    table = FakeTable()
    _investigation(table, "ack", "2026-09-01T00:00:00+00:00", status="acknowledged")
    found = open_investigation_for_alarm(table, FUNCTION_KEY, ALARM_NAME, 50, 2)
    assert found is not None
    assert found["finding_id"] == "ack"


def test_closed_investigation_is_not_a_repeat() -> None:
    table = FakeTable()
    _investigation(
        table, "done", "2026-09-01T00:00:00+00:00", status="closed", resolution="confirmed"
    )
    assert open_investigation_for_alarm(table, FUNCTION_KEY, ALARM_NAME, 50, 2) is None


def test_open_incident_counts() -> None:
    table = FakeTable()
    _stored(table, "inc", "2026-09-01T00:00:00+00:00", kind="incident", outcome="reported")
    found = open_investigation_for_alarm(table, FUNCTION_KEY, ALARM_NAME, 50, 2)
    assert found is not None
    assert found["finding_id"] == "inc"


def test_incident_finding_stores_its_members_and_count() -> None:
    storm = job("a", "b", "c", kind=FindingKind.INCIDENT, alarm_count=60)
    finding = build_finding(env="prod", job=storm, investigation=_reported("high"), now=NOW)
    assert finding.member_alarms == ["a", "b", "c"]
    assert finding.alarm_count == 60


def test_alarm_finding_has_no_members() -> None:
    finding = build_finding(env="prod", job=_job(), investigation=_reported("high"), now=NOW)
    assert finding.member_alarms == []
    assert finding.alarm_count is None


def test_finding_records_the_tool_trail_without_outputs(
    tool_ctx: ToolContext, settings: Settings
) -> None:
    tool_ctx.logs.responses["start_query"] = {"queryId": "q"}
    rows = {"status": "Complete", "results": [[{"field": "@message", "value": "boom-secret"}]]}
    empty = {"status": "Complete", "results": []}
    answers = iter([rows, empty])
    tool_ctx.logs.responses["get_query_results"] = lambda **_: next(answers)
    tool_ctx.cloudtrail.responses["lookup_events"] = client_error("ThrottlingException")
    query = "fields @message | filter @message like /token=abc123/ " + "x" * 300
    bedrock = FakeBedrock(
        converse_response(
            tool_use("query_logs", {"log_group": "/aws/lambda/a", "query": query}, "t1"),
            tool_use("query_logs", {"log_group": "/aws/lambda/b", "query": "fields 1"}, "t2"),
            tool_use("recent_changes", {}, "t3"),
        ),
        converse_response(report("high")),
    )
    investigation = investigate(
        bedrock, tool_ctx, settings, _job(), "## alarm\n{}", [], lambda: math.inf
    )
    finding = build_finding(
        env="prod",
        job=_job(),
        investigation=investigation,
        now=NOW,
        prior_finding_ids=["f-0", "f-1"],
    )
    assert finding.tools_used == ["query_logs", "recent_changes"]
    assert finding.tool_call_count == 3
    assert finding.sources_with_data == ["query_logs"]
    assert [(step.step, step.tool, step.status) for step in finding.tool_trail] == [
        (1, "query_logs", "data"),
        (2, "query_logs", "empty"),
        (3, "recent_changes", "error"),
    ]
    first = finding.tool_trail[0].input
    assert len(first) <= 200
    assert "/aws/lambda/a" in first
    assert "abc123" not in first
    assert finding.prior_finding_ids == ["f-0", "f-1"]
    item = to_item(finding)
    assert "boom-secret" not in json.dumps(item, default=str)
    assert set(item["tool_trail"][0]) == {"step", "tool", "status", "input", "args", "call"}
    assert item["tool_trail"][0]["call"]["label"] == "aws.logs.query_logs"


def test_tool_trail_is_capped() -> None:
    trail = tuple(
        ToolTrailStep(step=n, tool="get_metric", status="empty", input="{}")
        for n in range(1, MAX_TOOL_TRAIL + 6)
    )
    investigation = Investigation(
        "incomplete", None, 14, "model-a", ("get_metric",) * len(trail), trail=trail
    )
    finding = build_finding(env="prod", job=_job(), investigation=investigation, now=NOW)
    assert len(finding.tool_trail) == MAX_TOOL_TRAIL
    assert finding.tool_call_count == MAX_TOOL_TRAIL + 5
    assert finding.tools_used == ["get_metric"]
    assert finding.sources_with_data == []


def test_finding_carries_the_alarm_reason_and_time() -> None:
    finding = build_finding(env="prod", job=_job(), investigation=_reported("high"), now=NOW)
    assert finding.alarm_reason == "Threshold Crossed: 3 datapoints were greater than 5.0"
    assert finding.alarm_time == "2026-09-29T14:05:00+00:00"


def test_incident_takes_its_primary_alarm_reason_and_time() -> None:
    storm = job("a", "b", kind=FindingKind.INCIDENT)
    storm.alarms[1].detail.state.reason = "second"
    finding = build_finding(env="prod", job=storm, investigation=_reported("high"), now=NOW)
    assert finding.alarm_reason == "Threshold Crossed: 3 datapoints were greater than 5.0"
    assert finding.alarm_time == "2026-09-29T14:05:00+00:00"


def test_failed_investigation_writes_empty_trail_fields() -> None:
    investigation = Investigation("incomplete", None, 0, "model-a", ())
    finding = build_finding(
        env="prod", job=_job(), investigation=investigation, now=NOW, error="RuntimeError"
    )
    assert finding.tools_used == []
    assert finding.tool_call_count == 0
    assert finding.sources_with_data == []
    assert finding.tool_trail == []
    assert finding.prior_finding_ids == []
    assert finding.alarm_time == "2026-09-29T14:05:00+00:00"


def test_triage_finding_writes_alarm_fields_and_no_trail() -> None:
    finding = build_triage_finding(
        env="prod",
        kind=FindingKind.DEFERRED,
        signal=_signal(),
        resource_key=FUNCTION_KEY,
        floor=Severity.MEDIUM,
        now=NOW,
        title="Deferred",
        summary="Over budget.",
    )
    item = to_item(finding)
    assert item["tools_used"] == []
    assert item["tool_call_count"] is None
    assert item["sources_with_data"] == []
    assert item["tool_trail"] == []
    assert item["prior_finding_ids"] == []
    assert item["alarm_reason"] == "Threshold Crossed: 3 datapoints were greater than 5.0"
    assert item["alarm_time"] == "2026-09-29T14:05:00+00:00"


def test_event_without_a_time_stores_null_alarm_time() -> None:
    event = alarm_event()
    event["time"] = ""
    event["detail"]["state"]["timestamp"] = None
    event["detail"]["state"]["reason"] = ""
    finding = build_triage_finding(
        env="prod",
        kind=FindingKind.DEFERRED,
        signal=SignalRef.for_alarm(AlarmStateChangeEvent.model_validate(event), Severity.MEDIUM),
        resource_key=FUNCTION_KEY,
        floor=Severity.MEDIUM,
        now=NOW,
        title="Deferred",
        summary="Over budget.",
    )
    assert finding.alarm_time is None
    assert finding.alarm_reason is None


@pytest.mark.parametrize(
    ("item", "reviewed"),
    [
        ({"status": "closed", "resolution": "confirmed", "outcome": "reported"}, True),
        ({"status": "closed", "resolution": "false_positive", "outcome": "reported"}, True),
        ({"status": "closed", "resolution": "confirmed"}, True),
        ({"status": "closed", "resolution": "confirmed", "outcome": "incomplete"}, False),
        ({"status": "closed", "resolution": "confirmed", "outcome": "triaged"}, False),
        ({"status": "closed", "resolution": "dismissed", "outcome": "incomplete"}, False),
        ({"status": "closed", "resolution": "dismissed", "outcome": "reported"}, False),
        ({"status": "closed", "resolution": "wrong", "outcome": "reported"}, False),
        ({"status": "acknowledged", "resolution": None, "outcome": "reported"}, False),
        ({"status": "open", "resolution": "confirmed", "outcome": "reported"}, False),
    ],
)
def test_is_reviewed(item: dict[str, Any], reviewed: bool) -> None:
    assert is_reviewed(item) is reviewed


def test_only_findings_carry_status_and_resource_key(tool_ctx: ToolContext) -> None:
    """The sparse by_status and by_resource indexes must hold finding# items only."""
    table = FakeTable()
    store_finding(
        table, build_finding(env="prod", job=_job(), investigation=_reported("high"), now=NOW)
    )
    store_finding(
        table,
        build_triage_finding(
            env="prod",
            kind=FindingKind.LINKED,
            signal=_signal(),
            resource_key=FUNCTION_KEY,
            floor=Severity.MEDIUM,
            now=NOW,
            title="Linked",
            summary="Linked to f-1.",
            finding_id="f-2",
            linked_to="f-1",
        ),
    )
    record_recurrence(table, "f-1", NOW)
    store_snapshot(table, "f-1", {"snapshot": "{}"}, NOW)
    record_useful_sources(
        table, FUNCTION_KEY, [{"tool": "query_logs", "input": {"log_group": "/a"}}], NOW
    )
    claim_keys(table, [FUNCTION_KEY, "AWS/SQS:QueueName=q"], "f-3", NOW)
    link_alarm(table, FUNCTION_KEY, "other-alarm", NOW)
    release_keys(table, [FUNCTION_KEY], "f-3", NOW)
    consume_hourly_budget(table, 10, NOW)
    consume_daily_budget(table, 50, NOW)
    add_daily_tokens(table, 42_000, NOW)
    consume_datadog_share(table, 6, NOW)
    consume_p1_overflow(table, 10, NOW)
    record_rate(table, 3, NOW)
    claim_storm(table, Storm("f-4", "f-1"), NOW)

    prefixes = {pk.split("#", 1)[0] for pk in table.items}
    assert prefixes == {"finding", "snap", "obs", "active", "budget", "rate", "storm"}
    for pk, item in table.items.items():
        if pk.startswith("finding#"):
            assert {"status", "resource_key"} <= set(item), pk
        else:
            assert not {"status", "resource_key"} & set(item), pk


def test_finding_records_the_tokens_the_run_used() -> None:
    investigation = Investigation(
        "incomplete", None, 4, "model-a", (), tokens_used=61_000, weighted_tokens=18_500
    )
    finding = build_finding(env="prod", job=_job(), investigation=investigation, now=NOW)
    assert finding.tokens_used == 61_000
    assert finding.weighted_tokens == 18_500
    item = to_item(finding)
    assert (item["tokens_used"], item["weighted_tokens"]) == (61_000, 18_500)


def test_triage_finding_used_no_tokens() -> None:
    finding = build_triage_finding(
        env="prod",
        kind=FindingKind.DEFERRED,
        signal=_signal(),
        resource_key=FUNCTION_KEY,
        floor=Severity.HIGH,
        now=NOW,
        title="Deferred",
        summary="Deferred.",
    )
    assert finding.tokens_used == 0
    assert finding.weighted_tokens == 0


def _closed(table: FakeTable, finding_id: str, closed_ago: timedelta | None, **fields: Any) -> None:
    table.items[f"finding#{finding_id}"] = {
        "pk": f"finding#{finding_id}",
        "finding_id": finding_id,
        "created_at": (NOW - timedelta(days=1)).isoformat(),
        "kind": "alarm",
        "outcome": "reported",
        "status": "closed",
        "alarm_arn": ALARM_ARN,
        "resource_key": FUNCTION_KEY,
        "resolved_at": None if closed_ago is None else (NOW - closed_ago).isoformat(),
        **fields,
    }


def _cooldown(table: FakeTable, alarm_arn: str = ALARM_ARN) -> dict[str, Any] | None:
    return closed_in_cooldown(
        table,
        FUNCTION_KEY,
        alarm_arn,
        NOW,
        alarm_cooldown=timedelta(minutes=120),
        resource_cooldown=timedelta(minutes=60),
        limit=50,
    )


@pytest.mark.parametrize(
    ("closed_ago", "alarm_arn", "inside"),
    [
        (timedelta(minutes=90), ALARM_ARN, True),
        (timedelta(minutes=121), ALARM_ARN, False),
        (timedelta(minutes=45), "arn:aws:cloudwatch:us-east-1:111122223333:alarm:other", True),
        (timedelta(minutes=90), "arn:aws:cloudwatch:us-east-1:111122223333:alarm:other", False),
        (timedelta(minutes=45), "", True),
        (timedelta(minutes=90), "", False),
    ],
    ids=[
        "same-alarm-inside",
        "same-alarm-outside",
        "same-resource-inside",
        "same-resource-outside",
        "no-arn-inside",
        "no-arn-outside",
    ],
)
def test_closed_in_cooldown_by_alarm_and_by_resource(
    closed_ago: timedelta, alarm_arn: str, inside: bool
) -> None:
    table = FakeTable()
    _closed(table, "f-closed", closed_ago)
    found = _cooldown(table, alarm_arn)
    assert (found is not None and found["finding_id"] == "f-closed") is inside


def test_cooldown_falls_back_to_created_at() -> None:
    table = FakeTable()
    _closed(table, "f-recent", None, created_at=(NOW - timedelta(minutes=30)).isoformat())
    _closed(table, "f-old", None)
    found = _cooldown(table)
    assert found is not None and found["finding_id"] == "f-recent"


@pytest.mark.parametrize(
    "fields",
    [
        {"status": "open"},
        {"status": "acknowledged"},
        {"kind": "deferred", "outcome": "triaged"},
        {"kind": "linked", "outcome": "triaged"},
        {"kind": "skipped", "outcome": "triaged"},
        {"resolved_at": "not a time", "created_at": "not a time either"},
    ],
    ids=["open", "acknowledged", "deferred", "linked", "skipped", "unparseable"],
)
def test_cooldown_counts_only_closed_investigations(fields: dict[str, Any]) -> None:
    table = FakeTable()
    _closed(table, "f-1", timedelta(minutes=5), **fields)
    assert _cooldown(table) is None


def test_cooldown_reads_naive_and_zulu_times_as_utc() -> None:
    table = FakeTable()
    closed = (NOW - timedelta(minutes=30)).replace(tzinfo=None)
    _closed(table, "f-naive", None, resolved_at=closed.isoformat())
    assert _cooldown(table) is not None
    table = FakeTable()
    _closed(table, "f-zulu", None, resolved_at=closed.isoformat() + "Z")
    assert _cooldown(table) is not None


def test_datadog_finding_records_the_monitor() -> None:
    work = datadog_job(finding_id="f-dd")
    finding = build_finding(env="prod", job=work, investigation=_reported("high"), now=NOW)
    assert finding.source == "datadog"
    assert finding.alarm_name == "checkout-api 5xx rate (service:checkout-api-prod)"
    assert finding.alarm_arn == "datadog:monitor/1234567/service:checkout-api-prod"
    assert finding.alarm_time == "2026-10-14T13:12:05+00:00"
    assert finding.resource_key == "AWS/ECS:ServiceName=checkout-api-prod"


def test_incomplete_datadog_finding_points_at_the_monitor() -> None:
    investigation = Investigation("incomplete", None, 2, "model-a", ())
    finding = build_finding(env="prod", job=datadog_job(), investigation=investigation, now=NOW)
    assert "Look at the monitor directly." in finding.summary
    assert finding.actions[0].text.startswith("Open the monitor checkout-api 5xx rate (id 1234567)")
