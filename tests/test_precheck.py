"""Precomputed incident context: sections, failure tolerance, time budget, size cap."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from devops_agent import notes as notes_module
from devops_agent.notes import (
    EXAMPLE_NOTES_FILE,
    NOTES_FILE_ENV,
    ServiceNote,
    notes_path,
    read_notes,
)
from devops_agent.precheck import (
    MAX_CONTEXT_CHARS,
    MAX_NOTE_CHARS,
    MAX_NOTE_ENTRIES,
    MAX_PATTERN_CHARS,
    PATTERN_QUERY,
    PRECHECK_BUDGET_SECONDS,
    TRUNCATED_MARKER,
    IncidentContext,
    build_context,
)
from devops_agent.tools import LogsQueryInput, ToolContext
from tests.conftest import ALARM_ARN, ALARM_NAME, FUNCTION_KEY, client_error, datadog_job, job

NOW = datetime.now(UTC)
FUNCTION = "payment-api-prod"
LOG_GROUP = f"/aws/lambda/{FUNCTION}"
LAMBDA_DIMENSIONS = [{"Name": "FunctionName", "Value": FUNCTION}]
ORDERS_DIMENSIONS = [{"Name": "FunctionName", "Value": "orders-prod"}]
DB_DIMENSIONS = [{"Name": "DBClusterIdentifier", "Value": "db"}]


def _alarm_config(**overrides: Any) -> dict[str, Any]:
    return {
        "AlarmName": ALARM_NAME,
        "AlarmArn": ALARM_ARN,
        "StateValue": "ALARM",
        "StateReason": "Threshold Crossed",
        "Namespace": "AWS/Lambda",
        "MetricName": "Errors",
        "Dimensions": LAMBDA_DIMENSIONS,
        "Statistic": "Sum",
        "Period": 60,
        **overrides,
    }


def _firing(name: str, dimensions: list[dict[str, str]]) -> dict[str, Any]:
    return _alarm_config(
        AlarmName=name, Dimensions=dimensions, StateReason=f"{name} fired", MetricName="Throttles"
    )


FIRING = [
    _alarm_config(),
    _firing("payment-throttles", LAMBDA_DIMENSIONS),
    _firing("orders-errors", ORDERS_DIMENSIONS),
]


def _describe_alarms(
    config: dict[str, Any], firing: list[dict[str, Any]] = FIRING
) -> Callable[..., dict[str, Any]]:
    def answer(**kwargs: Any) -> dict[str, Any]:
        if kwargs.get("StateValue") == "ALARM":
            return {"MetricAlarms": firing}
        if config.get("AlarmRule"):
            return {"CompositeAlarms": [config]}
        return {"MetricAlarms": [config]}

    return answer


def _metric_data(**kwargs: Any) -> dict[str, Any]:
    points = [(NOW - timedelta(minutes=10 * n), float(n)) for n in (1, 2, 3)]
    points += [(NOW - timedelta(days=days, minutes=10), 10.0 * days) for days in range(1, 8)]
    points.sort(reverse=True)
    return {
        "MetricDataResults": [
            {
                "StatusCode": "Complete",
                "Timestamps": [ts for ts, _ in points],
                "Values": [value for _, value in points],
            }
        ]
    }


PATTERNS = {
    "status": "Complete",
    "results": [
        [
            {"field": "@pattern", "value": "ERROR <*> timeout after <*> ms"},
            {"field": "@sampleCount", "value": "42"},
            {"field": "@ptr", "value": "p"},
        ]
    ],
}


@pytest.fixture()
def ctx(tool_ctx: ToolContext) -> ToolContext:
    tool_ctx.cloudwatch.responses.update(
        {
            "describe_alarms": _describe_alarms(_alarm_config()),
            "list_tags_for_resource": {"Tags": [{"Key": "Severity", "Value": "high"}]},
            "describe_alarm_history": {
                "AlarmHistoryItems": [
                    {
                        "Timestamp": NOW - timedelta(hours=1),
                        "HistoryItemType": "StateUpdate",
                        "HistorySummary": "Alarm updated from OK to ALARM",
                    },
                    {
                        "Timestamp": NOW - timedelta(hours=2),
                        "HistoryItemType": "ConfigurationUpdate",
                        "HistorySummary": "Alarm updated",
                    },
                    {
                        "Timestamp": NOW - timedelta(hours=30),
                        "HistoryItemType": "StateUpdate",
                        "HistorySummary": "Alarm updated from ALARM to OK",
                    },
                ]
            },
            "get_metric_data": _metric_data,
        }
    )
    tool_ctx.logs.responses.update(
        {
            "describe_log_groups": {"logGroups": [{"logGroupName": LOG_GROUP}]},
            "start_query": {"queryId": "q-1"},
            "get_query_results": PATTERNS,
        }
    )
    tool_ctx.cloudtrail.responses["lookup_events"] = {
        "Events": [{"EventTime": NOW, "EventName": "UpdateFunctionCode", "EventSource": "lambda"}]
    }
    return tool_ctx


def _database_alarm(ctx: ToolContext, groups: int) -> None:
    ctx.logs.responses["describe_log_groups"] = {
        "logGroups": [{"logGroupName": f"/aws/rds/cluster/db/{n}"} for n in range(groups)]
    }
    ctx.cloudwatch.responses["describe_alarms"] = _describe_alarms(
        _alarm_config(Namespace="AWS/RDS", Dimensions=DB_DIMENSIONS)
    )


PAST = [{"tool": "query_logs", "input": {"log_group": LOG_GROUP}, "at": "2026-09-01"}]


def _build(
    ctx: ToolContext,
    keys: tuple[str, ...] = (FUNCTION_KEY,),
    past: Callable[[], list[dict[str, Any]]] = lambda: PAST,
    clock: Callable[[], float] = lambda: 0.0,
) -> IncidentContext:
    return build_context(ctx, job(keys=keys), NOW, past, clock)


def _section(context: IncidentContext, name: str) -> Any:
    body = context.text.split(f"## {name}\n", 1)[1].split("\n\n## ", 1)[0]
    return json.loads(body)


def test_bundle_holds_every_section_in_order(ctx: ToolContext) -> None:
    context = _build(ctx)
    names = [line[3:] for line in context.text.splitlines() if line.startswith("## ")]
    assert names == [
        "alarm",
        "metric",
        "log_sources",
        "log_patterns",
        "changes",
        "siblings",
        "database_events",
        "instance",
        "service_notes",
        "sources_last_time",
    ]
    assert context.summary.sections == {
        "alarm": "available",
        "metric": "available",
        "log_sources": "available",
        "log_patterns": "available",
        "changes": "available",
        "siblings": "available",
        "database_events": "not_applicable",
        "instance": "not_applicable",
        "service_notes": "not_applicable",
        "sources_last_time": "available",
    }
    assert context.summary.counts == {
        "alarm": 1,
        "metric": 3,
        "log_sources": 1,
        "log_patterns": 1,
        "changes": 1,
        "siblings": 1,
        "sources_last_time": 1,
    }
    assert context.summary.chars == len(context.text)
    assert context.summary.truncated is False
    assert _section(context, "sources_last_time") == PAST


def test_alarm_section_keeps_the_last_day_of_state_changes(ctx: ToolContext) -> None:
    alarm = _section(_build(ctx), "alarm")
    assert alarm["alarm"]["state_reason"] == "Threshold Crossed"
    assert alarm["tags"] == {"Severity": "high"}
    assert [item["summary"] for item in alarm["history"]] == ["Alarm updated from OK to ALARM"]


def test_metric_section_compares_now_with_the_seven_day_baseline(ctx: ToolContext) -> None:
    metric = _section(_build(ctx), "metric")
    assert metric["now"] == {"min": 1.0, "max": 3.0, "p50": 2.0, "last": 1.0}
    assert metric["baseline"] == {"min": 40.0, "max": 40.0, "p50": 40.0, "last": 40.0}
    assert metric["baseline_days_with_data"] == 7
    assert metric["stat"] == "Sum"
    assert metric["period_seconds"] == 300
    [call] = [kwargs for op, kwargs in ctx.cloudwatch.calls if op == "get_metric_data"]
    assert call["EndTime"] - call["StartTime"] == timedelta(days=7, hours=3)
    assert call["MetricDataQueries"][0]["MetricStat"]["Period"] == 300
    assert call["MaxDatapoints"] == 7 * 24 * 12 + 36 + 1


@pytest.mark.parametrize(
    "config",
    [
        {"AlarmName": ALARM_NAME, "AlarmArn": ALARM_ARN, "AlarmRule": "ALARM(a)"},
        {
            "AlarmName": ALARM_NAME,
            "AlarmArn": ALARM_ARN,
            "Metrics": [{"Id": "e1", "Expression": "m1 / m2"}],
        },
    ],
)
def test_metric_section_is_skipped_for_composite_and_math(
    ctx: ToolContext, config: dict[str, Any]
) -> None:
    ctx.cloudwatch.responses["describe_alarms"] = _describe_alarms(config)
    context = _build(ctx)
    assert context.summary.sections["metric"] == "not_applicable"
    assert _section(context, "metric").startswith("not applicable: composite or metric-math")
    assert "get_metric_data" not in ctx.cloudwatch.operations()


def test_log_patterns_run_the_pattern_query_over_the_alarm_window(ctx: ToolContext) -> None:
    patterns = _section(_build(ctx), "log_patterns")
    [group] = patterns["groups"]
    assert group == {
        "log_group": LOG_GROUP,
        "status": "Complete",
        "patterns": [{"pattern": "ERROR <*> timeout after <*> ms", "count": "42"}],
    }
    [call] = [kwargs for op, kwargs in ctx.logs.calls if op == "start_query"]
    assert call["queryString"] == PATTERN_QUERY
    assert call["logGroupName"] == LOG_GROUP
    assert call["endTime"] - call["startTime"] == 3600


def test_log_patterns_window_starts_fifteen_minutes_before_the_alarm(ctx: ToolContext) -> None:
    work = job()
    work.signal.observed_at = (NOW - timedelta(minutes=5)).isoformat()
    build_context(ctx, work, NOW, lambda: [], lambda: 0.0)
    [call] = [kwargs for op, kwargs in ctx.logs.calls if op == "start_query"]
    assert 19 * 60 <= call["endTime"] - call["startTime"] <= 21 * 60


def test_log_patterns_cover_at_most_three_groups(ctx: ToolContext) -> None:
    _database_alarm(ctx, groups=5)
    patterns = _section(_build(ctx), "log_patterns")
    assert [group["log_group"] for group in patterns["groups"]] == [
        "/aws/rds/cluster/db/0",
        "/aws/rds/cluster/db/1",
        "/aws/rds/cluster/db/2",
    ]


def test_pattern_lines_are_redacted_then_cut(ctx: ToolContext) -> None:
    line = "login failed password=hunter2 for AKIA" + "ABCDEFGHIJKLMNOP " + "x" * 600
    ctx.logs.responses["get_query_results"] = {
        "status": "Complete",
        "results": [
            [{"field": "@pattern", "value": line}, {"field": "@sampleCount", "value": "3"}]
        ],
    }
    context = _build(ctx)
    [pattern] = _section(context, "log_patterns")["groups"][0]["patterns"]
    assert "hunter2" not in context.text
    assert "AKIA" not in context.text
    assert pattern["pattern"].startswith("login failed password=[redacted] for [redacted] x")
    assert len(pattern["pattern"]) == MAX_PATTERN_CHARS


def test_log_patterns_need_log_sources(ctx: ToolContext) -> None:
    ctx.logs.responses["describe_log_groups"] = {"logGroups": []}
    context = _build(ctx)
    assert context.summary.sections["log_patterns"] == "not_applicable"
    assert "start_query" not in ctx.logs.operations()


def test_one_failing_pattern_query_keeps_the_others(ctx: ToolContext) -> None:
    _database_alarm(ctx, groups=2)
    answers: list[Any] = [client_error("LimitExceededException"), {"queryId": "q-2"}]

    def start_query(**_: Any) -> dict[str, Any]:
        answer = answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        result: dict[str, Any] = answer
        return result

    ctx.logs.responses["start_query"] = start_query
    groups = _section(_build(ctx), "log_patterns")["groups"]
    assert groups[0]["patterns"] == "unavailable: LimitExceededException"
    assert len(groups[1]["patterns"]) == 1


def test_changes_cover_six_hours_and_twenty_events(ctx: ToolContext) -> None:
    changes = _section(_build(ctx), "changes")
    assert changes["window_minutes"] == 360
    assert changes["events"][0]["event_name"] == "UpdateFunctionCode"
    [(_, call)] = ctx.cloudtrail.calls
    assert call["MaxResults"] == 20
    assert call["EndTime"] - call["StartTime"] == timedelta(hours=6)


def test_siblings_share_a_job_key_and_leave_out_the_job_alarm(ctx: ToolContext) -> None:
    siblings = _section(_build(ctx), "siblings")
    assert siblings["keys"] == [FUNCTION_KEY]
    assert siblings["alarms"] == [
        {
            "name": "payment-throttles",
            "state_reason": "payment-throttles fired",
            "updated": None,
            "resource_key": FUNCTION_KEY,
        }
    ]
    assert siblings["truncated"] is False


def test_siblings_match_any_job_key_and_are_capped(ctx: ToolContext) -> None:
    orders_key = "AWS/Lambda:FunctionName=orders-prod"
    firing = [_firing(f"orders-{n}", ORDERS_DIMENSIONS) for n in range(12)]
    ctx.cloudwatch.responses["describe_alarms"] = _describe_alarms(_alarm_config(), firing)
    siblings = _section(_build(ctx, keys=(FUNCTION_KEY, orders_key)), "siblings")
    assert len(siblings["alarms"]) == 10
    assert siblings["truncated"] is True
    assert {alarm["resource_key"] for alarm in siblings["alarms"]} == {orders_key}


@pytest.mark.parametrize(
    ("key", "source_type"),
    [
        ("AWS/RDS:DBClusterIdentifier=orders-db", "db-cluster"),
        ("AWS/DocDB:DBInstanceIdentifier=orders-db", "db-instance"),
    ],
)
def test_database_events_for_an_rds_or_docdb_key(
    ctx: ToolContext, key: str, source_type: str
) -> None:
    ctx.rds.responses["describe_events"] = {
        "Events": [{"Date": NOW, "Message": "Failover started", "EventCategories": ["failover"]}]
    }
    context = _build(ctx, keys=(key,))
    events = _section(context, "database_events")
    assert events["identifier"] == "orders-db"
    assert events["items"][0]["message"] == "Failover started"
    [(_, call)] = ctx.rds.calls
    assert call["SourceIdentifier"] == "orders-db"
    assert call["SourceType"] == source_type
    assert call["EndTime"] - call["StartTime"] == timedelta(hours=24)
    assert context.summary.counts["database_events"] == 1


def test_database_events_do_not_apply_to_other_keys(ctx: ToolContext) -> None:
    context = _build(ctx)
    assert _section(context, "database_events").startswith("not applicable:")
    assert ctx.rds.calls == []


@pytest.mark.parametrize(
    ("client", "operation", "failed"),
    [
        ("cloudwatch", "list_tags_for_resource", {"alarm", "metric"}),
        ("cloudwatch", "get_metric_data", {"metric"}),
        ("logs", "describe_log_groups", {"log_sources"}),
        ("cloudtrail", "lookup_events", {"changes"}),
    ],
)
def test_each_section_fails_on_its_own(
    ctx: ToolContext, client: str, operation: str, failed: set[str]
) -> None:
    getattr(ctx, client).responses[operation] = client_error("AccessDeniedException")
    context = _build(ctx)
    for name, status in context.summary.sections.items():
        if name in failed:
            assert status == "unavailable", name
        else:
            assert status in ("available", "not_applicable"), name
    assert "unavailable: AccessDeniedException" in context.text


def test_metric_without_the_alarm_config_is_unavailable(ctx: ToolContext) -> None:
    ctx.cloudwatch.responses["list_tags_for_resource"] = client_error("AccessDeniedException")
    context = _build(ctx)
    assert _section(context, "metric") == "unavailable: alarm config not read"


def test_memory_keeps_only_calls_of_the_tools_this_run_offers(ctx: ToolContext) -> None:
    datadog = {"tool": "search_datadog_logs", "input": {"service": "checkout-api"}, "at": "x"}
    gone = {"tool": "describe_widget", "input": {"name": "w"}, "at": "2026-09-02"}
    entries = [*PAST, datadog, gone, {"input": {}}]
    context = _build(ctx, past=lambda: entries)
    assert _section(context, "sources_last_time") == [*PAST, datadog]
    assert context.summary.counts["sources_last_time"] == 2
    bare = dataclasses.replace(ctx, datadog=None)
    assert _section(_build(bare, past=lambda: entries), "sources_last_time") == PAST


def test_failed_sibling_and_memory_reads_are_unavailable(ctx: ToolContext) -> None:
    def describe_alarms(**kwargs: Any) -> dict[str, Any]:
        if kwargs.get("StateValue"):
            raise client_error("ThrottlingException")
        return {"MetricAlarms": [_alarm_config()]}

    def past() -> list[dict[str, Any]]:
        raise client_error("ProvisionedThroughputExceededException")

    ctx.cloudwatch.responses["describe_alarms"] = describe_alarms
    context = _build(ctx, past=past)
    assert _section(context, "siblings") == "unavailable: ThrottlingException"
    assert _section(context, "sources_last_time") == (
        "unavailable: ProvisionedThroughputExceededException"
    )
    assert context.summary.sections["alarm"] == "available"


def test_time_budget_skips_the_remaining_sections(ctx: ToolContext) -> None:
    ticks = iter([0.0, 0.0, 10.0, 30.0, PRECHECK_BUDGET_SECONDS])
    context = _build(ctx, clock=lambda: next(ticks, PRECHECK_BUDGET_SECONDS + 1))
    assert context.summary.sections == {
        "alarm": "available",
        "metric": "available",
        "log_sources": "available",
        "log_patterns": "skipped",
        "changes": "skipped",
        "siblings": "skipped",
        "database_events": "skipped",
        "instance": "skipped",
        "service_notes": "skipped",
        "sources_last_time": "skipped",
    }
    assert _section(context, "changes") == "skipped: precheck time budget spent"
    assert ctx.cloudtrail.calls == []
    assert "start_query" not in ctx.logs.operations()


def test_time_budget_is_checked_between_pattern_queries(ctx: ToolContext) -> None:
    _database_alarm(ctx, groups=2)
    ticks = iter([0.0] * 6)
    context = _build(ctx, clock=lambda: next(ticks, PRECHECK_BUDGET_SECONDS))
    groups = _section(context, "log_patterns")["groups"]
    assert len(groups[0]["patterns"]) == 1
    assert groups[1]["patterns"] == "skipped: time budget spent"
    assert ctx.logs.operations().count("start_query") == 1


def test_bundle_is_capped(ctx: ToolContext) -> None:
    ctx.cloudtrail.responses["lookup_events"] = {
        "Events": [
            {"EventTime": NOW, "EventName": "PutObject" + "x" * 900, "EventSource": "s3"}
            for _ in range(20)
        ]
    }
    context = _build(ctx)
    assert len(context.text) == MAX_CONTEXT_CHARS
    assert context.text.endswith(TRUNCATED_MARKER)
    assert context.summary.truncated is True
    assert context.summary.chars == MAX_CONTEXT_CHARS


def test_pattern_query_passes_the_model_facing_validator() -> None:
    assert LogsQueryInput(log_group=LOG_GROUP, query=PATTERN_QUERY).query == PATTERN_QUERY


NODE_ID = "i-0123456789abcdef0"
NODE_KEY = f"AWS/EC2:InstanceId={NODE_ID}"


def _node(tags: list[dict[str, str]]) -> dict[str, Any]:
    instance = {
        "InstanceId": NODE_ID,
        "InstanceType": "t3.medium",
        "State": {"Name": "running"},
        "LaunchTime": NOW,
        "Tags": tags,
    }
    return {"Reservations": [{"Instances": [instance]}]}


def test_instance_section_names_the_eks_cluster_and_node_group(ctx: ToolContext) -> None:
    ctx.ec2.responses["describe_instances"] = _node(
        [
            {"Key": "eks:cluster-name", "Value": "acme-prod"},
            {"Key": "eks:nodegroup-name", "Value": "main-br"},
            {"Key": "aws:autoscaling:groupName", "Value": "eks-main-br-1234"},
            {"Key": "owner", "Value": "someone"},
        ]
    )
    context = _build(ctx, keys=(NODE_KEY,))
    instance = _section(context, "instance")
    assert instance == {
        "instance_id": NODE_ID,
        "instance_type": "t3.medium",
        "state": "running",
        "launch_time": NOW.isoformat(),
        "asg": "eks-main-br-1234",
        "eks_cluster": "acme-prod",
        "eks_nodegroup": "main-br",
    }
    assert ctx.ec2.calls == [("describe_instances", {"InstanceIds": [NODE_ID]})]
    assert context.summary.sections["instance"] == "available"
    assert context.summary.counts["instance"] == 1


def test_instance_section_of_a_plain_instance_has_no_eks_fields(ctx: ToolContext) -> None:
    ctx.ec2.responses["describe_instances"] = _node([{"Key": "Name", "Value": "bastion"}])
    instance = _section(_build(ctx, keys=(NODE_KEY,)), "instance")
    assert instance["name"] == "bastion"
    assert not {"eks_cluster", "eks_nodegroup"} & set(instance)


@pytest.mark.parametrize(
    ("failure", "text"),
    [
        (
            client_error("InvalidInstanceID.NotFound"),
            f"unavailable: instance '{NODE_ID}' not found",
        ),
        ({"Reservations": []}, f"unavailable: instance '{NODE_ID}' not found"),
        (client_error("UnauthorizedOperation"), "unavailable: UnauthorizedOperation"),
    ],
)
def test_instance_section_records_a_failed_read(ctx: ToolContext, failure: Any, text: str) -> None:
    ctx.ec2.responses["describe_instances"] = failure
    context = _build(ctx, keys=(NODE_KEY,))
    assert _section(context, "instance") == text
    assert context.summary.sections["instance"] == "unavailable"


def test_instance_section_does_not_apply_to_other_keys(ctx: ToolContext) -> None:
    context = _build(ctx)
    assert _section(context, "instance").startswith("not applicable:")
    assert ctx.ec2.calls == []


def _note(service: str, *match: str, notes: tuple[str, ...] = ("a fact",)) -> ServiceNote:
    return ServiceNote(service=service, match=list(match), notes=list(notes))


def _notes_section(
    ctx: ToolContext, notes: list[ServiceNote], *names: str, keys: tuple[str, ...] = (FUNCTION_KEY,)
) -> tuple[IncidentContext, Any]:
    context = build_context(ctx, job(*names, keys=keys), NOW, lambda: PAST, notes=notes)
    return context, _section(context, "service_notes")


def test_service_notes_match_the_alarm_name(ctx: ToolContext) -> None:
    notes = [_note("payment", "payment-api-errors", notes=("Payment runs on Lambda.",))]
    context, section = _notes_section(ctx, notes)
    assert section == {
        "entries": [{"service": "payment", "notes": ["Payment runs on Lambda."]}],
        "truncated": False,
    }
    assert context.summary.sections["service_notes"] == "available"
    assert context.summary.counts["service_notes"] == 1


def test_service_notes_match_the_resource_key(ctx: ToolContext) -> None:
    key = "AWS/ES:DomainName=catalog-prod"
    _, section = _notes_section(ctx, [_note("catalog", "catalog")], keys=(key,))
    assert [entry["service"] for entry in section["entries"]] == ["catalog"]


def test_service_notes_match_any_alarm_of_a_storm(ctx: ToolContext) -> None:
    notes = [_note("orders", "orders-")]
    _, section = _notes_section(ctx, notes, ALARM_NAME, "orders-throttles-prod")
    assert [entry["service"] for entry in section["entries"]] == ["orders"]


def test_service_notes_match_case_insensitively(ctx: ToolContext) -> None:
    _, section = _notes_section(ctx, [_note("acme", "acme-")], "Acme-EC2-CPU-i-0abc")
    assert [entry["service"] for entry in section["entries"]] == ["acme"]


def test_service_notes_do_not_apply_without_a_match(ctx: ToolContext) -> None:
    context, section = _notes_section(ctx, [_note("acme", "acme-")])
    assert context.summary.sections["service_notes"] == "not_applicable"
    assert section.startswith("not applicable:")
    assert "service_notes" not in context.summary.counts


def test_service_notes_keep_at_most_three_entries(ctx: ToolContext) -> None:
    notes = [_note(f"s{n}", "payment") for n in range(MAX_NOTE_ENTRIES + 2)]
    _, section = _notes_section(ctx, notes)
    assert [entry["service"] for entry in section["entries"]] == ["s0", "s1", "s2"]
    assert section["truncated"] is True


def test_service_notes_stop_at_the_char_cap(ctx: ToolContext) -> None:
    line = "x" * 400
    notes = [_note("a", "payment", notes=(line, line)), _note("b", "payment", notes=(line,))]
    _, section = _notes_section(ctx, notes)
    assert section["entries"] == [{"service": "a", "notes": [line, line]}]
    assert sum(len(text) for entry in section["entries"] for text in entry["notes"]) <= (
        MAX_NOTE_CHARS
    )
    assert section["truncated"] is True


def test_example_service_notes_load_and_are_complete() -> None:
    path = Path(notes_module.__file__).with_name(EXAMPLE_NOTES_FILE)
    notes = read_notes(path)
    assert {note.service for note in notes} == {"orders-api", "acme-reports"}
    for note in notes:
        assert note.match, note.service
        assert all(part and part == part.lower() for part in note.match), note.service
        assert 1 <= len(note.notes) <= 5, note.service
        assert all(line.strip() for line in note.notes), note.service


def test_missing_service_notes_file_means_no_notes(tmp_path: Path) -> None:
    assert read_notes(tmp_path / "service_notes.toml") == ()


def test_service_notes_file_comes_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "notes.toml"
    monkeypatch.setenv(NOTES_FILE_ENV, str(path))
    assert notes_path() == path
    monkeypatch.delenv(NOTES_FILE_ENV)
    assert notes_path().name == "service_notes.toml"


def test_datadog_signal_skips_the_alarm_sections(ctx: ToolContext) -> None:
    context = build_context(ctx, datadog_job(), NOW, lambda: PAST, lambda: 0.0)
    sections = context.summary.sections
    for name in ("alarm", "metric", "log_sources", "log_patterns"):
        assert sections[name] == "not_applicable", name
    assert "Datadog monitor" in _section(context, "alarm")
    assert "Datadog tools" in _section(context, "log_sources")
    assert sections["changes"] == "available"
    assert sections["siblings"] == "available"
    assert sections["sources_last_time"] == "available"
    operations = ctx.cloudwatch.operations()
    assert "describe_alarm_history" not in operations
    assert ctx.logs.calls == []
