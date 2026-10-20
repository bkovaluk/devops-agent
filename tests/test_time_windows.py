"""Explicit and default windows on the time-based tools."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from devops_agent.agent import system_prompt
from devops_agent.tools import (
    MAX_WINDOW_DAYS,
    ToolContext,
    ToolError,
    metric_period,
    run_tool,
    time_window,
    window_view,
)
from evals.replay import normalized_input

ALARM_AT = datetime(2026, 9, 29, 14, 5, tzinfo=UTC)
HOUR = timedelta(hours=1)
SIX_HOURS = timedelta(hours=6)

METRIC = {"namespace": "AWS/Lambda", "metric_name": "Errors"}
LOGS = {"log_group": "/aws/lambda/f", "query": "fields @message"}

# Each time-based tool, a valid input without a window, and its longest window.
TIME_TOOLS: list[tuple[str, dict[str, Any], timedelta]] = [
    ("get_metric", METRIC, timedelta(hours=6)),
    ("query_logs", LOGS, timedelta(hours=3)),
    ("recent_changes", {}, timedelta(hours=3)),
    ("search_datadog_logs", {"service": "checkout-api"}, timedelta(hours=3)),
    ("search_datadog_logs", {}, timedelta(hours=3)),
    ("datadog_events", {"service": "checkout-api"}, timedelta(hours=6)),
    ("github_recent_changes", {"repo": "chat-lambda"}, timedelta(hours=168)),
    ("scheduled_jobs", {}, timedelta(hours=24)),
]


def _iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _recent(**delta: float) -> datetime:
    """A whole-second time this far before now."""
    return (datetime.now(UTC) - timedelta(**delta)).replace(microsecond=0)


@pytest.fixture()
def ctx(tool_ctx: ToolContext) -> ToolContext:
    tool_ctx.logs.responses.update(
        {
            "start_query": {"queryId": "q-1"},
            "get_query_results": {"status": "Complete", "results": []},
        }
    )
    return tool_ctx


def _logs_window(ctx: ToolContext) -> tuple[datetime, datetime]:
    [call] = [kwargs for op, kwargs in ctx.logs.calls if op == "start_query"]
    return (
        datetime.fromtimestamp(call["startTime"], UTC),
        datetime.fromtimestamp(call["endTime"], UTC),
    )


def _only_call(client: Any, operation: str) -> dict[str, Any]:
    [(called, kwargs)] = client.calls
    assert called == operation
    return dict(kwargs)


def test_default_window_ends_at_the_alarm_time() -> None:
    assert time_window(None, None, HOUR, SIX_HOURS, ALARM_AT) == (ALARM_AT - HOUR, ALARM_AT)


def test_default_window_ends_now_without_an_alarm_time_or_after_a_future_one() -> None:
    before = datetime.now(UTC)
    for alarm_time in (None, before + HOUR):
        start, end = time_window(None, None, HOUR, SIX_HOURS, alarm_time)
        assert before <= end <= datetime.now(UTC)
        assert end - start == HOUR


def test_naive_alarm_time_is_utc() -> None:
    naive = ALARM_AT.replace(tzinfo=None)
    assert time_window(None, None, HOUR, SIX_HOURS, naive) == (ALARM_AT - HOUR, ALARM_AT)


def test_only_start_reads_the_length_from_it() -> None:
    start = _recent(hours=5)
    assert time_window(start, None, HOUR, SIX_HOURS, ALARM_AT) == (start, start + HOUR)


def test_only_end_reads_the_length_before_it() -> None:
    end = _recent(hours=5)
    assert time_window(None, end, HOUR, SIX_HOURS, ALARM_AT) == (end - HOUR, end)


def test_start_and_end_are_read_as_given() -> None:
    start = _recent(days=13)
    end = start + timedelta(hours=2)
    assert time_window(start, end, HOUR, SIX_HOURS, ALARM_AT) == (start, end)


def test_an_end_in_the_future_is_cut_to_now() -> None:
    start = _recent(hours=1)
    before = datetime.now(UTC)
    _, end = time_window(start, before + HOUR, HOUR, SIX_HOURS, None)
    assert before <= end <= datetime.now(UTC)


def test_a_lone_start_near_now_ends_now() -> None:
    start = _recent(minutes=10)
    _, end = time_window(start, None, HOUR, SIX_HOURS, None)
    assert end <= datetime.now(UTC)


@pytest.mark.parametrize(
    ("start", "end"),
    [
        (_recent(days=MAX_WINDOW_DAYS, minutes=1), None),
        (None, _recent(days=MAX_WINDOW_DAYS, minutes=1)),
        (_recent(days=MAX_WINDOW_DAYS, minutes=1), _recent(days=MAX_WINDOW_DAYS - 1)),
        (None, _recent(days=MAX_WINDOW_DAYS, minutes=-30)),
    ],
)
def test_a_window_older_than_fourteen_days_is_refused(
    start: datetime | None, end: datetime | None
) -> None:
    with pytest.raises(ToolError, match="within the last 14 days"):
        time_window(start, end, HOUR, SIX_HOURS, None)


@pytest.mark.parametrize(
    ("start", "end"),
    [
        (_recent(hours=1), _recent(hours=2)),
        (_recent(hours=1), _recent(hours=1)),
        (datetime.now(UTC) + HOUR, None),
    ],
)
def test_end_must_follow_start_and_start_must_be_past(
    start: datetime | None, end: datetime | None
) -> None:
    with pytest.raises(ToolError, match="end must be after start"):
        time_window(start, end, HOUR, SIX_HOURS, None)


def test_a_window_longer_than_the_tool_allows_is_refused() -> None:
    start = _recent(hours=8)
    with pytest.raises(ToolError, match="at most 6 hours"):
        time_window(start, start + SIX_HOURS + timedelta(seconds=1), HOUR, SIX_HOURS, None)
    assert time_window(start, start + SIX_HOURS, HOUR, SIX_HOURS, None) == (
        start,
        start + SIX_HOURS,
    )


@pytest.mark.parametrize(("tool", "base", "longest"), TIME_TOOLS)
def test_each_tool_caps_its_window(
    ctx: ToolContext, tool: str, base: dict[str, Any], longest: timedelta
) -> None:
    end = _recent(hours=1)
    longest_input = {**base, "start": _iso(end - longest), "end": _iso(end)}
    assert run_tool(tool, longest_input, ctx).status == "success"

    too_long = {**base, "start": _iso(end - longest - timedelta(minutes=1)), "end": _iso(end)}
    result = run_tool(tool, too_long, ctx)
    assert result.status == "error"
    assert f"at most {longest // HOUR} hours" in result.content["error"]


@pytest.mark.parametrize(("tool", "base", "longest"), TIME_TOOLS)
def test_each_tool_echoes_the_window_it_read(
    ctx: ToolContext, tool: str, base: dict[str, Any], longest: timedelta
) -> None:
    start = _recent(days=3)
    end = start + timedelta(minutes=45)
    result = run_tool(tool, {**base, "start": _iso(start), "end": _iso(end)}, ctx)
    assert result.status == "success"
    assert result.content["window"] == {"start": _iso(start), "end": _iso(end)}


@pytest.mark.parametrize(("tool", "base", "longest"), TIME_TOOLS)
def test_each_tool_defaults_to_the_window_ending_at_the_alarm(
    ctx: ToolContext, tool: str, base: dict[str, Any], longest: timedelta
) -> None:
    result = run_tool(tool, base, dataclasses.replace(ctx, alarm_time=ALARM_AT))
    assert result.status == "success"
    assert result.content["window"]["end"] == _iso(ALARM_AT)


@pytest.mark.parametrize(("tool", "base", "longest"), TIME_TOOLS)
def test_each_tool_refuses_a_window_older_than_fourteen_days(
    ctx: ToolContext, tool: str, base: dict[str, Any], longest: timedelta
) -> None:
    result = run_tool(tool, {**base, "start": _iso(_recent(days=15))}, ctx)
    assert result.status == "error"
    assert "within the last 14 days" in result.content["error"]
    for client in (ctx.cloudwatch, ctx.logs, ctx.cloudtrail, ctx.datadog, ctx.github):
        assert client.calls == []


def test_query_logs_default_window_ends_at_the_alarm(ctx: ToolContext) -> None:
    run_tool("query_logs", LOGS, dataclasses.replace(ctx, alarm_time=ALARM_AT))
    assert _logs_window(ctx) == (ALARM_AT - HOUR, ALARM_AT)


def test_get_metric_default_window_ends_at_the_alarm(ctx: ToolContext) -> None:
    alarm_ctx = dataclasses.replace(ctx, alarm_time=ALARM_AT)
    run_tool("get_metric", {**METRIC, "minutes": 120}, alarm_ctx)
    call = _only_call(ctx.cloudwatch, "get_metric_data")
    assert (call["StartTime"], call["EndTime"]) == (ALARM_AT - timedelta(hours=2), ALARM_AT)


def test_recent_changes_default_window_ends_at_the_alarm(ctx: ToolContext) -> None:
    run_tool("recent_changes", {"minutes": 30}, dataclasses.replace(ctx, alarm_time=ALARM_AT))
    call = _only_call(ctx.cloudtrail, "lookup_events")
    assert (call["StartTime"], call["EndTime"]) == (ALARM_AT - timedelta(minutes=30), ALARM_AT)


def test_minutes_set_the_length_from_a_lone_start(ctx: ToolContext) -> None:
    start = _recent(days=2)
    run_tool("query_logs", {**LOGS, "start": _iso(start), "minutes": 30}, ctx)
    assert _logs_window(ctx) == (start, start + timedelta(minutes=30))


def test_hours_set_the_length_before_a_lone_end(ctx: ToolContext) -> None:
    end = _recent(days=2)
    tool_input = {"repo": "chat-lambda", "end": _iso(end), "hours": 6}
    result = run_tool("github_recent_changes", tool_input, ctx)
    assert result.content["window"] == {"start": _iso(end - SIX_HOURS), "end": _iso(end)}


def test_start_and_end_win_over_minutes(ctx: ToolContext) -> None:
    start = _recent(days=1)
    end = start + timedelta(minutes=90)
    tool_input = {**LOGS, "start": _iso(start), "end": _iso(end), "minutes": 10}
    run_tool("query_logs", tool_input, dataclasses.replace(ctx, alarm_time=ALARM_AT))
    assert _logs_window(ctx) == (start, end)


def test_offsets_and_naive_times_are_read_as_utc(ctx: ToolContext) -> None:
    start = _recent(days=1)
    offset = (start - timedelta(hours=4)).replace(tzinfo=None).isoformat() + "-04:00"
    naive = (start + HOUR).replace(tzinfo=None).isoformat()
    run_tool("query_logs", {**LOGS, "start": offset, "end": naive}, ctx)
    assert _logs_window(ctx) == (start, start + HOUR)


@pytest.mark.parametrize(
    ("requested", "length", "period"),
    [
        (60, timedelta(hours=3), 60),
        (60, timedelta(hours=6), 300),
        (600, HOUR, 600),
        (120, timedelta(hours=6), 120),
    ],
)
def test_metric_period_keeps_the_series_within_the_point_cap(
    requested: int, length: timedelta, period: int
) -> None:
    end = datetime.now(UTC)
    assert metric_period(requested, end - length, end) == period


def test_get_metric_asks_for_the_period_it_reports(ctx: ToolContext) -> None:
    end = _recent(days=1)
    ctx.cloudwatch.responses["get_metric_data"] = {
        "MetricDataResults": [{"Id": "m1", "StatusCode": "Complete"}]
    }
    tool_input = {**METRIC, "start": _iso(end - SIX_HOURS), "end": _iso(end)}
    body = run_tool("get_metric", tool_input, ctx).content
    call = _only_call(ctx.cloudwatch, "get_metric_data")
    assert call["MetricDataQueries"][0]["MetricStat"]["Period"] == 300
    assert body["period_seconds"] == 300


def test_window_view_is_whole_seconds_in_utc() -> None:
    start = datetime(2026, 10, 2, 3, 10, 0, 123456, tzinfo=UTC)
    assert window_view(start, start + HOUR) == {
        "start": "2026-10-02T03:10:00Z",
        "end": "2026-10-02T04:10:00Z",
    }


def test_replay_normalizes_absent_and_explicit_windows_alike() -> None:
    absent = normalized_input("query_logs", LOGS)
    assert absent == normalized_input("query_logs", {**LOGS, "start": None, "end": None})
    zulu = normalized_input("query_logs", {**LOGS, "start": "2026-10-02T03:10:00Z"})
    for same in ("2026-10-02T03:10:00+00:00", "2026-10-02T03:10:00", "2026-10-01T23:10:00-04:00"):
        assert normalized_input("query_logs", {**LOGS, "start": same}) == zulu
    assert zulu != absent
    assert zulu != normalized_input("query_logs", {**LOGS, "start": "2026-10-02T03:11:00Z"})


def test_prompt_asks_to_follow_the_chain_with_explicit_windows() -> None:
    prompt = system_prompt(set())
    assert "Follow the chain." in prompt
    assert "dead-letter queue" in prompt
    assert "explicit start and end" in prompt
    assert "within the last 14 days" in prompt
    assert "Only conclude that the cause is not shown after trying." in prompt
    assert "github_get_file" not in prompt


def test_prompt_follows_the_chain_into_code_when_github_is_offered() -> None:
    prompt = system_prompt({"github_list_repos"})
    chain = prompt[prompt.index("Follow the chain.") :]
    assert "find the code with github_search_code and read it with github_get_file" in chain
