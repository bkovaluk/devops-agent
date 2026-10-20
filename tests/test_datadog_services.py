"""search_datadog_logs without service: the services ranked by error and warn logs.

Query building, bounds, bucket parsing, offering, HTTP failures, keys.
"""

from __future__ import annotations

import dataclasses
import io
import json
import logging
import urllib.error
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from devops_agent import datadog as datadog_module
from devops_agent.datadog import REQUEST_TIMEOUT_SECONDS, DatadogClient
from devops_agent.tools import (
    MAX_DATADOG_SERVICES,
    SEARCH_DATADOG_LOGS,
    DatadogLogsInput,
    ToolContext,
    datadog_logs_query,
    offered_tools,
    run_tool,
)

API_KEY = "ddapi0123456789abcdef0123456789ab"
APP_KEY = "ddapp0123456789abcdef0123456789abcdef0123"
ALARM_AT = datetime(2026, 9, 29, 14, 5, tzinfo=UTC)
AGGREGATE_URL = "https://api.datadoghq.com/api/v2/logs/analytics/aggregate"


def _list(tool_ctx: ToolContext, **tool_input: Any) -> Any:
    return run_tool(SEARCH_DATADOG_LOGS, tool_input, tool_ctx)


def _body(tool_ctx: ToolContext) -> dict[str, Any]:
    [(operation, kwargs)] = tool_ctx.datadog.calls
    assert operation == "aggregate_logs"
    body: dict[str, Any] = kwargs["body"]
    return body


def _bucket(service: Any, status: Any, count: Any) -> dict[str, Any]:
    return {"by": {"service": service, "status": status}, "computes": {"c0": count}}


def _buckets(*buckets: Any, after: str | None = None) -> dict[str, Any]:
    page = {"after": after} if after else {}
    return {"data": {"buckets": list(buckets)}, "meta": {"status": "done", "page": page}}


@pytest.mark.parametrize(
    ("tool_input", "query"),
    [
        ({}, "status:(error OR warn)"),
        ({"env": "prod"}, "env:prod status:(error OR warn)"),
        ({"name": "checkout"}, "service:*checkout* status:(error OR warn)"),
        ({"name": "Checkout-API"}, "service:*checkout-api* status:(error OR warn)"),
        ({"env": "prod", "name": "api"}, "service:*api* env:prod status:(error OR warn)"),
        (
            {"name": "api", "text": '"timed out"'},
            'service:*api* status:(error OR warn) "timed out"',
        ),
    ],
)
def test_query_is_built_from_the_fields(tool_input: dict[str, Any], query: str) -> None:
    assert datadog_logs_query(DatadogLogsInput.model_validate(tool_input)) == query


@pytest.mark.parametrize(
    "name",
    [
        "service:other",
        "checkout*",
        "cort?x",
        "(checkout)",
        "checkout OR billing",
        "NOT",
        "AND",
        "[a",
        "{x}",
        "back\\slash",
        "-checkout",
        "+checkout",
        '"checkout"',
        "checkout api",
        "",
        "x" * 51,
    ],
)
def test_name_with_query_syntax_is_rejected_without_a_call(
    tool_ctx: ToolContext, name: str
) -> None:
    result = _list(tool_ctx, name=name)
    assert result.status == "error"
    assert result.content["error"].startswith("invalid input: name:")
    assert tool_ctx.datadog.calls == []


@pytest.mark.parametrize("name", ["checkout", "checkout-api", "api.v2", "x" * 50, "or"])
def test_plain_name_parts_are_accepted(name: str) -> None:
    assert DatadogLogsInput(name=name).name == name


@pytest.mark.parametrize(
    "tool_input",
    [
        {"minutes": 0},
        {"minutes": 181},
        {"env": "prod OR dev"},
        {"env": "env:prod"},
        {"query": "service:x"},
        {"status": "error"},
        {"service": "checkout-api", "name": "checkout"},
    ],
)
def test_out_of_bounds_input_is_rejected_without_a_call(
    tool_ctx: ToolContext, tool_input: dict[str, Any]
) -> None:
    result = _list(tool_ctx, **tool_input)
    assert result.status == "error"
    assert result.content["error"].startswith("invalid input:")
    assert tool_ctx.datadog.calls == []


def test_request_groups_by_service_and_status_over_the_alarm_window(
    tool_ctx: ToolContext,
) -> None:
    ctx = dataclasses.replace(tool_ctx, alarm_time=ALARM_AT)
    body = _list(ctx, minutes=180, env="prod").content
    assert _body(ctx) == {
        "filter": {
            "query": "env:prod status:(error OR warn)",
            "from": (ALARM_AT - timedelta(minutes=180)).isoformat(),
            "to": ALARM_AT.isoformat(),
        },
        "compute": [{"aggregation": "count", "type": "total"}],
        "group_by": [
            {
                "facet": "service",
                "limit": MAX_DATADOG_SERVICES + 1,
                "sort": {"aggregation": "count", "order": "desc", "type": "measure"},
            },
            {"facet": "status", "limit": 5},
        ],
    }
    assert body["window"] == {
        "start": "2026-09-29T11:05:00Z",
        "end": "2026-09-29T14:05:00Z",
    }


def test_window_defaults_to_thirty_minutes_ending_now(tool_ctx: ToolContext) -> None:
    before = datetime.now(UTC)
    _list(tool_ctx)
    sent = _body(tool_ctx)["filter"]
    start = datetime.fromisoformat(sent["from"])
    end = datetime.fromisoformat(sent["to"])
    assert end - start == timedelta(minutes=30)
    assert before <= end <= datetime.now(UTC)


def test_buckets_become_rows_sorted_by_errors(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["aggregate_logs"] = _buckets(
        _bucket("orders-api", "warn", 40),
        _bucket("checkout-api", "error", 12),
        _bucket("checkout-api", "warn", 3),
        _bucket("ingest", "error", 12.0),
        _bucket("ingest", "warn", 9),
        _bucket("quiet", "info", 7),
        _bucket(None, "error", 5),
        _bucket("", "error", 5),
        {"by": {"service": "no-computes", "status": "error"}},
        "not a bucket",
    )
    body = _list(tool_ctx).content
    assert body["services"] == [
        {"service": "ingest", "error": 12, "warn": 9},
        {"service": "checkout-api", "error": 12, "warn": 3},
        {"service": "orders-api", "error": 0, "warn": 40},
        {"service": "no-computes", "error": 0, "warn": 0},
        {"service": "quiet", "error": 0, "warn": 0},
    ]
    assert body["count"] == 5
    assert body["truncated"] is False
    assert body["query"] == "status:(error OR warn)"


def test_rows_are_capped_and_marked_truncated(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["aggregate_logs"] = _buckets(
        *(_bucket(f"svc-{i:02d}", "error", i) for i in range(MAX_DATADOG_SERVICES + 1))
    )
    body = _list(tool_ctx).content
    assert body["count"] == MAX_DATADOG_SERVICES == 25
    assert body["truncated"] is True
    assert body["services"][0] == {"service": "svc-25", "error": 25, "warn": 0}
    assert body["services"][-1]["service"] == "svc-01"


def test_next_page_marks_the_result_truncated(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["aggregate_logs"] = _buckets(
        _bucket("checkout-api", "error", 1), after="eyJhZnRlciI6"
    )
    body = _list(tool_ctx).content
    assert body["count"] == 1
    assert body["truncated"] is True


def test_empty_response_returns_no_services(tool_ctx: ToolContext) -> None:
    body = _list(tool_ctx).content
    assert body["count"] == 0
    assert body["services"] == []
    assert body["truncated"] is False


def test_result_stays_small(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["aggregate_logs"] = _buckets(
        *(
            _bucket(f"service-{i:03d}-" + "x" * 80, status, 1000 + i)
            for i in range(MAX_DATADOG_SERVICES + 5)
            for status in ("error", "warn")
        )
    )
    assert len(json.dumps(_list(tool_ctx).content)) < 4000


def test_with_service_it_searches_logs_instead(tool_ctx: ToolContext) -> None:
    body = _list(tool_ctx, service="checkout-api").content
    [(operation, _)] = tool_ctx.datadog.calls
    assert operation == "search_logs"
    assert "logs" in body
    assert "services" not in body


def test_tool_is_offered_only_with_datadog(tool_ctx: ToolContext) -> None:
    assert SEARCH_DATADOG_LOGS in {tool.name for tool in offered_tools(tool_ctx)}
    ctx = dataclasses.replace(tool_ctx, datadog=None)
    assert SEARCH_DATADOG_LOGS not in {tool.name for tool in offered_tools(ctx)}
    result = _list(ctx)
    assert result.status == "error"
    assert "unknown tool" in result.content["error"]


def _http_ctx(tool_ctx: ToolContext) -> ToolContext:
    client = DatadogClient(site="datadoghq.com", api_key=API_KEY, app_key=APP_KEY)
    return dataclasses.replace(tool_ctx, datadog=client, alarm_time=ALARM_AT)


def _response(payload: dict[str, Any]) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return response


def test_request_posts_to_the_logs_aggregate_endpoint_with_both_keys(
    tool_ctx: ToolContext, mocker: MockerFixture
) -> None:
    urlopen = mocker.patch.object(
        datadog_module.urllib.request,
        "urlopen",
        return_value=_response(_buckets(_bucket("checkout-api", "error", 4))),
    )
    result = _list(_http_ctx(tool_ctx), name="checkout")
    assert result.status == "success"
    assert result.content["services"] == [{"service": "checkout-api", "error": 4, "warn": 0}]
    [call] = urlopen.call_args_list
    request = call.args[0]
    assert request.full_url == AGGREGATE_URL
    assert request.get_method() == "POST"
    assert request.get_header("Dd-api-key") == API_KEY
    assert request.get_header("Dd-application-key") == APP_KEY
    assert call.kwargs["timeout"] == REQUEST_TIMEOUT_SECONDS
    sent = json.loads(request.data)
    assert sent["filter"]["query"] == "service:*checkout* status:(error OR warn)"
    assert sent["filter"]["to"] == ALARM_AT.isoformat()
    assert API_KEY not in json.dumps(result.content)


def _http_error(code: int) -> urllib.error.HTTPError:
    body = io.BytesIO(json.dumps({"errors": [f"key {API_KEY} rejected"]}).encode())
    return urllib.error.HTTPError(AGGREGATE_URL, code, "Error", None, body)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (_http_error(403), "Datadog logs aggregate failed: HTTP 403"),
        (
            _http_error(429),
            "Datadog logs aggregate failed: HTTP 429 (rate limited, try again later)",
        ),
        (TimeoutError("timed out"), "Datadog logs aggregate failed: TimeoutError"),
        (urllib.error.URLError("dns"), "Datadog logs aggregate failed: URLError"),
    ],
)
def test_http_failures_become_error_results_without_the_keys(
    tool_ctx: ToolContext,
    mocker: MockerFixture,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    failure: Exception,
    message: str,
) -> None:
    mocker.patch.object(datadog_module.urllib.request, "urlopen", side_effect=failure)
    with caplog.at_level(logging.DEBUG):
        result = _list(_http_ctx(tool_ctx))
    assert result.status == "error"
    assert result.content == {"error": message}
    captured = capsys.readouterr()
    for text in (json.dumps(result.content), caplog.text, captured.out, captured.err):
        assert API_KEY not in text
        assert APP_KEY not in text


def test_aggregate_url_follows_the_site() -> None:
    client = DatadogClient(site="us5.datadoghq.com", api_key=API_KEY, app_key=APP_KEY)
    assert client.logs_aggregate_url == (
        "https://api.us5.datadoghq.com/api/v2/logs/analytics/aggregate"
    )
    assert API_KEY not in repr(client)
    assert APP_KEY not in repr(client)
