"""datadog_events: query building, bounds, projection, offering, HTTP failures, keys."""

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
from devops_agent.redact import REDACTED
from devops_agent.tools import (
    DATADOG_EVENTS,
    DatadogEventsInput,
    ToolContext,
    datadog_events_query,
    offered_tools,
    run_tool,
)

API_KEY = "ddapi0123456789abcdef0123456789ab"
APP_KEY = "ddapp0123456789abcdef0123456789abcdef0123"
ALARM_AT = datetime(2026, 9, 29, 14, 5, tzinfo=UTC)
EVENTS_URL = "https://api.datadoghq.com/api/v2/events/search"


def _events(tool_ctx: ToolContext, **tool_input: Any) -> Any:
    return run_tool(DATADOG_EVENTS, {"kube_namespace": "checkout", **tool_input}, tool_ctx)


def _body(tool_ctx: ToolContext) -> dict[str, Any]:
    [(operation, kwargs)] = tool_ctx.datadog.calls
    assert operation == "search_events"
    body: dict[str, Any] = kwargs["body"]
    return body


def _event(**attributes: Any) -> dict[str, Any]:
    return {"id": "AAAAAY", "type": "event", "attributes": attributes}


@pytest.mark.parametrize(
    ("tool_input", "query"),
    [
        ({"service": "checkout-api"}, "source:change_tracking service:checkout-api"),
        ({"kube_namespace": "checkout"}, "source:change_tracking kube_namespace:checkout"),
        (
            {"service": "checkout-api", "env": "prod", "source": "alert"},
            "source:alert service:checkout-api env:prod",
        ),
        (
            {"kube_namespace": "checkout", "source": "deployment_analysis"},
            "source:deployment_analysis kube_namespace:checkout",
        ),
    ],
)
def test_query_is_built_from_the_fields(tool_input: dict[str, Any], query: str) -> None:
    assert datadog_events_query(DatadogEventsInput.model_validate(tool_input)) == query


@pytest.mark.parametrize(
    "tool_input",
    [
        {},
        {"service": "checkout-api", "kube_namespace": "checkout"},
        {"service": "svc OR other"},
        {"service": "svc:x"},
        {"service": "svc*"},
        {"kube_namespace": "ns status:error"},
        {"kube_namespace": "(ns)"},
        {"kube_namespace": "-ns"},
        {"service": "svc", "env": "prod OR dev"},
        {"service": "svc", "source": "kubernetes OR alert"},
        {"service": "svc", "minutes": 0},
        {"service": "svc", "minutes": 361},
        {"service": "svc", "limit": 0},
        {"service": "svc", "limit": 51},
        {"service": "svc", "query": "source:*"},
    ],
)
def test_invalid_input_is_rejected_without_a_call(
    tool_ctx: ToolContext, tool_input: dict[str, Any]
) -> None:
    result = run_tool(DATADOG_EVENTS, tool_input, tool_ctx)
    assert result.status == "error"
    assert result.content["error"].startswith("invalid input:")
    assert tool_ctx.datadog.calls == []


def test_window_ends_at_the_alarm_time(tool_ctx: ToolContext) -> None:
    ctx = dataclasses.replace(tool_ctx, alarm_time=ALARM_AT)
    body = _events(ctx, minutes=360, limit=50).content
    assert _body(ctx) == {
        "filter": {
            "query": "source:change_tracking kube_namespace:checkout",
            "from": (ALARM_AT - timedelta(minutes=360)).isoformat(),
            "to": ALARM_AT.isoformat(),
        },
        "sort": "-timestamp",
        "page": {"limit": 50},
    }
    assert body["window"] == {
        "start": "2026-09-29T08:05:00Z",
        "end": "2026-09-29T14:05:00Z",
    }


def test_window_defaults_to_sixty_minutes_and_twenty_events(tool_ctx: ToolContext) -> None:
    before = datetime.now(UTC)
    _events(tool_ctx)
    sent = _body(tool_ctx)
    start = datetime.fromisoformat(sent["filter"]["from"])
    end = datetime.fromisoformat(sent["filter"]["to"])
    assert end - start == timedelta(minutes=60)
    assert before <= end <= datetime.now(UTC)
    assert sent["page"] == {"limit": 20}


def test_events_are_projected_filtered_and_stripped(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["search_events"] = {
        "data": [
            _event(
                timestamp="2026-09-29T14:03:00Z",
                message="%%% \nBack-off restarting failed container password=hunter2 "
                + "y" * 900
                + "\n %%%",
                tags=[
                    "kube_namespace:checkout",
                    "kube_deployment:checkout-api",
                    "pod_name:checkout-api-7d9f-x2k",
                    "service:checkout-api",
                    "env:prod",
                    "kube_cluster:acme-prod",
                    "image_id:sha256:abc",
                    "host:i-0abc",
                    7,
                ],
                attributes={"title": "Events from the Pod checkout/checkout-api-7d9f-x2k"},
            ),
            _event(title="OOMKilled", message="%%%\nContainer was OOMKilled\n%%%"),
            {"attributes": None},
        ],
        "meta": {"page": {}},
    }
    body = _events(tool_ctx).content
    assert body["count"] == 3
    assert body["truncated"] is False
    first, second, third = body["events"]
    assert set(first) == {"timestamp", "title", "tags", "message"}
    assert first["title"] == "Events from the Pod checkout/checkout-api-7d9f-x2k"
    assert first["tags"] == [
        "kube_namespace:checkout",
        "kube_deployment:checkout-api",
        "pod_name:checkout-api-7d9f-x2k",
        "service:checkout-api",
        "env:prod",
        "kube_cluster:acme-prod",
    ]
    assert first["message"].startswith(f"Back-off restarting failed container password={REDACTED}")
    assert len(first["message"]) == 400
    assert second == {"title": "OOMKilled", "message": "Container was OOMKilled"}
    assert third == {"message": ""}
    text = json.dumps(body)
    assert "%%%" not in text
    assert "hunter2" not in text
    assert "image_id" not in text


def test_next_page_marks_the_result_truncated(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["search_events"] = {
        "data": [_event(message=f"m{i}") for i in range(5)],
        "meta": {"page": {"after": "eyJhZnRlciI6"}},
    }
    body = _events(tool_ctx, limit=5).content
    assert body["count"] == 5
    assert body["truncated"] is True


def test_extra_events_beyond_the_limit_are_cut(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["search_events"] = {
        "data": [_event(message=f"m{i}") for i in range(60)]
    }
    body = _events(tool_ctx, limit=50).content
    assert body["count"] == 50
    assert body["truncated"] is True


def test_empty_response_returns_no_events(tool_ctx: ToolContext) -> None:
    body = _events(tool_ctx).content
    assert body["count"] == 0
    assert body["events"] == []
    assert body["truncated"] is False


def test_tool_is_not_offered_without_datadog(tool_ctx: ToolContext) -> None:
    assert DATADOG_EVENTS in {tool.name for tool in offered_tools(tool_ctx)}
    ctx = dataclasses.replace(tool_ctx, datadog=None)
    assert DATADOG_EVENTS not in {tool.name for tool in offered_tools(ctx)}
    result = _events(ctx)
    assert result.status == "error"
    assert "unknown tool" in result.content["error"]


def _http_ctx(tool_ctx: ToolContext) -> ToolContext:
    client = DatadogClient(site="datadoghq.com", api_key=API_KEY, app_key=APP_KEY)
    return dataclasses.replace(tool_ctx, datadog=client, alarm_time=ALARM_AT)


def _response(payload: dict[str, Any]) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return response


def test_request_posts_to_the_events_search_endpoint_with_both_keys(
    tool_ctx: ToolContext, mocker: MockerFixture
) -> None:
    urlopen = mocker.patch.object(
        datadog_module.urllib.request,
        "urlopen",
        return_value=_response({"data": [_event(title="Deploy", message="%%%\nv2\n%%%")]}),
    )
    result = _events(_http_ctx(tool_ctx), env="prod")
    assert result.status == "success"
    assert result.content["events"] == [{"title": "Deploy", "message": "v2"}]
    [call] = urlopen.call_args_list
    request = call.args[0]
    assert request.full_url == EVENTS_URL
    assert request.get_method() == "POST"
    assert request.get_header("Dd-api-key") == API_KEY
    assert request.get_header("Dd-application-key") == APP_KEY
    assert call.kwargs["timeout"] == REQUEST_TIMEOUT_SECONDS
    sent = json.loads(request.data)
    assert sent["filter"]["query"] == "source:change_tracking kube_namespace:checkout env:prod"
    assert API_KEY not in json.dumps(result.content)


def _http_error(code: int) -> urllib.error.HTTPError:
    body = io.BytesIO(json.dumps({"errors": [f"key {API_KEY} rejected"]}).encode())
    return urllib.error.HTTPError(EVENTS_URL, code, "Error", None, body)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (_http_error(403), "Datadog events search failed: HTTP 403"),
        (
            _http_error(429),
            "Datadog events search failed: HTTP 429 (rate limited, try again later)",
        ),
        (TimeoutError("timed out"), "Datadog events search failed: TimeoutError"),
        (urllib.error.URLError("dns"), "Datadog events search failed: URLError"),
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
        result = _events(_http_ctx(tool_ctx))
    assert result.status == "error"
    assert result.content == {"error": message}
    captured = capsys.readouterr()
    for text in (json.dumps(result.content), caplog.text, captured.out, captured.err):
        assert API_KEY not in text
        assert APP_KEY not in text
