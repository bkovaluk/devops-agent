"""search_datadog_logs: query building, bounds, projection, offering, HTTP failures, keys."""

from __future__ import annotations

import ast
import dataclasses
import io
import json
import logging
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from devops_agent import datadog as datadog_module
from devops_agent import github as github_module
from devops_agent import tools
from devops_agent.config import Settings, get_settings
from devops_agent.datadog import (
    EVENTS_SEARCH_PATH,
    LOGS_AGGREGATE_PATH,
    LOGS_SEARCH_PATH,
    METRICS_QUERY_PATH,
    MONITOR_PATH,
    REQUEST_TIMEOUT_SECONDS,
    DatadogClient,
    datadog_client,
)
from devops_agent.redact import REDACTED
from devops_agent.tools import (
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
SEARCH_URL = "https://api.datadoghq.com/api/v2/logs/events/search"


def _search(tool_ctx: ToolContext, **tool_input: Any) -> Any:
    return run_tool(SEARCH_DATADOG_LOGS, {"service": "checkout-api-prod", **tool_input}, tool_ctx)


def _body(tool_ctx: ToolContext) -> dict[str, Any]:
    [(operation, kwargs)] = tool_ctx.datadog.calls
    assert operation == "search_logs"
    body: dict[str, Any] = kwargs["body"]
    return body


def _event(**attributes: Any) -> dict[str, Any]:
    return {"id": "AQAAAY", "type": "log", "attributes": attributes}


@pytest.mark.parametrize(
    ("tool_input", "query"),
    [
        ({}, "service:checkout-api-prod status:(error OR warn)"),
        ({"env": "prod"}, "service:checkout-api-prod env:prod status:(error OR warn)"),
        ({"status": "info"}, "service:checkout-api-prod status:info"),
        ({"status": "error"}, "service:checkout-api-prod status:error"),
        (
            {"text": "timeout upstream"},
            "service:checkout-api-prod status:(error OR warn) timeout upstream",
        ),
        (
            {"env": "prod", "status": "warn", "text": '"connection reset" pool'},
            'service:checkout-api-prod env:prod status:warn "connection reset" pool',
        ),
    ],
)
def test_query_is_built_from_the_fields(tool_input: dict[str, Any], query: str) -> None:
    params = DatadogLogsInput.model_validate({"service": "checkout-api-prod", **tool_input})
    assert datadog_logs_query(params) == query


@pytest.mark.parametrize(
    "text",
    [
        "service:other",
        "error*",
        "erro?",
        "(timeout)",
        "timeout OR crash",
        "timeout AND crash",
        "NOT healthy",
        "[a TO b]",
        "{x}",
        "back\\slash",
        "-healthcheck",
        "timeout +crash",
        '"unbalanced',
        "x" * 101,
    ],
)
def test_text_with_query_operators_is_rejected_without_a_call(
    tool_ctx: ToolContext, text: str
) -> None:
    result = _search(tool_ctx, text=text)
    assert result.status == "error"
    assert result.content["error"].startswith("invalid input: text:")
    assert tool_ctx.datadog.calls == []


@pytest.mark.parametrize("text", ["not found", "time-out", "a or b", '"pool exhausted"'])
def test_plain_words_and_phrases_are_accepted(text: str) -> None:
    assert DatadogLogsInput(service="svc", text=text).text == text


@pytest.mark.parametrize(
    "tool_input",
    [
        {"minutes": 0},
        {"minutes": 181},
        {"limit": 0},
        {"limit": 51},
        {"status": "critical"},
        {"service": "svc status:info"},
        {"service": "svc:x"},
        {"service": ""},
        {"env": "prod OR dev"},
        {"query": "service:x"},
    ],
)
def test_out_of_bounds_input_is_rejected_without_a_call(
    tool_ctx: ToolContext, tool_input: dict[str, Any]
) -> None:
    result = _search(tool_ctx, **tool_input)
    assert result.status == "error"
    assert result.content["error"].startswith("invalid input:")
    assert tool_ctx.datadog.calls == []


def test_without_service_it_ranks_services_instead(tool_ctx: ToolContext) -> None:
    result = run_tool(SEARCH_DATADOG_LOGS, {}, tool_ctx)
    assert result.status == "success"
    assert [operation for operation, _ in tool_ctx.datadog.calls] == ["aggregate_logs"]
    assert "services" in result.content


def test_window_ends_at_the_alarm_time(tool_ctx: ToolContext) -> None:
    ctx = dataclasses.replace(tool_ctx, alarm_time=ALARM_AT)
    body = _search(ctx, minutes=180, limit=50).content
    sent = _body(ctx)
    assert sent["filter"] == {
        "query": "service:checkout-api-prod status:(error OR warn)",
        "from": (ALARM_AT - timedelta(minutes=180)).isoformat(),
        "to": ALARM_AT.isoformat(),
    }
    assert sent["sort"] == "-timestamp"
    assert sent["page"] == {"limit": 50}
    assert body["window"] == {
        "start": "2026-09-29T11:05:00Z",
        "end": "2026-09-29T14:05:00Z",
    }


def test_window_defaults_to_thirty_minutes_ending_now(tool_ctx: ToolContext) -> None:
    before = datetime.now(UTC)
    _search(tool_ctx)
    sent = _body(tool_ctx)
    start = datetime.fromisoformat(sent["filter"]["from"])
    end = datetime.fromisoformat(sent["filter"]["to"])
    assert end - start == timedelta(minutes=30)
    assert before <= end <= datetime.now(UTC)
    assert sent["page"] == {"limit": 25}


def test_alarm_time_in_the_future_ends_the_window_now(tool_ctx: ToolContext) -> None:
    ctx = dataclasses.replace(tool_ctx, alarm_time=datetime.now(UTC) + timedelta(hours=1))
    _search(ctx)
    assert datetime.fromisoformat(_body(ctx)["filter"]["to"]) <= datetime.now(UTC)


def test_logs_are_projected_cut_and_redacted(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["search_logs"] = {
        "data": [
            _event(
                timestamp="2026-09-29T14:04:59.123Z",
                service="checkout-api-prod",
                status="error",
                host="i-0abc",
                message="ERROR password=hunter2 " + "y" * 900,
                tags=["env:prod", "pod_name:checkout-api-7d9f-x2k", "kube_namespace:checkout"],
                attributes={"http": {"headers": {"authorization": "Bearer secret"}}},
            ),
            _event(
                status="warn",
                host="ip-10-0-0-1",
                message="slow",
                tags=["task_arn:arn:aws:ecs:us-east-1:111122223333:task/core/0f1e2d3c4b5a"],
            ),
            _event(status="warn", host="ip-10-0-0-2", message="slow", tags=["env:prod"]),
            {"attributes": None},
        ],
        "meta": {"page": {}},
    }
    body = _search(tool_ctx).content
    assert body["count"] == 4
    assert body["truncated"] is False
    first, second, third, fourth = body["logs"]
    assert set(first) == {"timestamp", "service", "status", "host", "message"}
    assert first["host"] == "checkout-api-7d9f-x2k"
    assert len(first["message"]) == 500
    assert first["message"].startswith(f"ERROR password={REDACTED} ")
    assert second["host"] == "0f1e2d3c4b5a"
    assert third["host"] == "ip-10-0-0-2"
    assert fourth == {"message": ""}
    text = json.dumps(body)
    assert "hunter2" not in text
    assert "Bearer" not in text
    assert "kube_namespace" not in text


def test_next_page_marks_the_result_truncated(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["search_logs"] = {
        "data": [_event(message=f"m{i}") for i in range(5)],
        "meta": {"page": {"after": "eyJhZnRlciI6"}},
    }
    body = _search(tool_ctx, limit=5).content
    assert body["count"] == 5
    assert body["truncated"] is True


def test_extra_logs_beyond_the_limit_are_cut(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["search_logs"] = {
        "data": [_event(message=f"m{i}") for i in range(60)]
    }
    body = _search(tool_ctx, limit=50).content
    assert body["count"] == 50
    assert body["truncated"] is True


def test_empty_response_returns_no_logs(tool_ctx: ToolContext) -> None:
    body = _search(tool_ctx).content
    assert body["count"] == 0
    assert body["logs"] == []
    assert body["truncated"] is False


def test_tool_is_not_offered_without_datadog(tool_ctx: ToolContext) -> None:
    ctx = dataclasses.replace(tool_ctx, datadog=None)
    assert SEARCH_DATADOG_LOGS not in {tool.name for tool in offered_tools(ctx)}
    assert SEARCH_DATADOG_LOGS in {tool.name for tool in offered_tools(tool_ctx)}
    result = run_tool(SEARCH_DATADOG_LOGS, {"service": "checkout-api-prod"}, ctx)
    assert result.status == "error"
    assert "unknown tool" in result.content["error"]


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"DD_API_KEY": API_KEY},
        {"DATADOG_APP_KEY": APP_KEY},
        {"DD_API_KEY": "", "DATADOG_APP_KEY": APP_KEY},
        {"DD_API_KEY": API_KEY, "DATADOG_APP_KEY": ""},
    ],
)
def test_missing_key_means_no_client(monkeypatch: pytest.MonkeyPatch, env: dict[str, str]) -> None:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert datadog_client(get_settings()) is None


def test_both_keys_make_a_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DD_API_KEY", API_KEY)
    monkeypatch.setenv("DATADOG_APP_KEY", APP_KEY)
    monkeypatch.setenv("DATADOG_SITE", "us5.datadoghq.com")
    settings = get_settings()
    client = datadog_client(settings)
    assert client is not None
    assert client.logs_search_url == "https://api.us5.datadoghq.com/api/v2/logs/events/search"
    for text in (repr(client), repr(settings), str(settings.model_dump())):
        assert API_KEY not in text
        assert APP_KEY not in text


@pytest.mark.parametrize("site", ["evil.example.com", "datadoghq.com.evil.io", "a/b.datadoghq.com"])
def test_site_must_be_a_datadog_site(monkeypatch: pytest.MonkeyPatch, site: str) -> None:
    monkeypatch.setenv("DATADOG_SITE", site)
    with pytest.raises(ValueError, match="datadog_site"):
        Settings()  # type: ignore[call-arg]


def _http_ctx(tool_ctx: ToolContext) -> ToolContext:
    client = DatadogClient(site="datadoghq.com", api_key=API_KEY, app_key=APP_KEY)
    return dataclasses.replace(tool_ctx, datadog=client, alarm_time=ALARM_AT)


def _response(payload: dict[str, Any]) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return response


def test_request_posts_to_the_logs_search_endpoint_with_both_keys(
    tool_ctx: ToolContext, mocker: MockerFixture
) -> None:
    urlopen = mocker.patch.object(
        datadog_module.urllib.request,
        "urlopen",
        return_value=_response({"data": [_event(message="boom", status="error")]}),
    )
    result = _search(_http_ctx(tool_ctx), env="prod")
    assert result.status == "success"
    assert result.content["logs"] == [{"status": "error", "message": "boom"}]
    [call] = urlopen.call_args_list
    request = call.args[0]
    assert request.full_url == SEARCH_URL
    assert request.get_method() == "POST"
    assert request.get_header("Dd-api-key") == API_KEY
    assert request.get_header("Dd-application-key") == APP_KEY
    assert request.get_header("Content-type") == "application/json"
    assert call.kwargs["timeout"] == REQUEST_TIMEOUT_SECONDS == 10.0
    sent = json.loads(request.data)
    assert sent["filter"]["query"] == "service:checkout-api-prod env:prod status:(error OR warn)"
    assert sent["filter"]["to"] == ALARM_AT.isoformat()


def _http_error(code: int) -> urllib.error.HTTPError:
    body = io.BytesIO(json.dumps({"errors": [f"key {API_KEY} rejected"]}).encode())
    return urllib.error.HTTPError(SEARCH_URL, code, "Error", None, body)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (_http_error(403), "Datadog logs search failed: HTTP 403"),
        (_http_error(429), "Datadog logs search failed: HTTP 429 (rate limited, try again later)"),
        (_http_error(500), "Datadog logs search failed: HTTP 500"),
        (TimeoutError("timed out"), "Datadog logs search failed: TimeoutError"),
        (urllib.error.URLError("dns"), "Datadog logs search failed: URLError"),
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
        result = _search(_http_ctx(tool_ctx))
    assert result.status == "error"
    assert result.content == {"error": message}
    captured = capsys.readouterr()
    for text in (json.dumps(result.content), caplog.text, captured.out, captured.err):
        assert API_KEY not in text
        assert APP_KEY not in text


def test_unreadable_response_is_an_error_result(
    tool_ctx: ToolContext, mocker: MockerFixture
) -> None:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = b"<html>"
    mocker.patch.object(datadog_module.urllib.request, "urlopen", return_value=response)
    result = _search(_http_ctx(tool_ctx))
    assert result.status == "error"
    assert result.content == {"error": "Datadog logs search failed: JSONDecodeError"}


def _string_constants(path: Path) -> set[str]:
    return {
        node.value
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


def test_the_only_outbound_urls_are_the_datadog_and_github_read_endpoints() -> None:
    package = Path(datadog_module.__file__).parent
    urls = {
        text
        for path in package.glob("*.py")
        for text in _string_constants(path)
        if text.startswith(
            ("https://", "http://", "/api/", "/app/", "/orgs/", "/repos/", "/search/")
        )
    }
    assert urls == {
        "https://api.",
        LOGS_SEARCH_PATH,
        LOGS_AGGREGATE_PATH,
        EVENTS_SEARCH_PATH,
        MONITOR_PATH,
        METRICS_QUERY_PATH,
        "https://api.github.com",
        "/app/installations/{installation_id}/access_tokens",
        "/orgs/{org}/repos",
        "/search/code",
        "/repos/{owner}/{repo}/contents/{path}",
        "/repos/{owner}/{repo}/commits",
        "/repos/{owner}/{repo}/commits/{sha}",
        "/repos/{owner}/{repo}/pulls",
        "/repos/{owner}/{repo}/pulls/{number}",
        "/repos/{owner}/{repo}/pulls/{number}/files",
        "/repos/{owner}/{repo}/actions/runs",
    }
    assert LOGS_SEARCH_PATH == "/api/v2/logs/events/search"
    assert LOGS_AGGREGATE_PATH == "/api/v2/logs/analytics/aggregate"
    assert EVENTS_SEARCH_PATH == "/api/v2/events/search"
    assert MONITOR_PATH == "/api/v1/monitor/{monitor_id}"
    assert METRICS_QUERY_PATH == "/api/v1/query"
    for path in package.glob("*.py"):
        if path.name not in ("datadog.py", "github.py"):
            source = path.read_text()
            assert "urllib" not in source, path.name
            assert "http.client" not in source, path.name
    github_source = Path(github_module.__file__).read_text()
    assert github_source.count("urlopen(") == 1
    # One GET for every read; the one POST is the installation token exchange.
    assert github_source.count('self._send("GET", ') == 1
    assert github_source.count('self._send("POST", ') == 1
    assert github_source.count("ACCESS_TOKENS_PATH.format(") == 1
    source = Path(datadog_module.__file__).read_text()
    assert source.count("urlopen(") == 1
    assert 'method="GET" if body is None else "POST"' in source
    assert Path(tools.__file__).read_text().count(".search_logs(") == 1
    tools_source = Path(tools.__file__).read_text()
    for operation in ("aggregate_logs", "search_events", "query_metrics"):
        assert tools_source.count(f".{operation}(") == 1, operation
