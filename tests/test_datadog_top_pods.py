"""datadog_top_pods: query, request, unit conversion, ranking, bounds, offering, failures."""

from __future__ import annotations

import dataclasses
import io
import json
import urllib.error
import urllib.parse
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from devops_agent import datadog as datadog_module
from devops_agent.datadog import REQUEST_TIMEOUT_SECONDS, DatadogClient
from devops_agent.tools import (
    DATADOG_TOP_PODS,
    MAX_TOP_PODS,
    ToolContext,
    offered_tools,
    run_tool,
)

API_KEY = "ddapi0123456789abcdef0123456789ab"
APP_KEY = "ddapp0123456789abcdef0123456789abcdef0123"
QUERY_URL = "https://api.datadoghq.com/api/v1/query"
NODE_ID = "i-0123456789abcdef0"
START = (datetime.now(UTC) - timedelta(days=1)).replace(minute=0, second=0, microsecond=0)
END = START + timedelta(hours=1)
WINDOW = {"start": START.isoformat(), "end": END.isoformat()}
NODE_QUERY = f"sum:kubernetes.cpu.usage.total{{host:{NODE_ID}}} by {{kube_namespace,pod_name}}"


def _top_pods(tool_ctx: ToolContext, **tool_input: Any) -> Any:
    return run_tool(DATADOG_TOP_PODS, {**WINDOW, **tool_input}, tool_ctx)


def _utc_text(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _ms(minutes: int) -> int:
    return int((START + timedelta(minutes=minutes)).timestamp() * 1000)


def _series(namespace: str, pod: str, points: list[tuple[int, float | None]]) -> dict[str, Any]:
    return {
        "metric": "kubernetes.cpu.usage.total",
        "scope": f"host:{NODE_ID},kube_namespace:{namespace},pod_name:{pod}",
        "tag_set": [f"kube_namespace:{namespace}", f"pod_name:{pod}"],
        "pointlist": [[_ms(minute), value] for minute, value in points],
    }


def _answer(*series: dict[str, Any]) -> dict[str, Any]:
    return {"status": "ok", "res_type": "time_series", "series": list(series)}


def test_host_request_sums_cpu_per_pod_on_the_node(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["query_metrics"] = _answer()
    result = _top_pods(tool_ctx, host=NODE_ID)
    assert result.status == "success"
    [(operation, kwargs)] = tool_ctx.datadog.calls
    assert operation == "query_metrics"
    assert kwargs == {
        "params": {
            "from": str(int(START.timestamp())),
            "to": str(int(END.timestamp())),
            "query": NODE_QUERY,
        }
    }
    assert result.content == {
        "query": NODE_QUERY,
        "window": {"start": _utc_text(START), "end": _utc_text(END)},
        "metric": "cpu",
        "unit": "cores",
        "count": 0,
        "truncated": False,
        "pods": [],
    }


def test_cluster_request_scopes_memory_to_a_namespace(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["query_metrics"] = _answer()
    result = _top_pods(tool_ctx, cluster="acme-prod", kube_namespace="catalog", metric="memory")
    assert result.status == "success"
    [(_, kwargs)] = tool_ctx.datadog.calls
    assert kwargs["params"]["query"] == (
        "sum:kubernetes.memory.usage{kube_cluster_name:acme-prod,"
        "kube_namespace:catalog} by {kube_namespace,pod_name}"
    )
    assert result.content["unit"] == "MiB"


def test_cpu_is_reported_in_cores_with_the_jump(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["query_metrics"] = _answer(
        _series(
            "catalog",
            "catalog-b79c879bf-bg7ss",
            [
                (0, 10_000_000.0),
                (10, 12_000_000.0),
                (20, None),
                (30, 2_500_000_000.0),
                (40, 3_100_000_000.0),
                (50, 2_000_000_000.0),
            ],
        )
    )
    result = _top_pods(tool_ctx, host=NODE_ID)
    assert result.content["pods"] == [
        {
            "kube_namespace": "catalog",
            "pod_name": "catalog-b79c879bf-bg7ss",
            "max": 3.1,
            "max_at": _utc_text(START + timedelta(minutes=40)),
            "avg": 1.524,
            "last": 2.0,
            "before": 0.011,
        }
    ]
    assert result.content["count"] == 1
    assert result.content["truncated"] is False


def test_memory_is_reported_in_mib(tool_ctx: ToolContext) -> None:
    mib = 1024 * 1024
    tool_ctx.datadog.responses["query_metrics"] = _answer(
        _series("checkout", "checkout-api-0", [(0, 256.0 * mib), (45, 512.0 * mib)])
    )
    result = _top_pods(tool_ctx, host=NODE_ID, metric="memory")
    [pod] = result.content["pods"]
    assert (pod["max"], pod["avg"], pod["last"], pod["before"]) == (512.0, 384.0, 512.0, 256.0)
    assert result.content["unit"] == "MiB"


def test_a_pod_without_points_in_the_first_quarter_has_no_before(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["query_metrics"] = _answer(
        _series("checkout", "checkout-api-new", [(40, 1e9)])
    )
    [pod] = _top_pods(tool_ctx, host=NODE_ID).content["pods"]
    assert "before" not in pod


def test_pods_are_ranked_by_max_and_capped(tool_ctx: ToolContext) -> None:
    series = [_series("ns", f"pod-{n}", [(5, n * 1e8), (50, 1e7)]) for n in range(1, 13)]
    series.append(_series("ns", "empty", [(5, None)]))
    tool_ctx.datadog.responses["query_metrics"] = _answer(*series)
    result = _top_pods(tool_ctx, host=NODE_ID)
    pods = result.content["pods"]
    assert len(pods) == MAX_TOP_PODS
    assert [pod["pod_name"] for pod in pods] == [f"pod-{n}" for n in range(12, 2, -1)]
    assert result.content["count"] == MAX_TOP_PODS
    assert result.content["truncated"] is True


def test_pod_names_are_redacted(tool_ctx: ToolContext) -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    tool_ctx.datadog.responses["query_metrics"] = _answer(
        _series("ns", f"job-{secret}", [(5, 1e9)])
    )
    result = _top_pods(tool_ctx, host=NODE_ID)
    assert secret not in json.dumps(result.content)


@pytest.mark.parametrize(
    "tool_input",
    [
        {},
        {"host": NODE_ID, "cluster": "acme-prod"},
        {"host": "i-07ac*"},
        {"host": "host:i-0123456789abcdef0"},
        {"host": "i-07AC21C137D6B4AB9"},
        {"cluster": "acme-prod OR other"},
        {"cluster": "acme-prod,env:prod"},
        {"cluster": "acme-prod}"},
        {"cluster": ""},
        {"cluster": "c", "kube_namespace": "ns:x"},
        {"cluster": "c", "kube_namespace": "*"},
        {"cluster": "c", "metric": "network"},
        {"cluster": "c", "minutes": 181},
        {"cluster": "c", "query": "avg:system.cpu.user{*}"},
    ],
)
def test_invalid_input_is_rejected_without_a_call(
    tool_ctx: ToolContext, tool_input: dict[str, Any]
) -> None:
    result = run_tool(DATADOG_TOP_PODS, tool_input, tool_ctx)
    assert result.status == "error"
    assert result.content["error"].startswith("invalid input:")
    assert tool_ctx.datadog.calls == []


def test_a_window_over_three_hours_is_rejected(tool_ctx: ToolContext) -> None:
    result = _top_pods(tool_ctx, host=NODE_ID, end=(START + timedelta(hours=4)).isoformat())
    assert result.status == "error"
    assert result.content == {"error": "the window is at most 3 hours"}
    assert tool_ctx.datadog.calls == []


def test_tool_is_not_offered_without_datadog(tool_ctx: ToolContext) -> None:
    assert DATADOG_TOP_PODS in {tool.name for tool in offered_tools(tool_ctx)}
    ctx = dataclasses.replace(tool_ctx, datadog=None)
    assert DATADOG_TOP_PODS not in {tool.name for tool in offered_tools(ctx)}
    result = _top_pods(ctx, host=NODE_ID)
    assert result.status == "error"
    assert "unknown tool" in result.content["error"]


def test_a_query_error_becomes_an_error_result(tool_ctx: ToolContext) -> None:
    tool_ctx.datadog.responses["query_metrics"] = {"status": "error", "error": "Rule parse error"}
    result = _top_pods(tool_ctx, host=NODE_ID)
    assert result.status == "error"
    assert result.content == {"error": "Datadog metrics query failed: Rule parse error"}


def _http_ctx(tool_ctx: ToolContext) -> ToolContext:
    client = DatadogClient(site="datadoghq.com", api_key=API_KEY, app_key=APP_KEY)
    return dataclasses.replace(tool_ctx, datadog=client)


def _response(payload: Any) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return response


def test_request_gets_the_metrics_query_with_both_keys(
    tool_ctx: ToolContext, mocker: MockerFixture
) -> None:
    urlopen = mocker.patch.object(
        datadog_module.urllib.request,
        "urlopen",
        return_value=_response(_answer(_series("ns", "pod-a", [(5, 1e9)]))),
    )
    result = _top_pods(_http_ctx(tool_ctx), host=NODE_ID)
    assert result.status == "success"
    assert [pod["pod_name"] for pod in result.content["pods"]] == ["pod-a"]
    [call] = urlopen.call_args_list
    request = call.args[0]
    assert request.full_url == (
        f"{QUERY_URL}?from={int(START.timestamp())}&to={int(END.timestamp())}"
        "&query=sum%3Akubernetes.cpu.usage.total%7Bhost%3Ai-0123456789abcdef0%7D"
        "+by+%7Bkube_namespace%2Cpod_name%7D"
    )
    url = urllib.parse.urlsplit(request.full_url)
    assert urllib.parse.parse_qs(url.query)["query"] == [NODE_QUERY]
    assert request.get_method() == "GET"
    assert request.data is None
    assert request.get_header("Dd-api-key") == API_KEY
    assert request.get_header("Dd-application-key") == APP_KEY
    assert call.kwargs["timeout"] == REQUEST_TIMEOUT_SECONDS
    assert API_KEY not in json.dumps(result.content)


def _http_error(code: int) -> urllib.error.HTTPError:
    body = io.BytesIO(json.dumps({"errors": [f"key {API_KEY} rejected"]}).encode())
    return urllib.error.HTTPError(QUERY_URL, code, "Error", None, body)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (_http_error(403), "Datadog metrics query failed: HTTP 403"),
        (
            _http_error(429),
            "Datadog metrics query failed: HTTP 429 (rate limited, try again later)",
        ),
        (TimeoutError("timed out"), "Datadog metrics query failed: TimeoutError"),
    ],
)
def test_http_failures_become_error_results_without_the_keys(
    tool_ctx: ToolContext, mocker: MockerFixture, failure: Exception, message: str
) -> None:
    mocker.patch.object(datadog_module.urllib.request, "urlopen", side_effect=failure)
    result = _top_pods(_http_ctx(tool_ctx), host=NODE_ID)
    assert result.status == "error"
    assert result.content == {"error": message}
    assert API_KEY not in json.dumps(result.content)
    assert APP_KEY not in json.dumps(result.content)
