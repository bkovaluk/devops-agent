"""Datadog signal verification: each drop reason, the cache and read failures."""

from __future__ import annotations

import json
import urllib.error
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from devops_agent import datadog as datadog_module
from devops_agent.datadog import DatadogClient, DatadogError
from devops_agent.signals import Signal, parse_signal
from devops_agent.verify import (
    FAILED_READ_CACHE_SECONDS,
    MONITOR_CACHE_SECONDS,
    clear_monitor_cache,
    read_monitor,
    verify_monitor,
)
from tests.conftest import DATADOG_MONITOR_ID, FakeClient, datadog_event, datadog_monitor


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _signal(**detail: Any) -> Signal:
    signal = parse_signal(datadog_event(**detail))
    assert signal is not None
    return signal


def _verify(monitor: Any, signal: Signal | None = None, env: str = "prod") -> Any:
    client = FakeClient({"get_monitor": monitor})
    return verify_monitor(client, signal or _signal(), env, 2, Clock())  # type: ignore[arg-type]


def test_alerting_opted_in_monitor_of_this_env_is_verified() -> None:
    client = FakeClient({"get_monitor": datadog_monitor()})
    verdict = verify_monitor(client, _signal(), "prod", 4, Clock())  # type: ignore[arg-type]
    assert verdict.verified
    assert verdict.priority == 2
    [(operation, kwargs)] = client.calls
    assert operation == "get_monitor"
    assert kwargs == {"monitor_id": DATADOG_MONITOR_ID, "params": {"group_states": "alert,warn"}}


def test_monitor_without_priority_takes_the_fallback() -> None:
    assert _verify(datadog_monitor(priority=None)).priority == 2


@pytest.mark.parametrize(
    ("monitor", "reason"),
    [
        (DatadogError("Datadog monitor read failed: HTTP 404", 404), "does not exist"),
        (datadog_monitor(tags=["env:prod"]), "devops_agent:true"),
        (
            datadog_monitor(state={"groups": {"service:checkout-api-prod": {"status": "OK"}}}),
            "the group is OK",
        ),
        (datadog_monitor(state={"groups": {}}), "not alerting"),
        (
            datadog_monitor(state={"groups": {"service:checkout-api-prod": {"status": "Warn"}}}),
            "the group is Warn",
        ),
    ],
    ids=["missing", "not-opted-in", "recovered", "group-gone", "warn-p2"],
)
def test_unverified_signals_are_dropped(monitor: Any, reason: str) -> None:
    verdict = _verify(monitor)
    assert not verdict.verified
    assert reason in str(verdict.reason)
    assert not verdict.misrouted


def test_warn_counts_for_priority_1() -> None:
    monitor = datadog_monitor(
        priority=1, state={"groups": {"service:checkout-api-prod": {"status": "Warn"}}}
    )
    assert _verify(monitor).verified


def test_monitor_of_another_env_is_misrouted() -> None:
    verdict = _verify(datadog_monitor(), env="staging")
    assert not verdict.verified
    assert verdict.misrouted
    assert verdict.reason == "the monitor's env is prod, not staging"


def test_signal_without_a_group_is_dropped() -> None:
    verdict = _verify(datadog_monitor(), _signal(tags=["env:prod"]))
    assert verdict.reason == "the notification names no group"


def test_group_order_does_not_matter() -> None:
    event = datadog_event(tags=["env:prod", "service:api", "region:us"])
    event["detail"]["meta"]["monitor"]["query"] = "avg:x{*} by {service,region} > 1"
    signal = parse_signal(event)
    assert signal is not None
    monitor = datadog_monitor(state={"groups": {"region:us,service:api": {"status": "Alert"}}})
    assert _verify(monitor, signal).verified


def test_simple_monitor_is_read_from_its_overall_state() -> None:
    event = datadog_event()
    event["detail"]["meta"]["monitor"]["query"] = "avg(last_5m):avg:x{env:prod} > 4"
    signal = parse_signal(event)
    assert signal is not None
    assert _verify(datadog_monitor(state={"groups": {}}), signal).verified
    clear_monitor_cache()
    assert not _verify(datadog_monitor(state={}, overall_state="OK"), signal).verified


def test_without_keys_nothing_is_read() -> None:
    verdict = verify_monitor(None, _signal(), "prod", 2)
    assert verdict.reason == "the Datadog keys are not configured"


def test_monitor_reads_are_cached_for_a_minute() -> None:
    client = FakeClient({"get_monitor": datadog_monitor()})
    clock = Clock()
    for _ in range(5):
        read_monitor(client, DATADOG_MONITOR_ID, clock)  # type: ignore[arg-type]
    assert len(client.calls) == 1
    clock.now += MONITOR_CACHE_SECONDS
    read_monitor(client, DATADOG_MONITOR_ID, clock)  # type: ignore[arg-type]
    assert len(client.calls) == 2


def test_a_missing_monitor_is_cached_too() -> None:
    client = FakeClient({"get_monitor": DatadogError("HTTP 404", 404)})
    clock = Clock()
    assert read_monitor(client, 1, clock) is None  # type: ignore[arg-type]
    assert read_monitor(client, 1, clock) is None  # type: ignore[arg-type]
    assert len(client.calls) == 1


def test_other_read_failures_raise_and_are_cached_for_30_seconds() -> None:
    client = FakeClient({"get_monitor": DatadogError("HTTP 500", 500)})
    clock = Clock()
    for _ in range(3):
        with pytest.raises(DatadogError) as raised:
            read_monitor(client, 1, clock)  # type: ignore[arg-type]
        assert raised.value.status == 500
    assert len(client.calls) == 1
    clock.now += FAILED_READ_CACHE_SECONDS
    with pytest.raises(DatadogError):
        read_monitor(client, 1, clock)  # type: ignore[arg-type]
    assert len(client.calls) == 2


def test_client_reads_one_monitor_with_a_get(mocker: MockerFixture) -> None:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(datadog_monitor()).encode()
    urlopen = mocker.patch.object(datadog_module.urllib.request, "urlopen", return_value=response)
    client = DatadogClient(site="datadoghq.com", api_key="api", app_key="app")
    assert client.get_monitor(monitor_id=42, params={"group_states": "alert,warn"})["id"]
    [call] = urlopen.call_args_list
    request = call.args[0]
    assert request.get_method() == "GET"
    assert request.full_url == (
        "https://api.datadoghq.com/api/v1/monitor/42?group_states=alert%2Cwarn"
    )


def test_client_error_carries_the_http_status(mocker: MockerFixture) -> None:
    failure = urllib.error.HTTPError("u", 404, "Not Found", None, None)  # type: ignore[arg-type]
    mocker.patch.object(datadog_module.urllib.request, "urlopen", side_effect=failure)
    client = DatadogClient(site="datadoghq.com", api_key="api", app_key="app")
    with pytest.raises(DatadogError) as raised:
        client.get_monitor(monitor_id=42, params={})
    assert raised.value.status == 404
    assert "api" not in str(raised.value).replace("Datadog monitor read", "")
