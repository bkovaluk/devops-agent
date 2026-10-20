"""Severity floor and final severity."""

from __future__ import annotations

import pytest

from devops_agent.models import Severity
from devops_agent.severity import alarm_tags, final_severity, notifies, severity_floor
from tests.conftest import ALARM_ARN, FakeClient, set_environment


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ("prod", Severity.HIGH),
        ("staging", Severity.MEDIUM),
        ("qa", Severity.LOW),
        ("dev", Severity.LOW),
    ],
)
def test_floor_without_tag_is_the_catalog_default_for_the_env(
    monkeypatch: pytest.MonkeyPatch, env: str, expected: Severity
) -> None:
    set_environment(monkeypatch, env)
    assert severity_floor({}) is expected


@pytest.mark.parametrize("value", ["critical", "CRITICAL", " Critical "])
def test_floor_from_severity_tag_is_case_insensitive(value: str) -> None:
    assert severity_floor({"Severity": value}) is Severity.CRITICAL
    assert severity_floor({"severity": value}) is Severity.CRITICAL


def test_tag_can_set_floor_below_env_default() -> None:
    assert severity_floor({"Severity": "low"}) is Severity.LOW


def test_unknown_tag_value_falls_back_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    set_environment(monkeypatch, "staging")
    assert severity_floor({"Severity": "sev1"}) is Severity.MEDIUM


def test_model_cannot_lower_floor() -> None:
    assert final_severity(Severity.HIGH, Severity.LOW) is Severity.HIGH
    assert final_severity(Severity.HIGH, None) is Severity.HIGH


def test_model_can_raise_floor() -> None:
    assert final_severity(Severity.LOW, Severity.CRITICAL) is Severity.CRITICAL


def test_only_critical_and_high_notify() -> None:
    assert [level for level in Severity if notifies(level)] == [Severity.CRITICAL, Severity.HIGH]


def test_alarm_tags_reads_list_tags_for_resource() -> None:
    cloudwatch = FakeClient(
        {"list_tags_for_resource": {"Tags": [{"Key": "Severity", "Value": "high"}]}}
    )
    assert alarm_tags(cloudwatch, ALARM_ARN) == {"Severity": "high"}
    assert cloudwatch.calls == [("list_tags_for_resource", {"ResourceARN": ALARM_ARN})]
