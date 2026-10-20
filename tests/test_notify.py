"""SNS publish for the Slack notifier."""

from __future__ import annotations

import json
from typing import Any

import pytest

from devops_agent.models import Effort, Evidence, Finding, FindingKind, Severity
from devops_agent.notify import build_payload, publish_finding, subject_for
from tests.conftest import ALARM_ARN, ALARM_NAME, FUNCTION_KEY, FakeClient, client_error

TOPIC = "arn:aws:sns:us-east-1:111122223333:ops-alerts-prod"
# The message fields a subscriber reads, and the Severity values.
ALERT_PAYLOAD_FIELDS = {
    "severity",
    "message",
    "service",
    "channel",
    "context",
    "blocks",
    "type",
    "ref_key",
}
NOTIFIER_SEVERITIES = {"critical", "error", "warning", "info"}


def _finding(severity: Severity, **overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "finding_id": "f-1",
        "created_at": "2026-09-29T14:05:00+00:00",
        "env": "prod",
        "alarm_name": ALARM_NAME,
        "alarm_arn": ALARM_ARN,
        "severity": severity,
        "severity_floor": Severity.HIGH,
        "proposed_severity": severity,
        "title": "Payment API 5xx after deploy",
        "summary": "Errors rose. <!channel> look",
        "likely_cause": "Bad deploy",
        "evidence": [Evidence(kind="log", detail=f"line {i}") for i in range(8)],
        "suggested_actions": ["deploy rollback payment-api-prod"],
        "fix_effort": Effort.LOW,
        "fix_effort_reason": "One rollback command.",
        "steps": 3,
        "model_id": "m",
        "outcome": "reported",
        "ttl": 1798553100,
        "resource_key": FUNCTION_KEY,
    }
    fields.update(overrides)
    return Finding(**fields)


@pytest.mark.parametrize("severity", [Severity.MEDIUM, Severity.LOW])
def test_medium_and_low_are_not_published(severity: Severity) -> None:
    sns = FakeClient()
    assert not publish_finding(sns, TOPIC, "#c", _finding(severity))
    assert sns.calls == []


@pytest.mark.parametrize(
    ("severity", "expected"), [(Severity.CRITICAL, "critical"), (Severity.HIGH, "error")]
)
def test_critical_and_high_are_published_as_alert_payload(
    severity: Severity, expected: str
) -> None:
    sns = FakeClient()
    assert publish_finding(sns, TOPIC, "#ops-alerts", _finding(severity))
    operation, call = sns.calls[0]
    assert operation == "publish"
    assert call["TopicArn"] == TOPIC
    assert len(call["Subject"]) <= 100
    payload = json.loads(call["Message"])
    assert set(payload) <= ALERT_PAYLOAD_FIELDS
    assert payload["severity"] == expected
    assert payload["severity"] in NOTIFIER_SEVERITIES
    assert payload["service"] == "devops-agent"
    assert payload["channel"] == "#ops-alerts"
    assert isinstance(payload["message"], str)
    assert isinstance(payload["blocks"], list)


def test_blocks_layout_and_escaping() -> None:
    blocks = build_payload(_finding(Severity.HIGH), "#c")["blocks"]
    assert blocks[0]["type"] == "header"
    assert blocks[0]["text"]["text"] == "PROD HIGH: Payment API 5xx after deploy"
    assert blocks[1] == {
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": "Effort low"}],
    }
    texts = [block["text"]["text"] for block in blocks[2:-1]]
    assert texts[0].startswith("*Summary*")
    assert "&lt;!channel&gt;" in texts[0]
    assert "<!channel>" not in json.dumps(blocks)
    evidence = next(text for text in texts if text.startswith("*Evidence*"))
    assert evidence.count("•") == 5
    assert any(text.startswith("*Suggested actions*\n1. deploy rollback") for text in texts)
    assert blocks[-1]["type"] == "context"


def test_subject_is_single_line_ascii_and_bounded() -> None:
    subject = subject_for(_finding(Severity.HIGH, title="Löng\ntitle " + "x" * 200))
    assert len(subject) <= 100
    assert "\n" not in subject
    assert subject.isascii()


def test_publish_failure_is_swallowed() -> None:
    sns = FakeClient({"publish": client_error("AuthorizationError")})
    assert not publish_finding(sns, TOPIC, "#c", _finding(Severity.CRITICAL))


def test_bare_urls_are_defanged() -> None:
    finding = _finding(
        Severity.HIGH,
        summary="See https://evil.example/x now",
        suggested_actions=["Open http://phish.example"],
    )
    blocks = json.dumps(build_payload(finding, "#c"))
    assert "://" not in blocks
    assert "https[:]//evil.example/x" in blocks
    assert "http[:]//phish.example" in blocks


def test_suggested_actions_are_capped() -> None:
    finding = _finding(Severity.HIGH, suggested_actions=[f"step {i}" for i in range(9)])
    blocks = build_payload(finding, "#c")["blocks"]
    actions = next(
        block["text"]["text"]
        for block in blocks
        if block.get("text", {}).get("text", "").startswith("*Suggested actions*")
    )
    assert "5. step 4" in actions
    assert "6." not in actions


def test_subject_escapes_mentions() -> None:
    subject = subject_for(_finding(Severity.HIGH, title="<!channel> down"))
    assert "<!channel>" not in subject
    assert "&lt;!channel&gt;" in subject


@pytest.mark.parametrize(
    ("effort", "expected"),
    [(Effort.LOW, "Effort low"), (Effort.VERY_HIGH, "Effort very high")],
)
def test_effort_is_a_labelled_fact_under_the_headline(effort: Effort, expected: str) -> None:
    blocks = build_payload(_finding(Severity.HIGH, fix_effort=effort), "#c")["blocks"]
    assert blocks[1]["elements"][0]["text"] == expected


def test_incident_headline_names_the_storm() -> None:
    sns = FakeClient()
    finding = _finding(Severity.HIGH, kind=FindingKind.INCIDENT)
    assert publish_finding(sns, TOPIC, "#c", finding, storm_size=7)
    [(_, call)] = sns.calls
    assert call["Subject"] == "[DevOps agent] PROD HIGH: Storm: 7 alarms in 60 s"
    payload = json.loads(call["Message"])
    assert payload["blocks"][0]["text"]["text"] == "PROD HIGH: Storm: 7 alarms in 60 s"
    assert payload["blocks"][2]["text"]["text"] == "*Payment API 5xx after deploy*"
    assert payload["message"].startswith("PROD HIGH: Storm: 7 alarms in 60 s. ")


def test_alarm_headline_is_the_title() -> None:
    blocks = build_payload(_finding(Severity.HIGH), "#c")["blocks"]
    assert blocks[0]["text"]["text"] == "PROD HIGH: Payment API 5xx after deploy"
    assert blocks[2]["text"]["text"].startswith("*Summary*")
