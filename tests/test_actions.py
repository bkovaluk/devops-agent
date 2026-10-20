"""Checked facts, typed actions and the run summary on a finding."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from devops_agent.agent import REPORT_FINDING_SPEC, Investigation, system_prompt
from devops_agent.findings import build_finding, build_triage_finding, to_item
from devops_agent.models import (
    MAX_ACTION_COMMAND_CHARS,
    MAX_ACTION_DETAIL_CHARS,
    MAX_ACTION_TEXT_CHARS,
    MAX_ACTIONS,
    MAX_CHECKED,
    MAX_CHECKED_CHARS,
    AlarmStateChangeEvent,
    FindingKind,
    ReportedFinding,
    RunSummary,
    Severity,
    SignalRef,
    ToolTrailStep,
)
from tests.conftest import alarm_event, job, report

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
RUN = RunSummary(
    stop_reason="chose",
    turns=3,
    max_turns=14,
    duration_seconds=41.7,
    weighted_tokens=52_000,
    token_budget=250_000,
)


def _input(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = report(**overrides)["toolUse"]["input"]
    return body


def _parsed(**overrides: Any) -> ReportedFinding:
    return ReportedFinding.model_validate(_input(**overrides))


def _trail(*steps: int) -> tuple[ToolTrailStep, ...]:
    return tuple(
        ToolTrailStep(step=step, tool="describe_database", status="data", input="{}")
        for step in steps
    )


def test_report_schema_requires_typed_actions() -> None:
    schema = REPORT_FINDING_SPEC["toolSpec"]["inputSchema"]["json"]
    properties = schema["properties"]
    assert "actions" in schema["required"]
    assert "suggested_actions" not in properties
    actions = properties["actions"]
    assert actions["maxItems"] == MAX_ACTIONS
    action = actions["items"]["properties"]
    assert action["kind"]["enum"] == ["change", "code", "read", "approval"]
    assert action["text"]["maxLength"] == MAX_ACTION_TEXT_CHARS
    assert action["detail"]["maxLength"] == MAX_ACTION_DETAIL_CHARS
    assert action["command"]["maxLength"] == MAX_ACTION_COMMAND_CHARS
    assert actions["items"]["required"] == ["kind", "text"]
    checked = properties["checked"]
    assert checked["maxItems"] == MAX_CHECKED
    assert checked["items"]["properties"]["text"]["maxLength"] == MAX_CHECKED_CHARS
    assert checked["items"]["properties"]["steps"]["items"] == {"type": "integer"}
    assert "checked" not in schema["required"]


def test_report_without_actions_is_invalid() -> None:
    body = _input()
    del body["actions"]
    with pytest.raises(ValidationError):
        ReportedFinding.model_validate(body)


def test_suggested_actions_alone_become_change_actions() -> None:
    body = _input()
    del body["actions"]
    parsed = ReportedFinding.model_validate(
        {**body, "suggested_actions": ["Redrive the DLQ", 7, "Scale the service"]}
    )
    assert [(action.kind, action.text) for action in parsed.actions] == [
        ("change", "Redrive the DLQ"),
        ("change", "Scale the service"),
    ]


def test_actions_win_over_suggested_actions() -> None:
    parsed = _parsed(suggested_actions=["old"])
    assert [action.text for action in parsed.actions] == ["Roll back the Lambda"]


def test_actions_are_clamped_and_unknown_kinds_become_change() -> None:
    actions: list[Any] = [
        {
            "kind": "restart",
            "text": "t" * 300,
            "detail": "d" * 500,
            "command": "c" * 600,
        },
        {"kind": "read", "text": "Read the DLQ message body", "detail": 3, "command": ""},
        "not an action",
        {"kind": "code"},
    ] + [{"kind": "approval", "text": f"extra {n}"} for n in range(10)]
    parsed = _parsed(actions=actions)
    assert len(parsed.actions) == MAX_ACTIONS
    first, second = parsed.actions[:2]
    assert first.kind == "change"
    assert first.text == "t" * MAX_ACTION_TEXT_CHARS
    assert first.detail == "d" * MAX_ACTION_DETAIL_CHARS
    assert first.command == "c" * MAX_ACTION_COMMAND_CHARS
    assert (second.kind, second.detail, second.command) == ("read", None, None)


def test_checked_facts_are_clamped_and_capped() -> None:
    checked: list[Any] = [
        {"text": "x" * 400, "steps": [1, "2", 1, True]},
        {"steps": [1]},
        "a fact",
    ] + [{"text": f"fact {n}", "steps": [n]} for n in range(10)]
    parsed = _parsed(checked=checked)
    assert len(parsed.checked) == MAX_CHECKED
    assert parsed.checked[0].text == "x" * MAX_CHECKED_CHARS
    assert parsed.checked[0].steps == [1]
    assert _parsed().checked == []


def test_finding_keeps_checked_steps_on_the_trail_and_derives_suggested_actions() -> None:
    body = _parsed(
        checked=[
            {"text": "The DLQ holds 12 messages, all from 03:10", "steps": [1, 7]},
            {"text": "No deploy in the last day", "steps": []},
        ],
        actions=[
            {
                "kind": "change",
                "text": "Redrive the DLQ",
                "command": "aws sqs start-message-move-task --source-arn arn:dlq",
            },
            {"kind": "approval", "text": "Ask the payments owner to sign off"},
        ],
    )
    investigation = Investigation(
        "reported", body, 2, "model-a", ("describe_database",), trail=_trail(1), run=RUN
    )
    finding = build_finding(env="prod", job=job(), investigation=investigation, now=NOW)

    assert [(item.text, item.steps) for item in finding.checked] == [
        ("The DLQ holds 12 messages, all from 03:10", [1]),
        ("No deploy in the last day", []),
    ]
    assert [action.kind for action in finding.actions] == ["change", "approval"]
    assert finding.suggested_actions == [
        "Redrive the DLQ: aws sqs start-message-move-task --source-arn arn:dlq",
        "Ask the payments owner to sign off",
    ]
    item = to_item(finding)
    assert item["actions"][1] == {
        "kind": "approval",
        "text": "Ask the payments owner to sign off",
        "detail": None,
        "command": None,
    }
    assert item["checked"][0] == {"text": "The DLQ holds 12 messages, all from 03:10", "steps": [1]}


def test_finding_stores_the_run_summary() -> None:
    investigation = Investigation(
        "reported", _parsed(), 3, "model-a", (), weighted_tokens=52_000, run=RUN
    )
    finding = build_finding(env="prod", job=job(), investigation=investigation, now=NOW)
    run = to_item(finding)["run"]
    assert run["stop_reason"] == "chose"
    assert (run["turns"], run["max_turns"]) == (3, 14)
    assert (run["weighted_tokens"], run["token_budget"]) == (52_000, 250_000)
    assert float(run["duration_seconds"]) == 41.7


def test_incomplete_finding_keeps_its_run_and_a_read_action() -> None:
    run = RUN.model_copy(update={"stop_reason": "no_report"})
    investigation = Investigation("incomplete", None, 14, "model-a", (), run=run)
    finding = build_finding(env="prod", job=job(), investigation=investigation, now=NOW)
    assert finding.run is not None and finding.run.stop_reason == "no_report"
    assert [action.kind for action in finding.actions] == ["read"]
    assert finding.suggested_actions == [finding.actions[0].text]


def test_triage_finding_has_no_run_or_actions() -> None:
    finding = build_triage_finding(
        env="prod",
        kind=FindingKind.DEFERRED,
        signal=SignalRef.for_alarm(
            AlarmStateChangeEvent.model_validate(alarm_event()), Severity.HIGH
        ),
        resource_key="lambda#x",
        floor=Severity.LOW,
        now=NOW,
        title="Deferred",
        summary="Over budget.",
    )
    assert finding.run is None
    assert finding.actions == []
    assert finding.checked == []


def test_prompt_keeps_reads_with_the_agent() -> None:
    prompt = " ".join(system_prompt(set()).split())
    assert "Never ask a person to run a read you can run or already ran." in prompt
    assert "list what you verified in checked, each with its steps" in prompt
    assert "Suggest actions as text only" not in prompt
