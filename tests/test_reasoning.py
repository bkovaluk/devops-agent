"""Visible reasoning: step labels, cited steps, hypotheses, confidence and trail args."""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from typing import Any

from devops_agent.agent import (
    MAX_ARG_CHARS,
    MAX_ARGS_BYTES,
    MAX_TOOL_RESULT_CHARS,
    REPORT_FINDING_SPEC,
    Investigation,
    ToolReply,
    investigate,
    system_prompt,
)
from devops_agent.config import Settings
from devops_agent.findings import build_finding, build_triage_finding
from devops_agent.models import (
    MAX_CONFIDENCE_REASON_CHARS,
    MAX_HYPOTHESES,
    MAX_HYPOTHESIS_CHARS,
    AlarmStateChangeEvent,
    FindingKind,
    ReportedFinding,
    Severity,
    SignalRef,
    ToolTrailStep,
)
from devops_agent.redact import REDACTED, redact_finding
from devops_agent.tools import ToolContext
from tests.conftest import (
    FakeBedrock,
    alarm_event,
    converse_response,
    job,
    report,
    tool_use,
)

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"


def _runner(text: str = '{"rows": [1]}') -> Any:
    def run(name: str, raw_input: Any, ctx: ToolContext) -> ToolReply:
        return ToolReply("success", text, returned_data=True)

    return run


def _result_texts(bedrock: FakeBedrock, call: int) -> list[str]:
    content = bedrock.calls[call]["messages"][-1]["content"]
    return [block["toolResult"]["content"][0]["text"] for block in content if "toolResult" in block]


def _investigate(
    tool_ctx: ToolContext, settings: Settings, bedrock: FakeBedrock, text: str = '{"rows": [1]}'
) -> Investigation:
    return investigate(
        bedrock, tool_ctx, settings, job(), "ctx", [], lambda: math.inf, run=_runner(text)
    )


def test_every_tool_result_is_labelled_with_its_trail_step(
    tool_ctx: ToolContext, settings: Settings
) -> None:
    bedrock = FakeBedrock(
        converse_response(
            tool_use("query_logs", {"log_group": "/aws/lambda/a", "query": "fields 1"}, "t1"),
            tool_use("recent_changes", {}, "t2"),
        ),
        converse_response(
            tool_use("get_metric", {"namespace": "AWS/Lambda", "metric_name": "Errors"}, "t3")
        ),
        converse_response(report()),
    )
    investigation = _investigate(tool_ctx, settings, bedrock)

    assert _result_texts(bedrock, 1) == ['[step 1]\n{"rows": [1]}', '[step 2]\n{"rows": [1]}']
    assert _result_texts(bedrock, 2) == ['[step 3]\n{"rows": [1]}']
    assert [(step.step, step.tool) for step in investigation.trail] == [
        (1, "query_logs"),
        (2, "recent_changes"),
        (3, "get_metric"),
    ]
    assert [call["output"] for call in investigation.calls] == ['{"rows": [1]}'] * 3


def test_a_labelled_result_keeps_the_size_cap(tool_ctx: ToolContext, settings: Settings) -> None:
    bedrock = FakeBedrock(
        converse_response(tool_use("recent_changes", {})), converse_response(report())
    )
    _investigate(tool_ctx, settings, bedrock, "x" * MAX_TOOL_RESULT_CHARS)

    [text] = _result_texts(bedrock, 1)
    assert text.startswith("[step 1]\nxxx")
    assert len(text) == MAX_TOOL_RESULT_CHARS


def _parsed(**overrides: Any) -> ReportedFinding:
    return ReportedFinding.model_validate(report(**overrides)["toolUse"]["input"])


def test_report_without_reasoning_fields_still_parses() -> None:
    parsed = _parsed()
    assert parsed.confidence is None
    assert parsed.confidence_reason is None
    assert parsed.hypotheses == []
    assert parsed.evidence[0].steps == []


def test_report_reasoning_fields_are_forgiving() -> None:
    hypotheses: list[Any] = [
        {"text": "h" * 300, "state": "maybe", "steps": [2, "3", True, 2, 1.5, 4]},
        {"text": "bad deploy", "state": "ruled_out"},
        "not a hypothesis",
        {"state": "likely"},
        {"text": "throttling", "state": "likely", "steps": "4"},
    ] + [{"text": f"extra {n}", "state": "unverified"} for n in range(10)]
    parsed = _parsed(
        confidence="certain",
        confidence_reason="r" * 500,
        hypotheses=hypotheses,
        evidence=[{"kind": "log", "detail": "boom", "steps": [1, "x", 1]}],
    )

    assert parsed.confidence is None
    assert parsed.confidence_reason == "r" * MAX_CONFIDENCE_REASON_CHARS
    assert len(parsed.hypotheses) == MAX_HYPOTHESES
    first, second, third = parsed.hypotheses[:3]
    assert first.text == "h" * MAX_HYPOTHESIS_CHARS
    assert first.state == "unverified"
    assert first.steps == [2, 4]
    assert (second.text, second.state, second.steps) == ("bad deploy", "ruled_out", [])
    assert (third.text, third.state, third.steps) == ("throttling", "likely", [])
    assert parsed.evidence[0].steps == [1]


def test_report_with_unusable_hypotheses_and_reason_keeps_the_finding() -> None:
    parsed = _parsed(confidence="low", confidence_reason=42, hypotheses="two of them")
    assert parsed.confidence == "low"
    assert parsed.confidence_reason is None
    assert parsed.hypotheses == []


def _trail(*steps: int) -> tuple[ToolTrailStep, ...]:
    return tuple(
        ToolTrailStep(step=step, tool="query_logs", status="data", input="{}") for step in steps
    )


def test_reported_finding_carries_reasoning_citing_only_trail_steps() -> None:
    body = _parsed(
        confidence="medium",
        confidence_reason=f"Logs show it, key {ACCESS_KEY} aside.",
        hypotheses=[
            {"text": "bad deploy", "state": "likely", "steps": [1, 9]},
            {"text": f"leaked {ACCESS_KEY}", "state": "ruled_out", "steps": [2]},
        ],
        evidence=[
            {"kind": "log", "detail": "KeyError", "steps": [2, 0, 51]},
            {"kind": "alarm", "detail": "from the bundle"},
        ],
    )
    investigation = Investigation(
        "reported", body, 3, "model-a", ("query_logs", "query_logs"), trail=_trail(1, 2)
    )
    finding = redact_finding(
        build_finding(env="prod", job=job(), investigation=investigation, now=NOW)
    )

    assert finding.confidence == "medium"
    assert finding.confidence_reason == f"Logs show it, key {REDACTED} aside."
    assert [(h.text, h.state, h.steps) for h in finding.hypotheses] == [
        ("bad deploy", "likely", [1]),
        (f"leaked {REDACTED}", "ruled_out", [2]),
    ]
    assert [item.steps for item in finding.evidence] == [[2], []]


def test_incomplete_finding_has_no_confidence_or_hypotheses() -> None:
    investigation = Investigation("incomplete", None, 14, "model-a", (), trail=_trail(1))
    finding = build_finding(env="prod", job=job(), investigation=investigation, now=NOW)
    assert finding.confidence is None
    assert finding.confidence_reason is None
    assert finding.hypotheses == []


def test_triage_finding_has_no_confidence_or_hypotheses() -> None:
    finding = build_triage_finding(
        env="prod",
        kind=FindingKind.GROUPED,
        signal=SignalRef.for_alarm(
            AlarmStateChangeEvent.model_validate(alarm_event()), Severity.HIGH
        ),
        resource_key="lambda#x",
        floor=Severity.LOW,
        now=NOW,
        title="Grouped",
        summary="Part of a storm.",
    )
    assert finding.confidence is None
    assert finding.confidence_reason is None
    assert finding.hypotheses == []


def _args_of(tool_ctx: ToolContext, settings: Settings, tool_input: Any) -> dict[str, Any]:
    bedrock = FakeBedrock(
        converse_response(tool_use("query_logs", tool_input)), converse_response(report())
    )
    return _investigate(tool_ctx, settings, bedrock).trail[0].args


def test_trail_args_are_redacted_and_cut(tool_ctx: ToolContext, settings: Settings) -> None:
    args = _args_of(
        tool_ctx,
        settings,
        {
            "log_group": "/aws/lambda/a",
            "query": f"filter @message like /{ACCESS_KEY}/ " + "x" * 400,
            "minutes": 30,
            "dimensions": [{"Name": "FunctionName", "Value": f"token={ACCESS_KEY}"}],
        },
    )

    assert args["log_group"] == "/aws/lambda/a"
    assert args["minutes"] == 30
    assert len(args["query"]) == MAX_ARG_CHARS
    assert ACCESS_KEY not in json.dumps(args)
    assert args["dimensions"] == [{"Name": "FunctionName", "Value": f"token={REDACTED}"}]


def test_trail_args_flatten_past_depth_three(tool_ctx: ToolContext, settings: Settings) -> None:
    args = _args_of(tool_ctx, settings, {"a": {"b": {"c": {"d": 1}}}})
    assert args == {"a": {"b": {"c": '{"d": 1}'}}}


def test_trail_args_drop_keys_past_the_size_cap(tool_ctx: ToolContext, settings: Settings) -> None:
    tool_input = {f"k{n}": "v" * 250 for n in range(10)}
    args = _args_of(tool_ctx, settings, tool_input)

    assert len(json.dumps(args).encode()) <= MAX_ARGS_BYTES
    assert 0 < len(args) < len(tool_input)
    assert list(args) == [f"k{n}" for n in range(len(args))]


def test_trail_args_of_a_non_object_input_are_empty(
    tool_ctx: ToolContext, settings: Settings
) -> None:
    assert _args_of(tool_ctx, settings, ["not", "an", "object"]) == {}


def test_prompt_asks_for_hypothesis_states_citations_and_calibrated_confidence() -> None:
    prompt = system_prompt(set())
    assert "state 2 to 4 hypotheses" in prompt
    assert "Each tool result starts with a [step N] line" in prompt
    assert "keeping the ruled-out ones" in prompt
    assert "one-sentence confidence_reason" in prompt
    assert 'When confidence is low, hedge the title and likely_cause ("possibly"' in prompt


def test_report_finding_schema_offers_the_reasoning_fields() -> None:
    schema = REPORT_FINDING_SPEC["toolSpec"]["inputSchema"]["json"]
    properties = schema["properties"]
    assert properties["confidence"]["enum"] == ["high", "medium", "low"]
    assert properties["confidence_reason"]["maxLength"] == MAX_CONFIDENCE_REASON_CHARS
    assert properties["hypotheses"]["maxItems"] == MAX_HYPOTHESES
    hypothesis = properties["hypotheses"]["items"]["properties"]
    assert hypothesis["state"]["enum"] == ["likely", "ruled_out", "unverified"]
    assert hypothesis["steps"]["items"] == {"type": "integer"}
    assert properties["evidence"]["items"]["properties"]["steps"]["items"] == {"type": "integer"}
    assert not {"confidence", "confidence_reason", "hypotheses"} & set(schema["required"])
