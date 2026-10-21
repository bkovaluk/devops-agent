"""Write the example findings-table items in docs/examples.

Each file is exactly the item the agent stores (findings.to_item), built by the same
builders the investigator and triage use, from synthetic signals. Run `just examples`
after changing a finding field, then review the diff.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from devops_agent.agent import Investigation, ToolReply, _trail_step
from devops_agent.findings import build_finding, build_triage_finding, to_item
from devops_agent.models import (
    AlarmStateChangeEvent,
    ContextSummary,
    Finding,
    FindingKind,
    InvestigationJob,
    ReportedFinding,
    RunSummary,
    Severity,
    SignalRef,
    ToolTrailStep,
    scoped_key,
)

ENV = "prod"
REGION = "us-east-1"
TOOLING = "210987654321"
MEMBER = "345678901234"
MODEL_ID = "us.anthropic.claude-opus-5-5"
ROLE_ARN = f"arn:aws:iam::{MEMBER}:role/devops-agent-read"
FIRED = datetime(2026, 10, 14, 13, 2, 11, tzinfo=UTC)
CHECKOUT_KEY = "AWS/Lambda:FunctionName=checkout-api-prod"
ORDERS_KEY = "AWS/SQS:QueueName=orders-prod"
INVOICES_KEY = "AWS/Lambda:FunctionName=invoice-render-prod"
SEARCH_KEY = "AWS/ES:DomainName=catalog-search"
CART_KEY = "AWS/ECS:ServiceName=cart-web"
REPORTED_ID = "5b0c1f9e-3c1a-5f7e-9a64-2f0d7b1c8e01"
INCIDENT_ID = "f1a3c5e7-9b2d-5f40-8c6e-1a3b5c7d9e20"
THRESHOLD = "Threshold Crossed: 1 datapoint was greater than or equal to the threshold."

CONTEXT = ContextSummary(
    sections={
        "alarm": "available",
        "metric": "available",
        "log_sources": "available",
        "log_patterns": "available",
        "changes": "available",
        "siblings": "available",
        "database_events": "not_applicable",
        "instance": "not_applicable",
        "service_notes": "available",
        "sources_last_time": "available",
    },
    counts={
        "metric": 60,
        "log_sources": 1,
        "log_patterns": 4,
        "changes": 2,
        "siblings": 1,
        "service_notes": 2,
        "sources_last_time": 3,
    },
    chars=8412,
    truncated=False,
)


def _alarm(name: str, account: str, reason: str = THRESHOLD) -> AlarmStateChangeEvent:
    return AlarmStateChangeEvent.model_validate(
        {
            "detail-type": "CloudWatch Alarm State Change",
            "account": account,
            "region": REGION,
            "time": FIRED.isoformat(),
            "resources": [f"arn:aws:cloudwatch:{REGION}:{account}:alarm:{name}"],
            "detail": {
                "alarmName": name,
                "state": {"value": "ALARM", "reason": reason, "timestamp": FIRED.isoformat()},
            },
        }
    )


def _signal(name: str, account: str, floor: Severity) -> SignalRef:
    return SignalRef.for_alarm(_alarm(name, account), floor)


def _job(
    finding_id: str,
    events: list[AlarmStateChangeEvent],
    keys: list[str],
    floor: Severity,
    kind: FindingKind = FindingKind.ALARM,
) -> InvestigationJob:
    return InvestigationJob(
        finding_id=finding_id,
        kind=kind,
        alarms=events,
        alarm_count=len(events),
        keys=keys,
        floor=floor,
    )


def _trail(*calls: tuple[str, dict[str, Any], str]) -> tuple[ToolTrailStep, ...]:
    """Trail steps as the investigator records them, from (tool, input, status)."""
    return tuple(
        _trail_step(
            step,
            tool,
            tool_input,
            ToolReply(
                "error" if status == "error" else "success", "", returned_data=status == "data"
            ),
        )
        for step, (tool, tool_input, status) in enumerate(calls, start=1)
    )


def _run(stop_reason: str, turns: int, seconds: float, weighted: int) -> RunSummary:
    return RunSummary.model_validate(
        {
            "stop_reason": stop_reason,
            "turns": turns,
            "max_turns": 14,
            "duration_seconds": seconds,
            "weighted_tokens": weighted,
            "token_budget": 250_000,
        }
    )


def _investigation(
    report: ReportedFinding | None,
    trail: tuple[ToolTrailStep, ...],
    tokens: int,
    run: RunSummary,
) -> Investigation:
    return Investigation(
        outcome="incomplete" if report is None else "reported",
        report=report,
        steps=run.turns,
        model_id=MODEL_ID,
        tool_calls=tuple(step.tool for step in trail),
        trail=trail,
        tokens_used=tokens,
        weighted_tokens=run.weighted_tokens,
        run=run,
    )


CHECKOUT_REPORT = {
    "title": "checkout-api fails on carts without a currency since the 12:58 deploy",
    "summary": (
        "Errors on checkout-api-prod rose from 0 to 37 a minute at 13:01, three minutes "
        "after version 214 was deployed. Every failing invocation raises KeyError: "
        "'currency' in pricing.py, where the new code reads cart['currency'], which carts "
        "created before the field existed do not carry."
    ),
    "likely_cause": (
        "Version 214 reads cart['currency'] without a default; older carts have no such key."
    ),
    "evidence": [
        {
            "kind": "metric",
            "detail": "Errors went from 0 to 37 per minute at 13:01 UTC.",
            "steps": [1],
        },
        {
            "kind": "log",
            "detail": "KeyError: 'currency' at checkout/pricing.py line 91 in all "
            "20 recent error lines.",
            "steps": [2],
        },
        {
            "kind": "change",
            "detail": "UpdateFunctionCode and PublishVersion 214 on "
            "checkout-api-prod at 12:58 UTC by the deploy role.",
            "steps": [3],
        },
        {
            "kind": "code",
            "detail": "pricing.py line 91 reads cart['currency'] with no default.",
            "steps": [5],
        },
    ],
    "checked": [
        {
            "text": "No queue or stream feeds the function, so no failed message waits to be "
            "redriven.",
            "steps": [4],
        },
        {
            "text": "The errors start within three minutes of the deploy, and no other change in "
            "the window touches the function.",
            "steps": [1, 3],
        },
    ],
    "actions": [
        {
            "kind": "change",
            "text": "Point the live alias back to version 213",
            "command": "aws lambda update-alias --function-name checkout-api-prod "
            "--name live --function-version 213",
        },
        {
            "kind": "code",
            "text": "Default the currency in pricing.py when a cart has none",
            "detail": "Read cart.get('currency', store.default_currency) at line 91 and add a "
            "test with a cart created before the field existed.",
        },
    ],
    "severity": "high",
    "fix_effort": "low",
    "fix_effort_reason": "A rollback restores service; the code fix is one line.",
    "error_signature": "KeyError: 'currency' at checkout/pricing.py:91",
    "confidence": "high",
    "confidence_reason": "The error, the line and the deploy time agree.",
    "hypotheses": [
        {
            "text": "Version 214 broke pricing for carts without a currency",
            "state": "likely",
            "steps": [2, 3, 5],
        },
        {"text": "A downstream dependency is failing", "state": "ruled_out", "steps": [2]},
        {"text": "A queue is replaying bad messages", "state": "ruled_out", "steps": [4]},
    ],
}


def reported() -> Finding:
    job = _job(
        REPORTED_ID,
        [_alarm("checkout-api-errors-prod", MEMBER)],
        [scoped_key(CHECKOUT_KEY, MEMBER)],
        Severity.HIGH,
    )
    trail = _trail(
        (
            "get_metric",
            {
                "namespace": "AWS/Lambda",
                "metric_name": "Errors",
                "dimensions": {"FunctionName": "checkout-api-prod"},
                "stat": "Sum",
                "minutes": 90,
            },
            "data",
        ),
        (
            "query_logs",
            {
                "log_group": "/aws/lambda/checkout-api-prod",
                "query": "fields @timestamp, @message | filter @message like /Error/ "
                "| sort @timestamp desc | limit 20",
            },
            "data",
        ),
        ("recent_changes", {"minutes": 120}, "data"),
        (
            "aws_call",
            {
                "service": "lambda",
                "operation": "list_event_source_mappings",
                "params": {"FunctionName": "checkout-api-prod"},
            },
            "empty",
        ),
        (
            "github_get_file",
            {"repo": "checkout-api", "path": "checkout/pricing.py", "line": 91, "context": 20},
            "data",
        ),
    )
    return build_finding(
        env=ENV,
        job=job,
        investigation=_investigation(
            ReportedFinding.model_validate(CHECKOUT_REPORT),
            trail,
            96_480,
            _run("chose", 7, 84.6, 61_230),
        ),
        now=FIRED + timedelta(minutes=3),
        context_summary=CONTEXT,
        previous_finding_id="0e6f2d4a-8b7c-5d1e-a3f9-6c2b4e8d1a70",
        prior_finding_ids=["0e6f2d4a-8b7c-5d1e-a3f9-6c2b4e8d1a70"],
    )


def incomplete() -> Finding:
    job = _job(
        "8d2a6c41-7e3b-5a90-b1f4-3e9c0d5a7b22",
        [_alarm("orders-queue-age-prod", TOOLING)],
        [ORDERS_KEY],
        Severity.MEDIUM,
    )
    trail = _trail(
        (
            "get_metric",
            {
                "namespace": "AWS/SQS",
                "metric_name": "ApproximateAgeOfOldestMessage",
                "dimensions": {"QueueName": "orders-prod"},
                "stat": "Maximum",
            },
            "data",
        ),
        ("recent_changes", {"minutes": 180}, "empty"),
    )
    return build_finding(
        env=ENV,
        job=job,
        investigation=_investigation(None, trail, 38_910, _run("time", 4, 868.2, 24_400)),
        now=FIRED + timedelta(minutes=15),
        context_summary=CONTEXT,
    )


def account_refused() -> Finding:
    job = _job(
        "c47e9b10-2d6f-5e83-9a1c-7f0b3d2e6a94",
        [_alarm("invoice-render-errors-prod", MEMBER)],
        [scoped_key(INVOICES_KEY, MEMBER)],
        Severity.MEDIUM,
    )
    return build_finding(
        env=ENV,
        job=job,
        investigation=Investigation("incomplete", None, 0, MODEL_ID, ()),
        now=FIRED + timedelta(seconds=40),
        error=f"AccountAccessError: AssumeRole of {ROLE_ARN} failed (AccessDenied)",
    )


def incident() -> Finding:
    members = [
        ("catalog-search-red-prod", SEARCH_KEY),
        ("checkout-api-errors-prod", CHECKOUT_KEY),
        ("cart-web-5xx-prod", CART_KEY),
        ("orders-queue-age-prod", ORDERS_KEY),
        ("invoice-render-errors-prod", INVOICES_KEY),
    ]
    job = _job(
        INCIDENT_ID,
        [_alarm(name, MEMBER) for name, _ in members],
        [scoped_key(key, MEMBER) for _, key in members],
        Severity.CRITICAL,
        FindingKind.INCIDENT,
    )
    trail = _trail(
        ("recent_changes", {"minutes": 60}, "data"),
        ("describe_search_domain", {"domain_name": "catalog-search"}, "data"),
    )
    report = ReportedFinding.model_validate(
        {
            "title": "Five services failed together when catalog-search went red",
            "summary": (
                "catalog-search lost a data node at 13:00 and went red; checkout, cart, "
                "orders and invoices all read it and failed within two minutes."
            ),
            "likely_cause": "Two primaries of catalog-search had no replica when a data node "
            "was replaced.",
            "evidence": [
                {
                    "kind": "resource",
                    "detail": "Cluster health red, 2 unassigned primaries.",
                    "steps": [2],
                },
                {
                    "kind": "change",
                    "detail": "No deploy in the hour before the storm.",
                    "steps": [1],
                },
            ],
            "checked": [
                {
                    "text": "catalog-search is the only dependency all five services share.",
                    "steps": [],
                },
            ],
            "actions": [
                {"kind": "change", "text": "Set catalog-search indices to 1 replica once green"},
            ],
            "severity": "critical",
            "fix_effort": "medium",
            "fix_effort_reason": "Replica settings and an index restore, about a day.",
            "confidence": "medium",
            "confidence_reason": "The timing fits; the node replacement is inferred.",
            "hypotheses": [
                {"text": "One shared dependency failed", "state": "likely", "steps": [2]},
                {"text": "A shared deploy broke them", "state": "ruled_out", "steps": [1]},
            ],
        }
    )
    return build_finding(
        env=ENV,
        job=job,
        investigation=_investigation(report, trail, 71_200, _run("chose", 4, 61.3, 45_900)),
        now=FIRED + timedelta(minutes=2),
        context_summary=CONTEXT,
    )


def _triage(**fields: Any) -> Finding:
    return build_triage_finding(env=ENV, now=FIRED + timedelta(seconds=30), **fields)


def skipped() -> Finding:
    signal = _signal("batch-export-duration-prod", TOOLING, Severity.LOW)
    return _triage(
        kind=FindingKind.SKIPPED,
        signal=signal,
        resource_key="AWS/Lambda:FunctionName=batch-export-prod",
        floor=Severity.LOW,
        finding_id="2a4c6e80-1b3d-5f57-9c2e-4a6b8c0d2e46",
        title=f"Skipped: {signal.name}",
        summary=f"{signal.name} {signal.fired} and was not investigated: opted out by tag.",
    )


def linked() -> Finding:
    signal = _signal("checkout-api-throttles-prod", MEMBER, Severity.MEDIUM)
    key = scoped_key(CHECKOUT_KEY, MEMBER)
    return _triage(
        kind=FindingKind.LINKED,
        signal=signal,
        resource_key=key,
        floor=Severity.MEDIUM,
        finding_id="6e8a0c24-5f7b-5d91-a3c6-8e0a2c4e6a81",
        linked_to=REPORTED_ID,
        title=f"Linked: {signal.name}",
        summary=(
            f"{signal.name} {signal.fired} while investigation {REPORTED_ID} covered {key}; "
            "it is recorded on that finding."
        ),
    )


def grouped() -> Finding:
    signal = _signal("cart-web-5xx-prod", MEMBER, Severity.HIGH)
    return _triage(
        kind=FindingKind.GROUPED,
        signal=signal,
        resource_key=scoped_key(CART_KEY, MEMBER),
        floor=Severity.HIGH,
        finding_id="9c1e3a57-2b4d-5c68-8e0f-a2c4e6f8a0b3",
        incident_id=INCIDENT_ID,
        title=f"Grouped: {signal.name}",
        summary=(
            f"{signal.name} {signal.fired} in a storm of 5 alarms, recorded together as "
            f"incident {INCIDENT_ID}."
        ),
    )


def storm() -> Finding:
    signal = _signal("catalog-search-red-prod", MEMBER, Severity.CRITICAL)
    head_key = scoped_key(SEARCH_KEY, MEMBER)
    head_job = "d3f5b7c9-0e2a-5b46-9d8f-b1c3e5a7c9d1"
    finding = _triage(
        kind=FindingKind.STORM,
        signal=signal,
        resource_key=head_key,
        floor=Severity.CRITICAL,
        finding_id="b7d9f1a3-4c6e-5a28-b0d2-e4f6a8c0e2f5",
        linked_to=head_job,
        alarm_count=1,
        source_counts={"cloudwatch": 1},
        resource_counts={head_key: 1},
        title="Storm: more than 30 signals per 5 minutes",
        summary=(
            "Signals arrived faster than 30 per 5 minutes for two buckets in a row. "
            f"{signal.name} is investigated as {head_job}; priority 1 and 2 signals still go "
            "through the budgets, the rest are counted here until the rate falls."
        ),
    )
    # The counts as they stand after 40 grouped signals, each added by storm.count_on_storm.
    return finding.model_copy(
        update={
            "alarm_count": 41,
            "source_counts": {"cloudwatch": 38, "datadog": 3},
            "resource_counts": {
                head_key: 9,
                scoped_key(CART_KEY, MEMBER): 14,
                scoped_key(CHECKOUT_KEY, MEMBER): 11,
                scoped_key(ORDERS_KEY, MEMBER): 7,
            },
            "last_seen_at": (FIRED + timedelta(minutes=9)).isoformat(),
        }
    )


def over_budget() -> Finding:
    signal = _signal("image-resize-duration-prod", TOOLING, Severity.MEDIUM)
    reason = "the rest of the hourly budget is kept for priority 1 and 2"
    return _triage(
        kind=FindingKind.SKIPPED,
        signal=signal,
        resource_key="AWS/Lambda:FunctionName=image-resize-prod",
        floor=Severity.MEDIUM,
        finding_id="4c6e8a02-3d5f-5b79-a1c3-6e8a0c2e4a68",
        title=f"Skipped: {signal.name}",
        summary=(
            f"The {signal.name} {signal.fired} and was not investigated: over budget, {reason}."
        ),
    )


def datadog() -> Finding:
    signal = SignalRef(
        source="datadog",
        name="cart-web p95 latency (service:cart-web)",
        subject="cart-web p95 latency",
        observed_at=FIRED.isoformat(),
        priority=2,
        account_id=MEMBER,
        region=REGION,
        ref={
            "monitor_id": 81234567,
            "group": "service:cart-web",
            "group_tags": ["service:cart-web"],
            "query": "avg(last_5m):p95:trace.http.request{env:prod,service:cart-web} > 1.5",
            "monitor_type": "query alert",
            "monitor_tags": [
                "env:prod",
                "devops_agent:true",
                "source:ecs",
                "service:cart-web",
                f"aws_account:{MEMBER}",
            ],
            "event_tags": ["env:prod", "service:cart-web"],
            "source_state": "OK",
            "dest_state": "Alert",
            "transition": "Triggered",
        },
    )
    reason = "the Datadog share of the hourly budget is spent"
    return _triage(
        kind=FindingKind.DEFERRED,
        signal=signal,
        resource_key=scoped_key(CART_KEY, MEMBER),
        floor=Severity.HIGH,
        finding_id="e5a7c9e1-6f8b-5d0a-b2c4-f6a8c0e2a4c7",
        title=f"Deferred: {signal.name}",
        summary=f"The {signal.name} {signal.fired} and was not investigated: {reason}.",
    )


EXAMPLES = {
    "finding-reported.json": reported,
    "finding-incomplete.json": incomplete,
    "finding-account-refused.json": account_refused,
    "finding-incident.json": incident,
    "finding-skipped.json": skipped,
    "finding-linked.json": linked,
    "finding-grouped.json": grouped,
    "finding-storm.json": storm,
    "finding-deferred-skipped.json": over_budget,
    "finding-datadog.json": datadog,
}


def _number(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def render(finding: Finding) -> str:
    """The stored item as stable JSON: keys sorted, two-space indent, newline-terminated."""
    return json.dumps(to_item(finding), default=_number, indent=2, sort_keys=True) + "\n"


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, build in EXAMPLES.items():
        (out_dir / name).write_text(render(build()))


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/examples"))
