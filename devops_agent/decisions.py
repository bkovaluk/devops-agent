"""Triage decisions: one CloudWatch EMF metric and one structured log line each.

The metric is ``Decision`` (Count) in ``DevOpsAgent`` with the dimensions env,
source and decision, plus account when the deployment serves member accounts. The log
line always names the signal's account.
"""

from __future__ import annotations

from typing import Any, Literal

from aws_lambda_powertools import Logger
from aws_lambda_powertools.metrics import MetricUnit, single_metric

from devops_agent.models import SignalRef

logger = Logger(service="devops-agent", child=True)

METRICS_NAMESPACE = "DevOpsAgent"
DECISION_METRIC = "Decision"

Decision = Literal[
    "investigated",
    "linked",
    "cooldown",
    "deferred",
    "skipped_budget",
    "skipped_unverified",
    "storm_grouped",
    "opted_out",
    "skipped_account",
]


def record_decision(
    decision: Decision,
    env: str,
    signal: SignalRef,
    message: str,
    *,
    per_account: bool = False,
    **fields: Any,
) -> None:
    """One metric and one log line; ``per_account`` adds the account dimension."""
    with single_metric(
        name=DECISION_METRIC, unit=MetricUnit.Count, value=1, namespace=METRICS_NAMESPACE
    ) as metric:
        metric.add_dimension(name="env", value=env)
        metric.add_dimension(name="source", value=signal.source)
        metric.add_dimension(name="decision", value=decision)
        if per_account:
            metric.add_dimension(name="account", value=signal.account_id or "unknown")
    logger.info(
        message,
        extra={
            "decision": decision,
            "source": signal.source,
            "signal_name": signal.name,
            "priority": signal.priority,
            "account_id": signal.account_id,
            **fields,
        },
    )
