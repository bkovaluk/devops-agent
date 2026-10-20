"""Replay a captured investigation against the real model with recorded tool results.

The context bundle comes from the snapshot instead of the precheck, and each tool call
is answered with the result recorded for the same tool and the same normalized input.
Failing that, it gets the result of the closest recorded call of the same tool on the
same resource and counts as approximate. A call with neither, or of a tool that does not
exist, gets a fixed error result and counts as a miss.
"""

from __future__ import annotations

import contextlib
import json
import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from devops_agent.agent import ToolReply, investigate
from devops_agent.config import Environment, Settings
from devops_agent.findings import build_finding
from devops_agent.models import Finding, InvestigationJob
from devops_agent.redact import redact_finding, redact_value
from devops_agent.tools import (
    AWS_TOOLS,
    DATADOG_TOOLS,
    READ_ONLY_TOOLS,
    ToolContext,
    aws_call_subject,
)

NO_RECORDED_DATA = "no recorded data for this call"
_MISS = ToolReply("error", json.dumps({"error": NO_RECORDED_DATA}), returned_data=False)
NO_SUCH_TOOL = "no such tool"
_NO_SUCH_TOOL = ToolReply("error", json.dumps({"error": NO_SUCH_TOOL}), returned_data=False)
_INPUT_MODELS = {tool.name: tool.input_model for tool in READ_ONLY_TOOLS}

# The input fields naming the resource a tool reads. A recorded call can answer a
# replayed one only when these agree; windows, query text and limits may differ.
IDENTITY_KEYS: dict[str, tuple[str, ...]] = {
    "get_metric": ("namespace", "metric_name", "dimensions"),
    "query_logs": ("log_group",),
    "recent_changes": (),
    "describe_s3_key": ("bucket", "key"),
    "describe_database": ("identifier",),
    "describe_search_domain": ("domain_name",),
    "describe_targets": ("load_balancer_name", "target_group_name"),
    "recent_executions": ("state_machine_name",),
    "scheduled_jobs": ("name_contains",),
    "search_datadog_logs": ("service", "name", "env"),
    "datadog_events": ("service", "kube_namespace", "env"),
    "datadog_top_pods": ("host", "cluster", "kube_namespace", "metric"),
    "github_list_repos": ("name",),
    "github_search_code": ("repo", "path"),
    "github_get_file": ("repo", "path"),
    "github_recent_changes": ("repo", "path"),
    "github_get_change": ("repo", "sha", "number"),
    "aws_call": ("service", "operation"),
}


def _params_subject(fields: dict[str, Any]) -> str | None:
    params = fields.get("params")
    return aws_call_subject(params) if isinstance(params, dict) else None


def _same_resource(name: str, recorded: dict[str, Any], fields: dict[str, Any]) -> bool:
    """Whether a recorded call read the same resource: the identity keys agree, and for
    aws_call so does the resource its params name."""
    if any(recorded.get(key) != fields.get(key) for key in IDENTITY_KEYS[name]):
        return False
    return name != "aws_call" or _params_subject(recorded) == _params_subject(fields)


def normalized_input(name: str, raw_input: Any) -> str:
    """A tool input as a canonical string: redacted, defaults filled, keys sorted.

    Inputs are redacted at capture, so a live input is redacted the same way before it
    is compared.
    """
    value = redact_value(raw_input or {})
    model = _INPUT_MODELS.get(name)
    if model is not None:
        with contextlib.suppress(ValidationError):
            value = model.model_validate(value).model_dump(mode="json")
    return json.dumps(value, sort_keys=True, default=str)


@dataclass(frozen=True)
class _Recorded:
    name: str
    fields: dict[str, Any]
    reply: ToolReply


def _fields(normalized: str) -> dict[str, Any]:
    value = json.loads(normalized)
    return value if isinstance(value, dict) else {}


class RecordedTools:
    """A tool runner answering from recorded calls.

    ``approximate`` counts calls answered by a recorded call on the same resource with
    other inputs, ``misses`` calls nothing recorded could answer, a call of a tool that
    does not exist included. Identical recorded calls are answered in their recorded
    order; once they run out the last one is repeated.
    """

    def __init__(self, calls: Iterable[dict[str, Any]]) -> None:
        self._exact: dict[tuple[str, str], list[ToolReply]] = {}
        self._calls: list[_Recorded] = []
        for call in calls:
            name = call["name"]
            normalized = normalized_input(name, call.get("input"))
            reply = ToolReply(call["status"], call["output"], returned_data=False)
            self._exact.setdefault((name, normalized), []).append(reply)
            self._calls.append(_Recorded(name, _fields(normalized), reply))
        self.approximate = 0
        self.misses = 0

    def __call__(self, name: str, raw_input: Any, ctx: ToolContext) -> ToolReply:
        if name not in _INPUT_MODELS:
            self.misses += 1
            return _NO_SUCH_TOOL
        normalized = normalized_input(name, raw_input)
        replies = self._exact.get((name, normalized))
        if replies:
            return replies.pop(0) if len(replies) > 1 else replies[0]
        nearest = self._nearest(name, _fields(normalized))
        if nearest is None:
            self.misses += 1
            return _MISS
        self.approximate += 1
        return nearest

    def _nearest(self, name: str, fields: dict[str, Any]) -> ToolReply | None:
        """The recorded reply on the same resource sharing the most other input fields.

        Ties go to the earliest recorded call.
        """
        identity = IDENTITY_KEYS.get(name)
        if identity is None:
            return None
        best: tuple[int, ToolReply] | None = None
        for call in self._calls:
            if call.name != name or not _same_resource(name, call.fields, fields):
                continue
            others = (set(call.fields) | set(fields)) - set(identity)
            shared = sum(call.fields.get(key) == fields.get(key) for key in others)
            if best is None or shared > best[0]:
                best = (shared, call.reply)
        return None if best is None else best[1]


def _strip(value: Any, exclude: Sequence[str]) -> Any:
    if isinstance(value, str):
        for text in exclude:
            value = value.replace(text, "")
        return value
    if isinstance(value, dict):
        return {key: _strip(item, exclude) for key, item in value.items()}
    if isinstance(value, list):
        return [_strip(item, exclude) for item in value]
    return value


def strip_excluded(snapshot: dict[str, Any], exclude: Sequence[str]) -> dict[str, Any]:
    """The snapshot with every excluded string removed from its text.

    Call names and inputs are kept as recorded so replayed calls still match them.
    """
    texts = [text for text in exclude if text]
    stripped: dict[str, Any] = _strip(
        {key: value for key, value in snapshot.items() if key != "calls"}, texts
    )
    stripped["calls"] = [
        {**call, "output": _strip(call["output"], texts)} for call in snapshot.get("calls", [])
    ]
    return stripped


def replay_settings(env: Environment, model_id: str) -> Settings:
    """Settings for a replay: the given model with no fallback, and no Slack."""
    return Settings(
        environment=env,
        findings_table="eval",
        slack_enabled=False,
        model_id=model_id,
        fallback_model_id=model_id,
    )


def replay_context(job: InvestigationJob, tools: Sequence[str]) -> ToolContext:
    """A context with no clients; the Datadog and generic AWS tools are offered when they
    were recorded."""
    offered_datadog = bool(DATADOG_TOOLS.intersection(tools))
    offered_aws = bool(AWS_TOOLS.intersection(tools))
    return ToolContext(
        cloudwatch=None,
        logs=None,
        cloudtrail=None,
        lambda_=None,
        sqs=None,
        kinesis=None,
        rds=None,
        pi=None,
        opensearch=None,
        elbv2=None,
        elasticache=None,
        stepfunctions=None,
        apigatewayv2=None,
        ec2=None,
        s3=None,
        events=None,
        scheduler=None,
        alarm_name=job.signal.name,
        datadog=object() if offered_datadog else None,
        aws_client=(lambda service: None) if offered_aws else None,
    )


@dataclass(frozen=True)
class Replay:
    finding: Finding
    tool_misses: int
    tool_approximate: int


def replay(case: dict[str, Any], bedrock: Any, model_id: str, now: datetime) -> Replay:
    """Run the investigation loop on a case's snapshot and return the new finding."""
    snapshot = strip_excluded(case["snapshot"], case.get("exclude", []))
    job = InvestigationJob.model_validate(snapshot["job"])
    settings = replay_settings(snapshot["env"], model_id)
    tools = RecordedTools(snapshot["calls"])
    investigation = investigate(
        bedrock,
        replay_context(job, snapshot["tools"]),
        settings,
        job,
        snapshot["context"],
        snapshot["prior"],
        lambda: math.inf,
        run=tools,
    )
    finding = redact_finding(
        build_finding(env=settings.environment, job=job, investigation=investigation, now=now)
    )
    return Replay(finding, tools.misses, tools.approximate)
