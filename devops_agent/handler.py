"""Investigator Lambda: one work-queue job per invocation.

Recall, precheck, investigate, count the run's tokens, redact, store under the
pre-allocated finding id, notify, remember the sources that returned data.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache, partial
from typing import Any

import boto3
from aws_lambda_powertools import Logger
from botocore.config import Config
from pydantic import ValidationError

from devops_agent.active import linked_alarms
from devops_agent.agent import MODEL_READ_TIMEOUT_SECONDS, Investigation, investigate
from devops_agent.config import Settings, get_settings
from devops_agent.datadog import datadog_client
from devops_agent.findings import (
    build_finding,
    finding_exists,
    is_reviewed,
    prior_findings,
    record_useful_sources,
    store_finding,
    store_snapshot,
    useful_sources,
)
from devops_agent.gate import add_daily_tokens
from devops_agent.github import github_client
from devops_agent.models import FindingKind, InvestigationJob
from devops_agent.notify import publish_finding
from devops_agent.precheck import build_context
from devops_agent.redact import redact_finding
from devops_agent.snapshot import build_snapshot, encode_snapshot
from devops_agent.tools import ToolContext, botocore_session, offered_tools

logger = Logger(service="devops-agent")
logging.getLogger("botocore").setLevel(logging.WARNING)

RECALL_PAGE = 25
PRIOR_FINDINGS = 3


@dataclass(frozen=True)
class AwsClients:
    cloudwatch: Any
    logs: Any
    cloudtrail: Any
    lambda_: Any
    sqs: Any
    kinesis: Any
    rds: Any
    pi: Any
    opensearch: Any
    elbv2: Any
    elasticache: Any
    stepfunctions: Any
    apigatewayv2: Any
    ec2: Any
    s3: Any
    events: Any
    scheduler: Any
    bedrock: Any
    sns: Any
    table: Any


@lru_cache(maxsize=1)
def aws_clients(region: str, table_name: str) -> AwsClients:
    bedrock_config = Config(
        read_timeout=MODEL_READ_TIMEOUT_SECONDS, retries={"mode": "standard", "max_attempts": 1}
    )
    return AwsClients(
        cloudwatch=boto3.client("cloudwatch", region_name=region),
        logs=boto3.client("logs", region_name=region),
        cloudtrail=boto3.client("cloudtrail", region_name=region),
        lambda_=boto3.client("lambda", region_name=region),
        sqs=boto3.client("sqs", region_name=region),
        kinesis=boto3.client("kinesis", region_name=region),
        rds=boto3.client("rds", region_name=region),
        pi=boto3.client("pi", region_name=region),
        opensearch=boto3.client("opensearch", region_name=region),
        elbv2=boto3.client("elbv2", region_name=region),
        elasticache=boto3.client("elasticache", region_name=region),
        stepfunctions=boto3.client("stepfunctions", region_name=region),
        apigatewayv2=boto3.client("apigatewayv2", region_name=region),
        ec2=boto3.client("ec2", region_name=region),
        s3=boto3.client("s3", region_name=region),
        events=boto3.client("events", region_name=region),
        scheduler=boto3.client("scheduler", region_name=region),
        bedrock=boto3.client("bedrock-runtime", region_name=region, config=bedrock_config),
        sns=boto3.client("sns", region_name=region),
        table=boto3.resource("dynamodb", region_name=region).Table(table_name),
    )


AWS_CALL_CLIENT_CONFIG = Config(
    connect_timeout=5, read_timeout=20, retries={"max_attempts": 2, "mode": "standard"}
)


@lru_cache(maxsize=1)
def _aws_call_session() -> boto3.session.Session:
    """A boto3 session on the botocore session the aws_call catalog and guard read."""
    return boto3.session.Session(botocore_session=botocore_session())


@lru_cache(maxsize=64)
def aws_service_client(region: str, service: str) -> Any:
    """A client for any covered service, for aws_call: built on first use, then kept."""
    return _aws_call_session().client(service, region_name=region, config=AWS_CALL_CLIENT_CONFIG)


def parse_job(record: dict[str, Any]) -> InvestigationJob | None:
    """The job a work-queue record carries, or None when the body is not a job."""
    try:
        return InvestigationJob.model_validate_json(record.get("body") or "")
    except ValidationError:
        logger.error(
            "ignored: record body is not a job", extra={"message_id": record.get("messageId")}
        )
        return None


def _signal_at(job: InvestigationJob) -> datetime | None:
    """When the job's signal fired: the alarm entered ALARM, or the monitor was evaluated."""
    if not job.signal.observed_at:
        return None
    try:
        return datetime.fromisoformat(job.signal.observed_at)
    except ValueError:
        return None


def _seconds_left(context: Any) -> Callable[[], float]:
    remaining = getattr(context, "get_remaining_time_in_millis", None)
    if remaining is None:
        return lambda: math.inf
    return lambda: remaining() / 1000


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    settings = get_settings()
    logger.setLevel(settings.log_level)
    aws = aws_clients(settings.aws_region, settings.findings_table)

    failures: list[dict[str, str]] = []
    for record in event.get("Records", []):
        try:
            handled = _handle_record(aws, settings, record, context)
        except Exception as exc:
            logger.error("job not handled", extra={"error": type(exc).__name__})
            handled = False
        if not handled:
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}


def _handle_record(
    aws: AwsClients, settings: Settings, record: dict[str, Any], context: Any
) -> bool:
    """False when the record must be retried: its finding could not be stored."""
    job = parse_job(record)
    if job is None:
        return True
    if finding_exists(aws.table, job.finding_id):
        logger.info("redelivered: finding already stored", extra={"finding_id": job.finding_id})
        return True
    now = datetime.now(UTC)
    try:
        _investigate_and_record(aws, settings, job, now, context)
    except Exception as exc:
        return _record_failure(aws, settings, job, now, exc)
    return True


@dataclass(frozen=True)
class Recall:
    previous_finding_id: str | None
    reviewed: list[dict[str, Any]]


def _recall(table: Any, job: InvestigationJob) -> Recall:
    """The newest prior finding on the job's resource, and the newest reviewed ones.

    The job's own findings are left out. Only findings a person closed as confirmed or
    false_positive are passed to the model; open and wrong conclusions never are.
    """
    items = [
        item
        for item in prior_findings(table, job.resource_key, RECALL_PAGE)
        if job.finding_id not in (item.get("incident_id"), item.get("linked_to"))
    ]
    return Recall(
        previous_finding_id=str(items[0]["finding_id"]) if items else None,
        reviewed=[item for item in items if is_reviewed(item)][:PRIOR_FINDINGS],
    )


def _remember_sources(
    table: Any, job: InvestigationJob, sources: tuple[dict[str, Any], ...], now: datetime
) -> None:
    if not sources:
        return
    try:
        record_useful_sources(table, job.resource_key, sources, now)
    except Exception as exc:
        logger.warning(
            "useful sources not recorded",
            extra={"finding_id": job.finding_id, "error": type(exc).__name__},
        )


def _count_tokens(table: Any, job: InvestigationJob, tokens: int, now: datetime) -> None:
    """Add the run's weighted tokens to today's counter; a failure never fails the job."""
    if not tokens:
        return
    try:
        add_daily_tokens(table, tokens, now)
    except Exception as exc:
        logger.warning(
            "tokens not counted",
            extra={"finding_id": job.finding_id, "error": type(exc).__name__},
        )


def _capture_snapshot(
    table: Any,
    settings: Settings,
    job: InvestigationJob,
    context: str,
    ctx: ToolContext,
    recall: Recall,
    investigation: Investigation,
    now: datetime,
) -> None:
    """Store the snap# item for eval replay. A failure is logged and never fails the job."""
    try:
        snapshot = build_snapshot(
            env=settings.environment,
            job=job,
            context=context,
            prior=recall.reviewed,
            tools=[tool.name for tool in offered_tools(ctx)],
            investigation=investigation,
        )
        attribute = encode_snapshot(snapshot)
        if attribute is None:
            logger.warning(
                "snapshot not captured: too large",
                extra={"finding_id": job.finding_id, "call_count": len(investigation.calls)},
            )
            return
        store_snapshot(table, job.finding_id, attribute, now)
    except Exception as exc:
        logger.warning(
            "snapshot not captured",
            extra={"finding_id": job.finding_id, "error": type(exc).__name__},
        )


def _investigate_and_record(
    aws: AwsClients,
    settings: Settings,
    job: InvestigationJob,
    now: datetime,
    context: Any,
) -> None:
    log_keys = {
        "alarm_name": job.signal.name,
        "source": job.signal.source,
        "finding_id": job.finding_id,
        "kind": job.kind.value,
    }
    recall = _recall(aws.table, job)
    ctx = ToolContext(
        cloudwatch=aws.cloudwatch,
        logs=aws.logs,
        cloudtrail=aws.cloudtrail,
        lambda_=aws.lambda_,
        sqs=aws.sqs,
        kinesis=aws.kinesis,
        rds=aws.rds,
        pi=aws.pi,
        opensearch=aws.opensearch,
        elbv2=aws.elbv2,
        elasticache=aws.elasticache,
        stepfunctions=aws.stepfunctions,
        apigatewayv2=aws.apigatewayv2,
        ec2=aws.ec2,
        s3=aws.s3,
        events=aws.events,
        scheduler=aws.scheduler,
        alarm_name=job.signal.name,
        datadog=datadog_client(settings),
        github=github_client(settings),
        aws_client=partial(aws_service_client, settings.aws_region),
        alarm_time=_signal_at(job),
    )
    bundle = build_context(ctx, job, now, lambda: useful_sources(aws.table, job.resource_key))
    investigation = investigate(
        aws.bedrock, ctx, settings, job, bundle.text, recall.reviewed, _seconds_left(context)
    )
    _count_tokens(aws.table, job, investigation.weighted_tokens, datetime.now(UTC))

    finding = redact_finding(
        build_finding(
            env=settings.environment,
            job=job,
            investigation=investigation,
            now=now,
            linked_alarms=linked_alarms(aws.table, job.keys, job.finding_id),
            previous_finding_id=recall.previous_finding_id,
            context_summary=bundle.summary,
            prior_finding_ids=[str(item["finding_id"]) for item in recall.reviewed],
        )
    )
    if not store_finding(aws.table, finding):
        logger.info("redelivered: finding already stored", extra=log_keys)
        return
    if investigation.outcome == "reported":
        _remember_sources(aws.table, job, investigation.sources, now)
    if settings.capture_snapshots:
        _capture_snapshot(aws.table, settings, job, bundle.text, ctx, recall, investigation, now)
    storm_size = job.alarm_count if job.kind is FindingKind.INCIDENT else None
    notified = (
        settings.slack_enabled
        and settings.slack_topic_arn is not None
        and publish_finding(
            aws.sns,
            settings.slack_topic_arn,
            settings.slack_channel,
            finding,
            storm_size=storm_size,
        )
    )

    logger.info(
        "finding recorded",
        extra={
            **log_keys,
            "severity": finding.severity.value,
            "severity_floor": job.floor.value,
            "outcome": finding.outcome,
            "steps": investigation.steps,
            "model_id": investigation.model_id,
            "tokens_used": investigation.tokens_used,
            "weighted_tokens": investigation.weighted_tokens,
            "tool_calls": list(investigation.tool_calls),
            "tool_call_count": len(investigation.tool_calls),
            "evidence_count": len(finding.evidence),
            "prior_finding_count": len(recall.reviewed),
            "context_sections": bundle.summary.sections,
            "context_chars": bundle.summary.chars,
            "useful_source_count": len(investigation.sources),
            "linked_alarm_count": len(finding.linked_alarms),
            "notified": notified,
        },
    )


def _record_failure(
    aws: AwsClients,
    settings: Settings,
    job: InvestigationJob,
    now: datetime,
    exc: Exception,
) -> bool:
    """Store an incomplete finding naming the failure. False when that store fails too.

    Only the exception's class name is kept; its message may quote what was read.
    """
    error = type(exc).__name__
    log_keys = {"alarm_name": job.signal.name, "finding_id": job.finding_id, "error": error}
    logger.error("investigation failed", extra=log_keys)
    try:
        finding = build_finding(
            env=settings.environment,
            job=job,
            investigation=Investigation("incomplete", None, 0, settings.model_id, ()),
            now=now,
            error=error,
        )
        store_finding(aws.table, finding)
    except Exception as store_exc:
        logger.error(
            "failure finding not stored, job will be retried",
            extra={**log_keys, "store_error": type(store_exc).__name__},
        )
        return False
    logger.info("failure recorded", extra=log_keys)
    return True
