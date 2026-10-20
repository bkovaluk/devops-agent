"""Snapshot capture: what the model read, stored as snap#<finding_id> for eval replay."""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime
from typing import Any

import pytest
from pytest_mock import MockerFixture

from devops_agent import handler as handler_module
from devops_agent.agent import Investigation, investigate
from devops_agent.config import Settings
from devops_agent.findings import SNAPSHOT_RETENTION_DAYS, store_snapshot
from devops_agent.handler import AwsClients, handler
from devops_agent.models import InvestigationJob
from devops_agent.snapshot import (
    MAX_PLAIN_SNAPSHOT_BYTES,
    build_snapshot,
    decode_snapshot,
    encode_snapshot,
)
from devops_agent.tools import ToolContext
from tests.conftest import (
    FakeBedrock,
    FakeClient,
    FakeTable,
    converse_response,
    job,
    report,
    sqs_record,
    tool_use,
)

ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
NOW = datetime(2026, 9, 29, 14, 10, tzinfo=UTC)


def _investigation(*calls: dict[str, Any]) -> Investigation:
    return Investigation("incomplete", None, 1, "model-a", (), calls=calls)


def test_investigation_records_each_call_with_the_text_the_model_read(
    tool_ctx: ToolContext, settings: Settings
) -> None:
    bedrock = FakeBedrock(
        converse_response(tool_use("recent_changes", {})),
        converse_response(report()),
    )
    result = investigate(bedrock, tool_ctx, settings, job(), "ctx", [], lambda: 1e9)

    seen = bedrock.calls[1]["messages"][-1]["content"][0]["toolResult"]
    assert result.calls == (
        {
            "name": "recent_changes",
            "input": {},
            "status": seen["status"],
            "output": seen["content"][0]["text"].removeprefix("[step 1]\n"),
        },
    )
    assert seen["content"][0]["text"].startswith("[step 1]\n")


def test_snapshot_holds_the_job_context_prior_tools_and_redacted_inputs() -> None:
    work = job()
    prior = [
        {
            "pk": "finding#old",
            "created_at": "2026-09-01T00:00:00+00:00",
            "status": "closed",
            "resolution": "confirmed",
            "severity": "high",
            "title": "Old cause",
            "fix_effort": "low",
            "likely_cause": "A bad deploy.",
            "summary": "not passed to the model",
        }
    ]
    call = {
        "name": "query_logs",
        "input": {"log_group": "g", "query": f"filter @message like /{ACCESS_KEY}/"},
        "status": "success",
        "output": "{}",
    }
    snapshot = build_snapshot(
        env="prod",
        job=work,
        context="bundle",
        prior=prior,
        tools=["get_metric", "query_logs"],
        investigation=_investigation(call),
    )

    assert InvestigationJob.model_validate(snapshot["job"]) == work
    assert snapshot["context"] == "bundle"
    assert snapshot["tools"] == ["get_metric", "query_logs"]
    assert snapshot["prior"] == [
        {key: value for key, value in prior[0].items() if key not in ("pk", "summary")}
    ]
    assert ACCESS_KEY not in json.dumps(snapshot)
    assert snapshot["calls"][0]["output"] == "{}"


def test_snapshot_records_the_tokens_the_run_used() -> None:
    investigation = Investigation(
        "incomplete", None, 1, "model-a", (), tokens_used=8_250, weighted_tokens=3_100
    )
    snapshot = build_snapshot(
        env="prod", job=job(), context="", prior=[], tools=[], investigation=investigation
    )
    assert snapshot["tokens_used"] == 8_250
    assert snapshot["weighted_tokens"] == 3_100


def test_small_snapshot_is_stored_as_plain_json() -> None:
    snapshot = {"context": "x" * 1000}
    attribute = encode_snapshot(snapshot)
    assert attribute is not None
    assert set(attribute) == {"snapshot"}
    assert decode_snapshot(attribute) == snapshot


def test_large_snapshot_is_gzipped_and_round_trips() -> None:
    snapshot = {"context": "x" * (MAX_PLAIN_SNAPSHOT_BYTES + 1)}
    attribute = encode_snapshot(snapshot)
    assert attribute is not None
    assert set(attribute) == {"snapshot_gz"}
    assert len(attribute["snapshot_gz"]) < MAX_PLAIN_SNAPSHOT_BYTES
    assert decode_snapshot(attribute) == snapshot


def test_snapshot_too_large_after_compression_is_skipped() -> None:
    noise = random.Random(0).randbytes(400_000).hex()
    assert encode_snapshot({"context": noise}) is None


def test_store_snapshot_puts_a_snap_item_with_a_ttl() -> None:
    table = FakeTable()
    store_snapshot(table, "f-1", {"snapshot": "{}"}, NOW)
    item = table.items["snap#f-1"]
    assert item["finding_id"] == "f-1"
    assert item["snapshot"] == "{}"
    assert item["ttl"] == int(NOW.timestamp()) + SNAPSHOT_RETENTION_DAYS * 86400


@pytest.fixture()
def aws(mocker: MockerFixture) -> AwsClients:
    clients = AwsClients(
        cloudwatch=FakeClient(),
        logs=FakeClient(),
        cloudtrail=FakeClient(),
        lambda_=FakeClient(),
        sqs=FakeClient(),
        kinesis=FakeClient(),
        rds=FakeClient(),
        pi=FakeClient(),
        opensearch=FakeClient(),
        elbv2=FakeClient(),
        elasticache=FakeClient(),
        stepfunctions=FakeClient(),
        apigatewayv2=FakeClient(),
        ec2=FakeClient(),
        s3=FakeClient(),
        events=FakeClient(),
        scheduler=FakeClient(),
        bedrock=FakeBedrock(),
        sns=FakeClient(),
        table=FakeTable(),
    )
    mocker.patch.object(handler_module, "aws_clients", return_value=clients)
    return clients


def _event(work: InvestigationJob) -> dict[str, Any]:
    return {"Records": [sqs_record(work.model_dump(mode="json", by_alias=True))]}


def test_handler_captures_a_snapshot_after_storing_the_finding(aws: AwsClients) -> None:
    aws.bedrock.script.extend(
        [converse_response(tool_use("recent_changes", {})), converse_response(report())]
    )
    assert handler(_event(job(finding_id="f-1")), None) == {"batchItemFailures": []}

    snapshot = decode_snapshot(aws.table.items["snap#f-1"])
    assert snapshot["env"] == "prod"
    assert snapshot["job"]["finding_id"] == "f-1"
    assert snapshot["context"].startswith("## ")
    assert "recent_changes" in snapshot["tools"]
    assert [call["name"] for call in snapshot["calls"]] == ["recent_changes"]


def test_handler_skips_the_snapshot_when_capture_is_off(
    aws: AwsClients, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CAPTURE_SNAPSHOTS", "false")
    aws.bedrock.script.append(converse_response(report()))
    handler(_event(job(finding_id="f-1")), None)
    assert "finding#f-1" in aws.table.items
    assert "snap#f-1" not in aws.table.items


def test_a_failed_snapshot_write_does_not_fail_the_job(
    aws: AwsClients, mocker: MockerFixture
) -> None:
    mocker.patch.object(handler_module, "store_snapshot", side_effect=RuntimeError("boom"))
    aws.bedrock.script.append(converse_response(report()))
    assert handler(_event(job(finding_id="f-1")), None) == {"batchItemFailures": []}
    assert "finding#f-1" in aws.table.items


def test_an_oversized_snapshot_is_not_stored(aws: AwsClients, mocker: MockerFixture) -> None:
    mocker.patch.object(handler_module, "encode_snapshot", return_value=None)
    aws.bedrock.script.append(converse_response(report()))
    assert handler(_event(job(finding_id="f-1")), None) == {"batchItemFailures": []}
    assert "finding#f-1" in aws.table.items
    assert "snap#f-1" not in aws.table.items
