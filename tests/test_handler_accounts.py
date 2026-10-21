"""The investigator across accounts: one session per job, from the job's account."""

from __future__ import annotations

import dataclasses
import json
import uuid
from typing import Any

import pytest
from botocore.stub import Stubber
from pytest_mock import MockerFixture

from devops_agent import handler as handler_module
from devops_agent.accounts import MIN_SESSION_SECONDS
from devops_agent.config import get_settings
from devops_agent.handler import AgentClients, handler
from devops_agent.models import ContextSummary, InvestigationJob, Severity, scoped_key
from devops_agent.precheck import IncidentContext
from devops_agent.tools import ToolContext
from tests.conftest import (
    ALARM_FIELDS,
    ALARM_NAME,
    FUNCTION_KEY,
    MEMBER_ACCOUNT,
    OTHER_ACCOUNT,
    OWN_ACCESS_KEY,
    OWN_ACCOUNT,
    FakeBedrock,
    FakeClient,
    FakeTable,
    converse_response,
    job,
    lambda_context,
    member_alarm_event,
    member_credentials,
    report,
    signing_key,
    sqs_record,
    stubbed_sts,
)

ROLE = "devops-agent-read"
EXTERNAL_ID = "org-external-1"
# ToolContext fields that are not AWS clients of the investigated account.
NOT_AWS = ALARM_FIELDS | {"datadog", "github", "aws_client"}


@dataclasses.dataclass
class Run:
    """The investigator's own fakes, its STS stubber and the tool contexts it built."""

    clients: AgentClients
    stubber: Stubber
    contexts: list[ToolContext] = dataclasses.field(default_factory=list)
    past_sources: list[list[dict[str, Any]]] = dataclasses.field(default_factory=list)

    @property
    def table(self) -> FakeTable:
        table: FakeTable = self.clients.table
        return table

    @property
    def bedrock(self) -> FakeBedrock:
        bedrock: FakeBedrock = self.clients.bedrock
        return bedrock

    def expect_assume(self, account: str, finding_id: str) -> None:
        self.stubber.add_response(
            "assume_role",
            {"Credentials": member_credentials(account)},
            {
                "RoleArn": f"arn:aws:iam::{account}:role/{ROLE}",
                "RoleSessionName": f"devops-agent-{finding_id}",
                "DurationSeconds": MIN_SESSION_SECONDS,
                "ExternalId": EXTERNAL_ID,
            },
        )


@pytest.fixture()
def run(mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch, own_credentials: None) -> Run:
    """An investigator with member accounts: its own clients faked, its STS client and
    every job's session real; the context bundle is not read."""
    monkeypatch.setenv("MEMBER_ROLE_NAME", ROLE)
    monkeypatch.setenv("MEMBER_EXTERNAL_ID", EXTERNAL_ID)
    get_settings.cache_clear()
    sts, stubber = stubbed_sts()
    clients = AgentClients(bedrock=FakeBedrock(), sns=FakeClient(), sts=sts, table=FakeTable())
    mocker.patch.object(handler_module, "agent_clients", return_value=clients)
    state = Run(clients, stubber)

    def build_context(ctx: ToolContext, work: InvestigationJob, now: Any, past: Any) -> Any:
        state.contexts.append(ctx)
        state.past_sources.append(past())
        summary = ContextSummary(sections={}, counts={}, chars=0, truncated=False)
        return IncidentContext("", summary)

    mocker.patch.object(handler_module, "build_context", side_effect=build_context)
    return state


def member_job(account: str = MEMBER_ACCOUNT, finding_id: str | None = None) -> InvestigationJob:
    """A job for the test alarm in a member account, keyed as triage keys it."""
    return InvestigationJob.model_validate(
        {
            "finding_id": finding_id or str(uuid.uuid4()),
            "kind": "alarm",
            "alarms": [member_alarm_event(account=account)],
            "alarm_count": 1,
            "keys": [scoped_key(FUNCTION_KEY, account)],
            "floor": Severity.HIGH,
            "account_id": account,
            "region": "us-east-1",
        }
    )


def _event(*jobs: InvestigationJob) -> dict[str, Any]:
    return {
        "Records": [
            sqs_record(item.model_dump(mode="json", by_alias=True), message_id=f"msg-{n}")
            for n, item in enumerate(jobs, start=1)
        ]
    }


def _reports(run: Run, count: int = 1) -> None:
    run.bedrock.script.extend(converse_response(report("high")) for _ in range(count))


def _aws_keys(ctx: ToolContext) -> dict[str, str]:
    """The access key each AWS client of the tool context signs with."""
    keys = {
        field.name: signing_key(getattr(ctx, field.name))
        for field in dataclasses.fields(ctx)
        if field.name not in NOT_AWS
    }
    assert ctx.aws_client is not None
    keys["aws_call.ec2"] = signing_key(ctx.aws_client("ec2"))
    keys["aws_call.dynamodb"] = signing_key(ctx.aws_client("dynamodb"))
    return keys


def test_own_account_job_reads_with_the_agents_credentials(run: Run) -> None:
    _reports(run)
    assert handler(_event(job(finding_id="f-1")), lambda_context()) == {"batchItemFailures": []}
    run.stubber.assert_no_pending_responses()
    [ctx] = run.contexts
    assert set(_aws_keys(ctx).values()) == {OWN_ACCESS_KEY}
    item = run.table.items["finding#f-1"]
    assert item["account_id"] == OWN_ACCOUNT
    assert item["resource_key"] == FUNCTION_KEY


def test_member_job_reads_every_aws_client_through_the_member_role(run: Run) -> None:
    run.expect_assume(MEMBER_ACCOUNT, "f-1")
    _reports(run)
    result = handler(_event(member_job(finding_id="f-1")), lambda_context())
    assert result == {"batchItemFailures": []}
    run.stubber.assert_no_pending_responses()
    [ctx] = run.contexts
    keys = _aws_keys(ctx)
    assert len(keys) == 19
    assert set(keys.values()) == {f"member-key-{MEMBER_ACCOUNT}"}

    item = run.table.items["finding#f-1"]
    assert item["outcome"] == "reported"
    assert item["account_id"] == MEMBER_ACCOUNT
    assert item["region"] == "us-east-1"
    assert item["resource_key"] == scoped_key(FUNCTION_KEY, MEMBER_ACCOUNT)
    assert len(run.bedrock.calls) == 1


def test_the_agents_own_clients_never_use_a_member_session(own_credentials: None) -> None:
    handler_module.agent_clients.cache_clear()
    clients = handler_module.agent_clients("us-east-1", "devops-agent-findings-prod")
    assert signing_key(clients.bedrock) == OWN_ACCESS_KEY
    assert signing_key(clients.sns) == OWN_ACCESS_KEY
    assert signing_key(clients.sts) == OWN_ACCESS_KEY
    assert signing_key(clients.table.meta.client) == OWN_ACCESS_KEY
    handler_module.agent_clients.cache_clear()


def test_member_job_stores_and_notifies_on_the_agents_clients(run: Run) -> None:
    run.expect_assume(MEMBER_ACCOUNT, "f-1")
    _reports(run)
    handler(_event(member_job(finding_id="f-1")), lambda_context())
    assert "finding#f-1" in run.table.items
    assert [operation for operation, _ in run.clients.sns.calls] == ["publish"]


def test_failed_assume_role_is_an_incomplete_finding_naming_it(run: Run) -> None:
    run.stubber.add_client_error("assume_role", "AccessDenied", "not authorized")
    result = handler(_event(member_job(finding_id="f-1")), lambda_context())
    assert result == {"batchItemFailures": []}
    item = run.table.items["finding#f-1"]
    assert item["outcome"] == "incomplete"
    assert item["account_id"] == MEMBER_ACCOUNT
    assert (
        f"failed with AccountAccessError: AssumeRole of arn:aws:iam::{MEMBER_ACCOUNT}:role/"
        f"{ROLE} failed (AccessDenied)" in item["summary"]
    )
    assert run.contexts == []
    assert run.bedrock.calls == []


def test_member_job_without_a_member_role_is_incomplete(
    run: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MEMBER_ROLE_NAME")
    get_settings.cache_clear()
    handler(_event(member_job(finding_id="f-1")), lambda_context())
    item = run.table.items["finding#f-1"]
    assert item["outcome"] == "incomplete"
    assert "needs MEMBER_ROLE_NAME, which is not set" in item["summary"]
    assert run.contexts == []


def test_consecutive_jobs_never_reuse_credentials(run: Run) -> None:
    run.expect_assume(MEMBER_ACCOUNT, "f-1")
    run.expect_assume(OTHER_ACCOUNT, "f-2")
    _reports(run, 3)
    handler(
        _event(
            member_job(MEMBER_ACCOUNT, "f-1"),
            member_job(OTHER_ACCOUNT, "f-2"),
            job(finding_id="f-3"),
        ),
        lambda_context(),
    )
    run.stubber.assert_no_pending_responses()
    first, second, own = run.contexts
    assert set(_aws_keys(first).values()) == {f"member-key-{MEMBER_ACCOUNT}"}
    assert set(_aws_keys(second).values()) == {f"member-key-{OTHER_ACCOUNT}"}
    assert set(_aws_keys(own).values()) == {OWN_ACCESS_KEY}
    assert first.cloudwatch is not second.cloudwatch
    assert first.aws_client is not None
    assert second.aws_client is not None
    assert first.aws_client("ec2") is not second.aws_client("ec2")
    accounts = [run.table.items[f"finding#f-{n}"]["account_id"] for n in (1, 2, 3)]
    assert accounts == [MEMBER_ACCOUNT, OTHER_ACCOUNT, OWN_ACCOUNT]


def test_recall_and_remembered_sources_are_scoped_by_account(run: Run) -> None:
    run.table.items["finding#f-old"] = {
        "pk": "finding#f-old",
        "finding_id": "f-old",
        "created_at": "2026-09-01T00:00:00+00:00",
        "kind": "alarm",
        "status": "closed",
        "resolution": "confirmed",
        "outcome": "reported",
        "title": "Own account deploy broke it",
        "resource_key": FUNCTION_KEY,
    }
    run.table.items[f"obs#{FUNCTION_KEY}"] = {
        "pk": f"obs#{FUNCTION_KEY}",
        "entries": [{"tool": "get_metric", "input": {}, "at": "2026-09-01T00:00:00+00:00"}],
    }
    run.expect_assume(MEMBER_ACCOUNT, "f-1")
    _reports(run)
    handler(_event(member_job(finding_id="f-1")), lambda_context())
    assert run.past_sources == [[]]
    prompt = json.dumps(run.bedrock.calls[0]["messages"])
    assert f"No reviewed prior findings on {scoped_key(FUNCTION_KEY, MEMBER_ACCOUNT)}." in prompt
    item = run.table.items["finding#f-1"]
    assert item["previous_finding_id"] is None
    assert item["prior_finding_ids"] == []


def test_job_written_without_an_account_takes_its_alarms() -> None:
    body = job(finding_id="f-1").model_dump(mode="json", by_alias=True)
    del body["account_id"], body["region"]
    for signal in body["signals"]:
        del signal["account_id"], signal["region"]
    parsed = InvestigationJob.model_validate(body)
    assert parsed.account_id == OWN_ACCOUNT
    assert parsed.region == "us-east-1"
    assert parsed.signal.name == ALARM_NAME
