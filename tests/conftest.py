"""Fixtures and fake AWS clients for DevOps agent tests."""

from __future__ import annotations

import copy
import functools
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from devops_agent import github as github_module
from devops_agent.catalog import load_catalog
from devops_agent.config import Settings, get_settings, get_triage_settings
from devops_agent.models import (
    AlarmStateChangeEvent,
    FindingKind,
    InvestigationJob,
    Severity,
    SignalRef,
)
from devops_agent.signals import parse_signal
from devops_agent.tools import ToolContext
from devops_agent.verify import clear_monitor_cache

ALARM_NAME = "payment-api-errors-prod"
ALARM_ARN = f"arn:aws:cloudwatch:us-east-1:111122223333:alarm:{ALARM_NAME}"
FUNCTION_KEY = "AWS/Lambda:FunctionName=payment-api-prod"
WORK_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/111122223333/devops-agent-work-prod"
ALARMS_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/111122223333/devops-agent-alarms-prod"


@pytest.fixture(autouse=True)
def settings_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("ENVIRONMENT", "prod")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("FINDINGS_TABLE", "devops-agent-findings-prod")
    monkeypatch.setenv("SLACK_TOPIC_ARN", "arn:aws:sns:us-east-1:111122223333:ops-alerts-prod")
    monkeypatch.setenv("SLACK_CHANNEL", "#ops-alerts")
    monkeypatch.setenv("SLACK_ENABLED", "true")
    monkeypatch.setenv("WORK_QUEUE_URL", WORK_QUEUE_URL)
    monkeypatch.setenv("ALARMS_QUEUE_URL", ALARMS_QUEUE_URL)
    get_settings.cache_clear()
    get_triage_settings.cache_clear()
    yield
    get_settings.cache_clear()
    get_triage_settings.cache_clear()


@pytest.fixture(autouse=True)
def bundled_catalog(settings_env: None) -> Iterator[None]:
    """Every test reads the bundled catalog unless it sets CATALOG_PARAMETER."""
    load_catalog.cache_clear()
    yield
    load_catalog.cache_clear()


def set_environment(monkeypatch: pytest.MonkeyPatch, env: str) -> None:
    """Run the rest of the test as ``env``'s agent, its catalog read afresh."""
    monkeypatch.setenv("ENVIRONMENT", env)
    monkeypatch.setenv("SLACK_TOPIC_ARN", f"arn:aws:sns:us-east-1:111122223333:ops-alerts-{env}")
    get_settings.cache_clear()
    load_catalog.cache_clear()


@pytest.fixture()
def settings() -> Settings:
    return get_settings()


def client_error(code: str, message: str = "boom", operation: str = "Op") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


class FakeClient:
    """Records every operation called and answers from a response map.

    A response may be a value, a callable taking the call kwargs, or an exception.
    """

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, operation: str) -> Any:
        if operation.startswith("_"):
            raise AttributeError(operation)

        def call(**kwargs: Any) -> Any:
            self.calls.append((operation, copy.deepcopy(kwargs)))
            response = self.responses.get(operation, {})
            if isinstance(response, BaseException):
                raise response
            if callable(response):
                return response(**kwargs)
            return copy.deepcopy(response)

        return call

    def operations(self) -> list[str]:
        return [operation for operation, _ in self.calls]


class FakeClients:
    """An aws_client factory: one FakeClient per service, kept in ``clients``."""

    def __init__(self) -> None:
        self.clients: dict[str, FakeClient] = {}

    def __call__(self, service: str) -> FakeClient:
        return self.clients.setdefault(service, FakeClient())

    @property
    def calls(self) -> list[tuple[str, dict[str, Any]]]:
        return [call for client in self.clients.values() for call in client.calls]

    def operations(self) -> list[str]:
        return [operation for operation, _ in self.calls]


INDEX_HASH_KEYS = {"by_status": "status", "by_resource": "resource_key"}
OPEN_INVESTIGATION_FILTER = (
    "alarm_name = :alarm AND #status IN (:open, :acknowledged) "
    "AND #kind IN (:alarm_kind, :incident_kind) AND #outcome = :reported"
)


def _matches(
    expression: str, names: dict[str, str], values: dict[str, Any], item: dict[str, Any]
) -> bool:
    if expression != OPEN_INVESTIGATION_FILTER:
        raise AssertionError(f"unmodelled filter {expression!r}")
    assert names == {"#status": "status", "#kind": "kind", "#outcome": "outcome"}
    return (
        item.get("alarm_name") == values[":alarm"]
        and item.get("status") in (values[":open"], values[":acknowledged"])
        and item.get("kind") in (values[":alarm_kind"], values[":incident_kind"])
        and item.get("outcome") == values[":reported"]
    )


class FakeTable:
    """A DynamoDB Table resource that evaluates the expressions the agent sends.

    Every condition, update and query shape the code uses is modelled; an unknown one
    fails the test, so a changed expression cannot pass against a stale fake. GSIs hold
    only the items that carry their hash attribute, sorted by created_at. ``errors``
    makes an operation raise.
    """

    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}
        self.puts: list[dict[str, Any]] = []
        self.updates: list[dict[str, Any]] = []
        self.gets: list[dict[str, Any]] = []
        self.queries: list[dict[str, Any]] = []
        self.errors: dict[str, BaseException] = {}

    def _raise_if_failing(self, operation: str) -> None:
        if operation in self.errors:
            raise self.errors[operation]

    @staticmethod
    def _check(condition: str | None, item: dict[str, Any] | None, values: dict[str, Any]) -> None:
        if condition is None:
            return
        if condition == "attribute_not_exists(pk)":
            passed = item is None
        elif condition == "attribute_not_exists(pk) OR #ttl < :now":
            passed = item is None or item["ttl"] < values[":now"]
        elif condition == "attribute_exists(pk)":
            passed = item is not None
        elif condition == "finding_id = :id":
            passed = item is not None and item.get("finding_id") == values[":id"]
        elif condition == "attribute_exists(pk) AND #ttl > :now":
            passed = item is not None and item["ttl"] > values[":now"]
        else:
            raise AssertionError(f"unmodelled condition {condition!r}")
        if not passed:
            raise client_error("ConditionalCheckFailedException", operation="Write")

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        self._raise_if_failing("put_item")
        self.puts.append(copy.deepcopy(kwargs))
        item = kwargs["Item"]
        self._check(
            kwargs.get("ConditionExpression"),
            self.items.get(item["pk"]),
            kwargs.get("ExpressionAttributeValues", {}),
        )
        self.items[item["pk"]] = copy.deepcopy(item)
        return {}

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self._raise_if_failing("get_item")
        self.gets.append(copy.deepcopy(kwargs))
        item = self.items.get(kwargs["Key"]["pk"])
        return {} if item is None else {"Item": copy.deepcopy(item)}

    def update_item(self, **kwargs: Any) -> dict[str, Any]:
        self._raise_if_failing("update_item")
        self.updates.append(copy.deepcopy(kwargs))
        pk = kwargs["Key"]["pk"]
        values = kwargs.get("ExpressionAttributeValues", {})
        self._check(kwargs.get("ConditionExpression"), self.items.get(pk), values)
        item = self.items.setdefault(pk, {"pk": pk})
        expression = kwargs["UpdateExpression"]
        if expression == "SET entries = :entries, #ttl = :ttl":
            assert kwargs["ExpressionAttributeNames"] == {"#ttl": "ttl"}
            item["entries"] = copy.deepcopy(values[":entries"])
            item["ttl"] = values[":ttl"]
            return {}
        if expression == "SET #ttl = :now":
            item["ttl"] = values[":now"]
            return {}
        if expression == "ADD #count :delta SET #ttl = if_not_exists(#ttl, :ttl)":
            item["count"] = item.get("count", Decimal(0)) + values[":delta"]
            item.setdefault("ttl", values[":ttl"])
            return {"Attributes": {"count": item["count"], "ttl": item["ttl"]}}
        if expression == (
            "ADD alarm_count :one, source_counts.#source :one, "
            "resource_counts.#resource :one SET last_seen_at = :now"
        ):
            names = kwargs["ExpressionAttributeNames"]
            item["alarm_count"] = item.get("alarm_count", 0) + values[":one"]
            for attribute, name in (("source_counts", "#source"), ("resource_counts", "#resource")):
                counts = item[attribute]
                counts[names[name]] = counts.get(names[name], 0) + values[":one"]
            item["last_seen_at"] = values[":now"]
            return {}
        if expression == "SET linked_to = :head, summary = :summary":
            item["linked_to"] = values[":head"]
            item["summary"] = values[":summary"]
            return {}
        if expression == "ADD recurrence_count :one SET last_seen_at = :now":
            item["recurrence_count"] = item.get("recurrence_count", 0) + values[":one"]
            item["last_seen_at"] = values[":now"]
            return {}
        if expression == (
            "SET linked_alarms = list_append(if_not_exists(linked_alarms, :empty), :alarm)"
        ):
            item["linked_alarms"] = item.get("linked_alarms", values[":empty"]) + values[":alarm"]
            return {}
        raise AssertionError(f"unmodelled update {expression!r}")

    def query(self, **kwargs: Any) -> dict[str, Any]:
        self._raise_if_failing("query")
        self.queries.append(copy.deepcopy(kwargs))
        attribute = INDEX_HASH_KEYS[kwargs["IndexName"]]
        names = kwargs.get("ExpressionAttributeNames", {})
        values = kwargs["ExpressionAttributeValues"]
        hash_name, hash_value = (
            part.strip() for part in kwargs["KeyConditionExpression"].split("=")
        )
        assert names.get(hash_name, hash_name) == attribute
        indexed = sorted(
            (item for item in self.items.values() if item.get(attribute) == values[hash_value]),
            key=lambda item: item["created_at"],
            reverse=not kwargs.get("ScanIndexForward", True),
        )
        start = kwargs.get("ExclusiveStartKey", {}).get("position", 0)
        limit = kwargs.get("Limit", len(indexed))
        page = indexed[start : start + limit]
        filtered = page
        if expression := kwargs.get("FilterExpression"):
            filtered = [item for item in page if _matches(expression, names, values, item)]
        response: dict[str, Any] = {"Items": copy.deepcopy(filtered)}
        if start + limit < len(indexed):
            response["LastEvaluatedKey"] = {"position": start + limit}
        return response

    def findings(self) -> list[dict[str, Any]]:
        return [item for pk, item in self.items.items() if pk.startswith("finding#")]


class FakeSqs(FakeClient):
    """An SQS client that keeps the messages sent to it, plus the FakeClient reads."""

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        super().__init__(responses)
        self.sent: list[dict[str, Any]] = []
        self.send_error: BaseException | None = None

    def send_message(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("send_message", copy.deepcopy(kwargs)))
        if self.send_error is not None:
            raise self.send_error
        self.sent.append(
            {"QueueUrl": kwargs["QueueUrl"], "body": json.loads(kwargs["MessageBody"])}
        )
        return {"MessageId": f"m-{len(self.sent)}"}


class FakeBedrock:
    """Answers converse calls from a script of responses or exceptions."""

    def __init__(self, *script: Any) -> None:
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    def converse(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(copy.deepcopy(kwargs))
        step = self.script.pop(0)
        if isinstance(step, BaseException):
            raise step
        response: dict[str, Any] = step
        return response


def converse_response(*blocks: dict[str, Any]) -> dict[str, Any]:
    return {
        "output": {"message": {"role": "assistant", "content": list(blocks)}},
        "stopReason": "tool_use",
    }


def tool_use(name: str, tool_input: dict[str, Any], tool_use_id: str = "t1") -> dict[str, Any]:
    return {"toolUse": {"toolUseId": tool_use_id, "name": name, "input": tool_input}}


def report(severity: str = "medium", **overrides: Any) -> dict[str, Any]:
    body = {
        "title": "Payment API 5xx after deploy",
        "summary": "Error rate rose to 7% at 14:02 right after a deploy.",
        "likely_cause": "Lambda payment-api-prod version 42 fails on startup.",
        "evidence": [{"kind": "metric", "detail": "Errors 0 -> 120 at 14:02"}],
        "actions": [
            {
                "kind": "change",
                "text": "Roll back the Lambda",
                "command": "deploy rollback payment-api-prod",
            }
        ],
        "severity": severity,
        "fix_effort": "low",
        "fix_effort_reason": "Rolling back one Lambda version is a single command.",
    }
    body.update(overrides)
    return tool_use("report_finding", body, tool_use_id="report")


def alarm_event(
    *,
    name: str = ALARM_NAME,
    state: str = "ALARM",
    detail_type: str = "CloudWatch Alarm State Change",
) -> dict[str, Any]:
    return {
        "version": "0",
        "id": "c4c1c1c9-6542-e61b-6ef0-8c4d36933a92",
        "detail-type": detail_type,
        "source": "aws.cloudwatch",
        "account": "111122223333",
        "time": "2026-09-29T14:05:00Z",
        "region": "us-east-1",
        "resources": [f"arn:aws:cloudwatch:us-east-1:111122223333:alarm:{name}"],
        "detail": {
            "alarmName": name,
            "state": {
                "value": state,
                "reason": "Threshold Crossed: 3 datapoints were greater than 5.0",
                "timestamp": "2026-09-29T14:05:00.000+0000",
            },
            "previousState": {"value": "OK"},
            "configuration": {"description": "Payment API error rate"},
        },
    }


DATADOG_FIXTURE = Path(__file__).parent / "fixtures" / "datadog_monitor_alert.json"
DATADOG_MONITOR_ID = 1234567
ECS_SERVICE_KEY = "AWS/ECS:ServiceName=checkout-api-prod"


def datadog_event(**detail: Any) -> dict[str, Any]:
    """The Datadog notification fixture, with top-level ``detail`` fields replaced."""
    event: dict[str, Any] = json.loads(DATADOG_FIXTURE.read_text())
    event["detail"].update(detail)
    return event


def datadog_monitor(**fields: Any) -> dict[str, Any]:
    """The fixture's monitor as GET /api/v1/monitor/{id} returns it, in Alert."""
    return {
        "id": DATADOG_MONITOR_ID,
        "name": "checkout-api 5xx rate",
        "type": "query alert",
        "query": (
            "sum(last_5m):sum:trace.http.request.errors{env:prod,source:ecs} "
            "by {service}.as_count() > 50"
        ),
        "tags": ["env:prod", "devops_agent:true", "source:ecs"],
        "priority": 2,
        "overall_state": "Alert",
        "state": {"groups": {"service:checkout-api-prod": {"status": "Alert"}}},
        **fields,
    }


def job(
    *names: str,
    kind: FindingKind = FindingKind.ALARM,
    keys: tuple[str, ...] = (FUNCTION_KEY,),
    floor: Severity = Severity.HIGH,
    finding_id: str | None = None,
    alarm_count: int | None = None,
) -> InvestigationJob:
    """A work-queue job for the named alarms (default: the one test alarm)."""
    events = [alarm_event(name=name) for name in names or (ALARM_NAME,)]
    return InvestigationJob.model_validate(
        {
            "finding_id": finding_id or str(uuid.uuid4()),
            "kind": kind,
            "alarms": events,
            "alarm_count": alarm_count or len(events),
            "keys": list(keys),
            "floor": floor,
        }
    )


def datadog_job(*, finding_id: str | None = None, extra: int = 0) -> InvestigationJob:
    """A work-queue job for the fixture's Datadog signal, with ``extra`` alarms after it."""
    signal = parse_signal(datadog_event())
    assert signal is not None
    events = [alarm_event(name=f"extra-{n}-errors") for n in range(extra)]
    alarms = [AlarmStateChangeEvent.model_validate(event) for event in events]
    return InvestigationJob(
        finding_id=finding_id or str(uuid.uuid4()),
        kind=FindingKind.INCIDENT if extra else FindingKind.ALARM,
        signals=[
            signal.model_copy(update={"priority": 2}).as_ref(),
            *(SignalRef.for_alarm(alarm, Severity.HIGH) for alarm in alarms),
        ],
        alarms=alarms,
        alarm_count=1 + extra,
        keys=signal.resource_keys,
        floor=Severity.HIGH,
    )


def sqs_record(body: Any, message_id: str = "msg-1") -> dict[str, Any]:
    """An SQS Lambda event record; a model is sent as JSON with its aliases."""
    text = body if isinstance(body, str) else json.dumps(body)
    return {"messageId": message_id, "receiptHandle": "rh", "body": text, "eventSource": "aws:sqs"}


class FakeSession:
    """An AccountSession: one FakeClient per service, the same one for aws_call."""

    def __init__(self, account_id: str = "") -> None:
        self.account_id = account_id
        self.clients: dict[str, FakeClient] = {}

    def client(self, service: str) -> FakeClient:
        return self.clients.setdefault(service, FakeClient())

    def aws_call_client(self, service: str) -> FakeClient:
        return self.client(service)


class FakeInvestigator:
    """The investigator's clients: its own (Bedrock, SNS, STS, the table) and the job's
    session, which every read of the investigated account goes through."""

    def __init__(self) -> None:
        self.bedrock = FakeBedrock()
        self.sns = FakeClient()
        self.sts = FakeClient()
        self.table = FakeTable()
        self.session = FakeSession()

    def __getattr__(self, name: str) -> FakeClient:
        if name.startswith("_"):
            raise AttributeError(name)
        return self.session.client(name)


def patch_investigator(mocker: Any) -> FakeInvestigator:
    """Run the investigator handler on fakes: its own clients and every job's session."""
    from devops_agent import handler as handler_module

    fake = FakeInvestigator()
    mocker.patch.object(
        handler_module,
        "agent_clients",
        return_value=handler_module.AgentClients(
            bedrock=fake.bedrock, sns=fake.sns, sts=fake.sts, table=fake.table
        ),
    )
    mocker.patch.object(handler_module, "open_session", return_value=fake.session)
    return fake


OWN_ACCOUNT = "111122223333"
MEMBER_ACCOUNT = "444455556666"
OTHER_ACCOUNT = "777788889999"
OWN_ACCESS_KEY = "own-key-0000000000"
FUNCTION_ARN = f"arn:aws:lambda:us-east-1:{OWN_ACCOUNT}:function:devops-agent-prod"


def lambda_context(arn: str | None = FUNCTION_ARN, seconds_left: float = 600.0) -> Any:
    """A Lambda context of the agent's function in its own account."""
    context = MagicMock()
    context.invoked_function_arn = arn
    context.aws_request_id = "req-1"
    context.get_remaining_time_in_millis.return_value = int(seconds_left * 1000)
    return context


def member_alarm_event(name: str = ALARM_NAME, account: str = MEMBER_ACCOUNT) -> dict[str, Any]:
    """An alarm event forwarded from a member account."""
    event = alarm_event(name=name)
    event["account"] = account
    event["resources"] = [f"arn:aws:cloudwatch:us-east-1:{account}:alarm:{name}"]
    return event


def signing_key(client: Any) -> str:
    """The access key a boto3 client signs with."""
    key: str = client._request_signer._credentials.get_frozen_credentials().access_key
    return key


def member_credentials(account: str) -> dict[str, Any]:
    """AssumeRole credentials for a member account, built at run time."""
    return {
        "AccessKeyId": f"member-key-{account}",
        "SecretAccessKey": f"member-secret-{account}",
        "SessionToken": f"member-token-{account}",
        "Expiration": datetime.now(UTC) + timedelta(hours=1),
    }


def stubbed_sts() -> tuple[Any, Stubber]:
    """A real STS client on the agent's own credentials, answering from a Stubber."""
    sts = boto3.client(
        "sts",
        region_name="us-east-1",
        aws_access_key_id=OWN_ACCESS_KEY,
        aws_secret_access_key="own-secret",
    )
    stubber = Stubber(sts)
    stubber.activate()
    return sts, stubber


@pytest.fixture()
def own_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """The agent's own credentials, as Lambda puts them in the environment."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", OWN_ACCESS_KEY)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "own-secret")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


# ToolContext fields that hold the alarm, not a client.
ALARM_FIELDS = frozenset({"alarm_name", "alarm_time"})


GITHUB_ORG = "acme"
GITHUB_APP_ID = "123456"
GITHUB_INSTALLATION_ID = "7890123"


@functools.lru_cache(maxsize=1)
def github_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def github_private_pem() -> str:
    """A test-only App private key, generated once per run."""
    return (
        github_private_key()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )


@pytest.fixture(autouse=True)
def _no_cached_monitors() -> Iterator[None]:
    clear_monitor_cache()
    yield
    clear_monitor_cache()


@pytest.fixture(autouse=True)
def _no_cached_github_tokens() -> Iterator[None]:
    github_module._installation_tokens.clear()
    yield
    github_module._installation_tokens.clear()


def fake_github() -> FakeClient:
    """A FakeClient standing in for GitHubClient, with its org."""
    client = FakeClient()
    client.org = GITHUB_ORG  # type: ignore[attr-defined]
    return client


@pytest.fixture()
def tool_ctx() -> ToolContext:
    return ToolContext(
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
        alarm_name=ALARM_NAME,
        datadog=FakeClient(),
        github=fake_github(),
        aws_client=FakeClients(),
    )


def has_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(has_float(item) for item in value.values())
    if isinstance(value, list):
        return any(has_float(item) for item in value)
    return False
