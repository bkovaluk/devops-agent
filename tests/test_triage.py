"""Triage: parse, resource keys, repeat, link, storm, budgets, emit."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pytest_mock import MockerFixture

from devops_agent import triage as triage_module
from devops_agent.datadog import DatadogError
from devops_agent.models import InvestigationJob
from devops_agent.signals import parse_signal
from devops_agent.triage import TriageClients, handler
from tests.conftest import (
    ALARM_NAME,
    ALARMS_QUEUE_URL,
    DATADOG_MONITOR_ID,
    ECS_SERVICE_KEY,
    FUNCTION_KEY,
    OWN_ACCOUNT,
    WORK_QUEUE_URL,
    FakeClient,
    FakeSqs,
    FakeTable,
    alarm_event,
    client_error,
    datadog_event,
    datadog_monitor,
    sqs_record,
)

FUNCTION = "payment-api-prod"
QUEUE_ARN = "arn:aws:sqs:us-east-1:111122223333:orders"
STREAM_ARN = "arn:aws:kinesis:us-east-1:111122223333:stream/events"


def _metric_alarm(name: str, namespace: str, dimensions: dict[str, str]) -> dict[str, Any]:
    return {
        "AlarmName": name,
        "AlarmArn": f"arn:aws:cloudwatch:us-east-1:111122223333:alarm:{name}",
        "Namespace": namespace,
        "MetricName": "Errors",
        "Dimensions": [{"Name": key, "Value": value} for key, value in dimensions.items()],
    }


class Account:
    """Alarm configs and tags by alarm name; unknown alarms watch their own function."""

    def __init__(self) -> None:
        self.alarms: dict[str, dict[str, Any]] = {}
        self.tags: dict[str, dict[str, str]] = {}
        self.broken: set[str] = set()

    def describe_alarms(self, **kwargs: Any) -> dict[str, Any]:
        [name] = kwargs["AlarmNames"]
        if name in self.broken:
            raise RuntimeError("describe broke")
        if name == ALARM_NAME:
            default = _metric_alarm(name, "AWS/Lambda", {"FunctionName": FUNCTION})
        else:
            default = _metric_alarm(name, "AWS/Lambda", {"FunctionName": f"fn-{name}"})
        alarm = self.alarms.get(name, default)
        if alarm.get("AlarmRule"):
            return {"MetricAlarms": [], "CompositeAlarms": [alarm]}
        return {"MetricAlarms": [alarm] if alarm else [], "CompositeAlarms": []}

    def list_tags_for_resource(self, **kwargs: Any) -> dict[str, Any]:
        name = kwargs["ResourceARN"].rsplit(":alarm:", 1)[1]
        tags = self.tags.get(name, {})
        return {"Tags": [{"Key": key, "Value": value} for key, value in tags.items()]}


@pytest.fixture()
def account() -> Account:
    return Account()


@pytest.fixture()
def clients(mocker: MockerFixture, account: Account) -> TriageClients:
    built = TriageClients(
        cloudwatch=FakeClient(
            {
                "describe_alarms": account.describe_alarms,
                "list_tags_for_resource": account.list_tags_for_resource,
            }
        ),
        lambda_=FakeClient({"list_event_source_mappings": {"EventSourceMappings": []}}),
        sqs=FakeSqs(),
        kinesis=FakeClient(),
        sts=FakeClient({"get_caller_identity": {"Account": OWN_ACCOUNT}}),
        table=FakeTable(),
    )
    mocker.patch.object(triage_module, "triage_clients", return_value=built)
    return built


def _batch(*events: Any) -> dict[str, Any]:
    return {
        "Records": [
            sqs_record(event, message_id=f"msg-{n}") for n, event in enumerate(events, start=1)
        ]
    }


def _work(clients: TriageClients) -> list[dict[str, Any]]:
    return [message for message in clients.sqs.sent if message["QueueUrl"] == WORK_QUEUE_URL]


def _retries(clients: TriageClients) -> list[dict[str, Any]]:
    """The alarm events sent back to the alarms queue, with their send arguments."""
    return [
        {**kwargs, "body": json.loads(kwargs["MessageBody"])}
        for operation, kwargs in clients.sqs.calls
        if operation == "send_message" and kwargs["QueueUrl"] == ALARMS_QUEUE_URL
    ]


def _jobs(clients: TriageClients) -> list[InvestigationJob]:
    return [InvestigationJob.model_validate(message["body"]) for message in _work(clients)]


def _kinds(clients: TriageClients) -> list[str]:
    return sorted(item["kind"] for item in clients.table.findings())


def _env(monkeypatch: pytest.MonkeyPatch, env: str) -> None:
    monkeypatch.setenv("ENVIRONMENT", env)
    monkeypatch.setenv("SLACK_TOPIC_ARN", f"arn:aws:sns:us-east-1:111122223333:ops-alerts-{env}")
    triage_module.get_triage_settings.cache_clear()


# Step 1: parse, drop, dedupe


@pytest.mark.parametrize(
    "body",
    [
        alarm_event(state="OK"),
        alarm_event(detail_type="EC2 Instance State-change Notification"),
        alarm_event(name="devops-agent-errors-prod"),
        {"detail-type": "CloudWatch Alarm State Change", "detail": {}},
        "not json",
    ],
)
def test_events_that_are_not_alarm_entries_are_dropped(clients: TriageClients, body: Any) -> None:
    assert handler(_batch(body), None) == {"batchItemFailures": []}
    assert _work(clients) == []
    assert clients.table.puts == []
    assert clients.cloudwatch.calls == []


def test_an_alarm_twice_in_a_batch_is_one_job(clients: TriageClients) -> None:
    handler(_batch(alarm_event(), alarm_event()), None)
    assert len(_work(clients)) == 1
    assert clients.cloudwatch.operations().count("describe_alarms") == 1


# Step 2: resource keys and the consumer chain


def test_lambda_alarm_is_keyed_by_function(clients: TriageClients) -> None:
    handler(_batch(alarm_event()), None)
    [work] = _jobs(clients)
    assert work.keys == [FUNCTION_KEY]


def test_queue_alarm_adds_its_consumer_lambdas(clients: TriageClients, account: Account) -> None:
    account.alarms[ALARM_NAME] = _metric_alarm(ALARM_NAME, "AWS/SQS", {"QueueName": "orders"})
    clients.sqs.responses.update(
        {
            "get_queue_url": {"QueueUrl": "https://sqs/orders"},
            "get_queue_attributes": {"Attributes": {"QueueArn": QUEUE_ARN}},
        }
    )
    clients.lambda_.responses["list_event_source_mappings"] = {
        "EventSourceMappings": [
            {"FunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:orders-worker"}
        ]
    }
    handler(_batch(alarm_event()), None)
    [work] = _jobs(clients)
    assert work.keys == [
        "AWS/SQS:QueueName=orders",
        "AWS/Lambda:FunctionName=orders-worker",
    ]
    assert dict(clients.lambda_.calls)["list_event_source_mappings"]["EventSourceArn"] == QUEUE_ARN


def test_stream_alarm_adds_its_consumer_lambdas(clients: TriageClients, account: Account) -> None:
    account.alarms[ALARM_NAME] = _metric_alarm(ALARM_NAME, "AWS/Kinesis", {"StreamName": "events"})
    clients.kinesis.responses["describe_stream_summary"] = {
        "StreamDescriptionSummary": {"StreamARN": STREAM_ARN}
    }
    clients.lambda_.responses["list_event_source_mappings"] = {
        "EventSourceMappings": [
            {"FunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:events-indexer"}
        ]
    }
    handler(_batch(alarm_event()), None)
    [work] = _jobs(clients)
    assert work.keys == [
        "AWS/Kinesis:StreamName=events",
        "AWS/Lambda:FunctionName=events-indexer",
    ]


def test_consumer_chain_failure_keeps_the_primary_key(
    clients: TriageClients, account: Account
) -> None:
    account.alarms[ALARM_NAME] = _metric_alarm(ALARM_NAME, "AWS/SQS", {"QueueName": "orders"})
    clients.sqs.responses["get_queue_url"] = client_error("AWS.SimpleQueueService.NonExistentQueue")
    handler(_batch(alarm_event()), None)
    [work] = _jobs(clients)
    assert work.keys == ["AWS/SQS:QueueName=orders"]


@pytest.mark.parametrize(
    ("namespace", "dimensions", "key"),
    [
        (
            "AWS/RDS",
            {"DBInstanceIdentifier": "db-1", "DBClusterIdentifier": "core"},
            "AWS/RDS:DBClusterIdentifier=core",
        ),
        ("AWS/RDS", {"DBInstanceIdentifier": "db-1"}, "AWS/RDS:DBInstanceIdentifier=db-1"),
        ("Custom/App", {"Service": "search", "Stage": "prod"}, "Custom/App:Service=search"),
        ("Custom/App", {}, f"alarm:{ALARM_NAME}"),
    ],
)
def test_primary_dimension_names_the_resource(
    clients: TriageClients,
    account: Account,
    namespace: str,
    dimensions: dict[str, str],
    key: str,
) -> None:
    account.alarms[ALARM_NAME] = _metric_alarm(ALARM_NAME, namespace, dimensions)
    handler(_batch(alarm_event()), None)
    assert _jobs(clients)[0].keys == [key]


@pytest.mark.parametrize(
    "alarm",
    [
        {"AlarmName": ALARM_NAME, "AlarmArn": "arn", "AlarmRule": "ALARM(a) OR ALARM(b)"},
        {
            "AlarmName": ALARM_NAME,
            "AlarmArn": "arn",
            "Metrics": [{"Id": "e1", "Expression": "m1 / m2"}],
        },
        {},
    ],
    ids=["composite", "metric-math", "deleted"],
)
def test_alarm_without_one_metric_is_keyed_by_name(
    clients: TriageClients, account: Account, alarm: dict[str, Any]
) -> None:
    account.alarms[ALARM_NAME] = alarm
    handler(_batch(alarm_event()), None)
    assert _jobs(clients)[0].keys == [f"alarm:{ALARM_NAME}"]


def test_unreadable_alarm_is_keyed_by_name(clients: TriageClients) -> None:
    clients.cloudwatch.responses["describe_alarms"] = client_error("Throttling")
    handler(_batch(alarm_event()), None)
    assert _jobs(clients)[0].keys == [f"alarm:{ALARM_NAME}"]


# Severity floor


def test_untagged_low_floor_alarm_is_a_job(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(monkeypatch, "dev")
    assert handler(_batch(alarm_event()), None) == {"batchItemFailures": []}
    [work] = _jobs(clients)
    assert work.floor == "low"
    assert work.keys == [FUNCTION_KEY]
    assert clients.table.findings() == []


def test_tag_failure_falls_back_to_env_floor(clients: TriageClients) -> None:
    clients.cloudwatch.responses["list_tags_for_resource"] = client_error("AccessDenied")
    handler(_batch(alarm_event()), None)
    assert _jobs(clients)[0].floor == "high"


# Step 3: repeat


def _open_finding(table: FakeTable, finding_id: str, floor: str, **fields: Any) -> None:
    """An open investigated finding as the investigator stores it."""
    table.items[f"finding#{finding_id}"] = {
        "pk": f"finding#{finding_id}",
        "finding_id": finding_id,
        "created_at": "2026-09-29T13:00:00+00:00",
        "env": "prod",
        "kind": "alarm",
        "outcome": "reported",
        "status": "open",
        "alarm_name": ALARM_NAME,
        "severity": floor,
        "severity_floor": floor,
        "resource_key": FUNCTION_KEY,
        "recurrence_count": 0,
        "linked_alarms": [],
        **fields,
    }


def test_open_repeat_increments_the_open_finding(clients: TriageClients) -> None:
    _open_finding(clients.table, "f-open", "high")
    assert handler(_batch(alarm_event()), None) == {"batchItemFailures": []}
    item = clients.table.items["finding#f-open"]
    assert item["recurrence_count"] == 1
    assert item["last_seen_at"]
    assert _work(clients) == []
    assert len(clients.table.findings()) == 1
    query = clients.table.queries[0]
    assert query["IndexName"] == "by_resource"
    assert query["ExpressionAttributeValues"][":key"] == FUNCTION_KEY
    assert query["ExpressionAttributeValues"][":alarm"] == ALARM_NAME
    assert query["ScanIndexForward"] is False
    assert query["Limit"] == 50


def test_acknowledged_finding_counts_as_a_repeat(clients: TriageClients) -> None:
    _open_finding(clients.table, "f-ack", "high", status="acknowledged")
    handler(_batch(alarm_event()), None)
    assert clients.table.items["finding#f-ack"]["recurrence_count"] == 1
    assert _work(clients) == []


def test_open_incident_counts_as_a_repeat(clients: TriageClients) -> None:
    _open_finding(clients.table, "inc", "high", kind="incident")
    handler(_batch(alarm_event()), None)
    assert clients.table.items["finding#inc"]["recurrence_count"] == 1
    assert _work(clients) == []


def test_floor_escalation_is_investigated_again(clients: TriageClients, account: Account) -> None:
    _open_finding(clients.table, "f-open", "high")
    account.tags[ALARM_NAME] = {"Severity": "critical"}
    handler(_batch(alarm_event()), None)
    assert clients.table.items["finding#f-open"]["recurrence_count"] == 0
    assert _jobs(clients)[0].floor == "critical"


@pytest.mark.parametrize(
    "fields",
    [
        {"status": "closed", "resolution": "confirmed"},
        {"outcome": "incomplete"},
        {"kind": "deferred", "outcome": "triaged"},
        {"kind": "linked", "outcome": "triaged"},
        {"kind": "grouped", "outcome": "triaged"},
        {"kind": "skipped", "outcome": "triaged"},
    ],
    ids=["closed", "incomplete", "deferred", "linked", "grouped", "skipped"],
)
def test_non_investigations_do_not_block_an_investigation(
    clients: TriageClients, fields: dict[str, Any]
) -> None:
    _open_finding(clients.table, "f-other", "high", **fields)
    handler(_batch(alarm_event()), None)
    assert len(_work(clients)) == 1
    assert clients.table.items["finding#f-other"]["recurrence_count"] == 0


def test_deferred_alarm_is_investigated_on_its_next_firing(clients: TriageClients) -> None:
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(alarm_event()), None)
    assert _kinds(clients) == ["deferred"]
    clients.table.items[_hour_pk()]["count"] = 0
    handler({"Records": [sqs_record(alarm_event(), message_id="msg-later")]}, None)
    assert len(_work(clients)) == 1


# Step 4: link to a running job


def _active(table: FakeTable, key: str, finding_id: str, ttl: int) -> None:
    table.items[f"active#{key}"] = {
        "pk": f"active#{key}",
        "finding_id": finding_id,
        "linked_alarms": [],
        "ttl": ttl,
    }


def test_alarm_on_an_active_key_is_linked(clients: TriageClients) -> None:
    _active(clients.table, FUNCTION_KEY, "f-running", int(time.time()) + 600)
    assert handler(_batch(alarm_event()), None) == {"batchItemFailures": []}
    assert _work(clients) == []
    [item] = clients.table.findings()
    assert item["kind"] == "linked"
    assert item["linked_to"] == "f-running"
    assert clients.table.items[f"active#{FUNCTION_KEY}"]["linked_alarms"] == [ALARM_NAME]


def test_link_via_a_consumer_key(clients: TriageClients, account: Account) -> None:
    account.alarms[ALARM_NAME] = _metric_alarm(ALARM_NAME, "AWS/SQS", {"QueueName": "orders"})
    clients.sqs.responses.update(
        {
            "get_queue_url": {"QueueUrl": "https://sqs/orders"},
            "get_queue_attributes": {"Attributes": {"QueueArn": QUEUE_ARN}},
        }
    )
    clients.lambda_.responses["list_event_source_mappings"] = {
        "EventSourceMappings": [
            {"FunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:orders-worker"}
        ]
    }
    consumer_key = "AWS/Lambda:FunctionName=orders-worker"
    _active(clients.table, consumer_key, "f-worker", int(time.time()) + 600)
    handler(_batch(alarm_event()), None)
    [item] = clients.table.findings()
    assert item["kind"] == "linked"
    assert item["linked_to"] == "f-worker"
    assert item["resource_key"] == "AWS/SQS:QueueName=orders"


def test_expired_active_item_is_not_linked(clients: TriageClients) -> None:
    _active(clients.table, FUNCTION_KEY, "f-old", int(time.time()) - 1)
    handler(_batch(alarm_event()), None)
    assert len(_work(clients)) == 1
    assert _kinds(clients) == []


# Step 5: storm


def _storm(count: int) -> list[dict[str, Any]]:
    return [alarm_event(name=f"svc-{n:02d}-errors") for n in range(count)]


def test_below_the_storm_threshold_each_alarm_is_a_job(clients: TriageClients) -> None:
    handler(_batch(*_storm(4)), None)
    jobs = _jobs(clients)
    assert [work.kind for work in jobs] == ["alarm"] * 4
    assert _kinds(clients) == []


def test_storm_is_one_incident_with_grouped_findings(
    clients: TriageClients, account: Account
) -> None:
    account.tags["svc-03-errors"] = {"Severity": "critical"}
    assert handler(_batch(*_storm(5)), None) == {"batchItemFailures": []}
    [incident] = _jobs(clients)
    assert incident.kind == "incident"
    assert incident.alarm_count == 5
    assert incident.alarm.alarm_name == "svc-03-errors"
    assert incident.floor == "critical"
    assert sorted(event.alarm_name for event in incident.alarms) == [
        f"svc-{n:02d}-errors" for n in range(5)
    ]
    assert len(incident.keys) == 5
    grouped = clients.table.findings()
    assert [item["kind"] for item in grouped] == ["grouped"] * 4
    assert {item["incident_id"] for item in grouped} == {incident.finding_id}
    assert "svc-03-errors" not in {item["alarm_name"] for item in grouped}


def test_storm_listing_is_bounded(clients: TriageClients) -> None:
    handler(_batch(*_storm(60)), None)
    [incident] = _jobs(clients)
    assert len(incident.alarms) == 50
    assert incident.alarm_count == 60
    assert len(clients.table.findings()) == 59


def test_storm_threshold_is_configurable(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STORM_THRESHOLD", "3")
    triage_module.get_triage_settings.cache_clear()
    handler(_batch(*_storm(3)), None)
    assert [work.kind for work in _jobs(clients)] == ["incident"]


def test_settled_alarms_do_not_count_toward_a_storm(clients: TriageClients) -> None:
    events = _storm(5)
    _active(
        clients.table, "AWS/Lambda:FunctionName=fn-svc-00-errors", "f-x", int(time.time()) + 600
    )
    handler(_batch(*events), None)
    assert [work.kind for work in _jobs(clients)] == ["alarm"] * 4


# In-batch linking


def _same_function(account: Account, *names: str) -> None:
    for name in names:
        account.alarms[name] = _metric_alarm(name, "AWS/Lambda", {"FunctionName": FUNCTION})


def test_alarms_sharing_a_key_in_one_batch_are_one_job(
    clients: TriageClients, account: Account
) -> None:
    _same_function(account, "payment-errors", "payment-duration")
    account.tags["payment-duration"] = {"Severity": "critical"}
    events = [alarm_event(name="payment-errors"), alarm_event(name="payment-duration")]
    assert handler(_batch(*events), None) == {"batchItemFailures": []}

    [work] = _jobs(clients)
    assert work.alarm.alarm_name == "payment-duration"
    [linked] = clients.table.findings()
    assert linked["kind"] == "linked"
    assert linked["alarm_name"] == "payment-errors"
    assert linked["linked_to"] == work.finding_id
    active = clients.table.items[f"active#{FUNCTION_KEY}"]
    assert active["finding_id"] == work.finding_id
    assert active["linked_alarms"] == ["payment-errors"]
    assert clients.table.items[_hour_pk()]["count"] == 1


def test_in_batch_link_follows_the_consumer_chain(clients: TriageClients, account: Account) -> None:
    account.alarms["orders-age"] = _metric_alarm("orders-age", "AWS/SQS", {"QueueName": "orders"})
    account.alarms["worker-errors"] = _metric_alarm(
        "worker-errors", "AWS/Lambda", {"FunctionName": "orders-worker"}
    )
    clients.sqs.responses.update(
        {
            "get_queue_url": {"QueueUrl": "https://sqs/orders"},
            "get_queue_attributes": {"Attributes": {"QueueArn": QUEUE_ARN}},
        }
    )
    clients.lambda_.responses["list_event_source_mappings"] = {
        "EventSourceMappings": [
            {"FunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:orders-worker"}
        ]
    }
    handler(_batch(alarm_event(name="orders-age"), alarm_event(name="worker-errors")), None)
    [work] = _jobs(clients)
    assert work.alarm.alarm_name == "orders-age"
    [linked] = clients.table.findings()
    assert linked["alarm_name"] == "worker-errors"
    assert linked["linked_to"] == work.finding_id
    consumer = clients.table.items["active#AWS/Lambda:FunctionName=orders-worker"]
    assert consumer["linked_alarms"] == ["worker-errors"]


def test_storm_counts_distinct_jobs_after_in_batch_links(
    clients: TriageClients, account: Account
) -> None:
    _same_function(account, "svc-00-errors", "svc-01-errors")
    handler(_batch(*_storm(5)), None)
    jobs = _jobs(clients)
    assert [work.kind for work in jobs] == ["alarm"] * 4
    assert _kinds(clients) == ["linked"]


def test_storm_links_followers_to_the_incident(clients: TriageClients, account: Account) -> None:
    _same_function(account, "svc-00-errors", "svc-06-errors")
    handler(_batch(*_storm(7)), None)
    [incident] = _jobs(clients)
    assert incident.kind == "incident"
    assert incident.alarm_count == 6
    findings = clients.table.findings()
    [linked] = [item for item in findings if item["kind"] == "linked"]
    assert linked["alarm_name"] == "svc-06-errors"
    assert linked["linked_to"] == incident.finding_id
    assert sorted(item["kind"] for item in findings) == ["grouped"] * 5 + ["linked"]


def test_followers_fail_with_their_job(clients: TriageClients, account: Account) -> None:
    _same_function(account, "payment-errors", "payment-duration")
    clients.sqs.send_error = RuntimeError("down")
    events = [alarm_event(name="payment-errors"), alarm_event(name="payment-duration")]
    result = handler(_batch(*events), None)
    assert sorted(f["itemIdentifier"] for f in result["batchItemFailures"]) == ["msg-1", "msg-2"]
    assert clients.table.findings() == []


def test_followers_of_a_deferred_job_link_to_the_deferred_finding(
    clients: TriageClients, account: Account
) -> None:
    _same_function(account, "payment-errors", "payment-duration")
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(alarm_event(name="payment-errors"), alarm_event(name="payment-duration")), None)
    findings = clients.table.findings()
    [deferred] = [item for item in findings if item["kind"] == "deferred"]
    [linked] = [item for item in findings if item["kind"] == "linked"]
    assert linked["linked_to"] == deferred["finding_id"]
    active = clients.table.items[f"active#{FUNCTION_KEY}"]
    assert active["ttl"] <= int(time.time())
    assert active["linked_alarms"] == []


# Step 6: budgets


def _budget(table: FakeTable, pk: str, count: int) -> None:
    table.items[pk] = {"pk": pk, "count": count, "ttl": int(time.time()) + 3600}


def _hour_pk() -> str:
    return "budget#" + triage_module.datetime.now(triage_module.UTC).strftime("%Y-%m-%dT%H")


def _day_pk() -> str:
    return "budget#" + triage_module.datetime.now(triage_module.UTC).strftime("%Y-%m-%d")


def test_job_counts_against_hourly_and_daily_budgets(clients: TriageClients) -> None:
    handler(_batch(alarm_event()), None)
    assert clients.table.items[_hour_pk()]["count"] == 1
    assert clients.table.items[_day_pk()]["count"] == 1


def test_incident_counts_once(clients: TriageClients) -> None:
    handler(_batch(*_storm(6)), None)
    assert clients.table.items[_hour_pk()]["count"] == 1
    assert clients.table.items[_day_pk()]["count"] == 1


def test_spent_hourly_budget_defers(clients: TriageClients) -> None:
    _budget(clients.table, _hour_pk(), 10)
    assert handler(_batch(alarm_event()), None) == {"batchItemFailures": []}
    assert _work(clients) == []
    [item] = clients.table.findings()
    assert item["kind"] == "deferred"
    assert "hourly investigation budget is spent" in item["summary"]


def test_spent_daily_budget_defers(clients: TriageClients) -> None:
    _budget(clients.table, _day_pk(), 50)
    handler(_batch(alarm_event()), None)
    assert _work(clients) == []
    [item] = clients.table.findings()
    assert item["kind"] == "deferred"
    assert "daily investigation budget is spent" in item["summary"]


def test_deferred_storm_groups_under_the_deferred_finding(clients: TriageClients) -> None:
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(*_storm(5)), None)
    findings = clients.table.findings()
    [deferred] = [item for item in findings if item["kind"] == "deferred"]
    grouped = [item for item in findings if item["kind"] == "grouped"]
    assert deferred["title"] == "Deferred: storm of 5 alarms"
    assert deferred["alarm_count"] == 5
    assert len(deferred["member_alarms"]) == 5
    assert deferred["member_alarms"][0] == deferred["alarm_name"]
    assert len(grouped) == 4
    assert {item["incident_id"] for item in grouped} == {deferred["finding_id"]}


@pytest.mark.parametrize(("count", "skipped"), [(4, False), (5, True)])
def test_low_floor_is_skipped_at_half_the_hourly_budget(
    clients: TriageClients,
    monkeypatch: pytest.MonkeyPatch,
    count: int,
    skipped: bool,
) -> None:
    _env(monkeypatch, "dev")
    _budget(clients.table, _hour_pk(), count)
    handler(_batch(alarm_event()), None)
    assert (_work(clients) == []) is skipped
    assert _kinds(clients) == (["skipped"] if skipped else [])
    if skipped:
        assert "half spent" in clients.table.findings()[0]["summary"]
        assert clients.table.items[_hour_pk()]["count"] == count


@pytest.mark.parametrize(("count", "skipped"), [(6, False), (7, True)])
def test_medium_floor_may_not_use_the_hourly_reserve(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch, count: int, skipped: bool
) -> None:
    _env(monkeypatch, "staging")
    _budget(clients.table, _hour_pk(), count)
    handler(_batch(alarm_event()), None)
    assert (_work(clients) == []) is skipped
    assert _kinds(clients) == (["skipped"] if skipped else [])
    assert _retries(clients) == []


# Step 7: emit


def test_job_is_emitted_with_a_pre_allocated_id_and_active_items(clients: TriageClients) -> None:
    before = int(time.time())
    handler(_batch(alarm_event()), None)
    [message] = _work(clients)
    assert message["QueueUrl"] == WORK_QUEUE_URL
    body = message["body"]
    assert set(body) == {
        "finding_id",
        "kind",
        "signals",
        "alarms",
        "alarm_count",
        "keys",
        "floor",
        "account_id",
        "region",
    }
    assert body["account_id"] == "111122223333"
    assert body["region"] == "us-east-1"
    assert body["signals"][0]["source"] == "cloudwatch"
    assert body["signals"][0]["name"] == ALARM_NAME
    assert body["signals"][0]["priority"] == 2
    assert body["kind"] == "alarm"
    assert body["floor"] == "high"
    assert body["keys"] == [FUNCTION_KEY]
    assert body["alarms"][0]["detail-type"] == "CloudWatch Alarm State Change"
    assert body["alarms"][0]["detail"]["alarmName"] == ALARM_NAME

    active = clients.table.items[f"active#{FUNCTION_KEY}"]
    assert active["finding_id"] == body["finding_id"]
    assert active["linked_alarms"] == []
    assert before + 1200 <= active["ttl"] <= int(time.time()) + 1200
    assert clients.table.findings() == []


def test_storm_writes_active_items_for_every_key(clients: TriageClients) -> None:
    handler(_batch(*_storm(5)), None)
    [incident] = _jobs(clients)
    for key in incident.keys:
        assert clients.table.items[f"active#{key}"]["finding_id"] == incident.finding_id


def test_send_failure_releases_active_items_and_fails_the_records(
    clients: TriageClients,
) -> None:
    clients.sqs.send_error = client_error("AWS.SimpleQueueService.NonExistentQueue")
    result = handler(_batch(alarm_event(), alarm_event()), None)
    assert result == {
        "batchItemFailures": [{"itemIdentifier": "msg-1"}, {"itemIdentifier": "msg-2"}]
    }
    assert clients.table.items[f"active#{FUNCTION_KEY}"]["ttl"] <= int(time.time())


def test_release_leaves_a_key_another_job_claimed(clients: TriageClients) -> None:
    now = triage_module.datetime.now(triage_module.UTC)
    _active(clients.table, FUNCTION_KEY, "f-other", int(time.time()) + 600)
    triage_module.release_keys(clients.table, [FUNCTION_KEY], "f-mine", now)
    assert clients.table.items[f"active#{FUNCTION_KEY}"]["ttl"] > int(time.time())


def test_send_failure_moves_no_budget_counter(clients: TriageClients) -> None:
    clients.sqs.send_error = RuntimeError("down")
    handler(_batch(alarm_event()), None)
    assert clients.table.items[_hour_pk()]["count"] == 0
    assert clients.table.items[_day_pk()]["count"] == 0


def test_refused_job_keeps_no_count(clients: TriageClients) -> None:
    _budget(clients.table, _day_pk(), 50)
    handler(_batch(alarm_event()), None)
    assert clients.table.items[_hour_pk()]["count"] == 0
    assert clients.table.items[_day_pk()]["count"] == 50


def test_member_store_failure_after_send_does_not_fail_records(
    clients: TriageClients, mocker: MockerFixture
) -> None:
    mocker.patch.object(triage_module, "_store_grouped", side_effect=RuntimeError("table down"))
    result = handler(_batch(*_storm(5)), None)
    assert result == {"batchItemFailures": []}
    assert len(_work(clients)) == 1


# Concurrent triage invocations


def test_claim_on_a_key_another_job_holds_is_refused(clients: TriageClients) -> None:
    now = triage_module.datetime.now(triage_module.UTC)
    other_key = "AWS/SQS:QueueName=orders"
    assert triage_module.claim_keys(clients.table, [FUNCTION_KEY], "f-first", now) is None
    conflict = triage_module.claim_keys(clients.table, [other_key, FUNCTION_KEY], "f-second", now)
    assert conflict == (FUNCTION_KEY, "f-first")
    assert clients.table.items[f"active#{FUNCTION_KEY}"]["finding_id"] == "f-first"
    assert clients.table.items[f"active#{other_key}"]["ttl"] <= int(now.timestamp())


def test_concurrent_jobs_on_one_key_make_one_job_and_one_link(
    clients: TriageClients, account: Account, mocker: MockerFixture
) -> None:
    _same_function(account, "payment-errors", "payment-duration")
    # Both invocations read no active item before either claims.
    mocker.patch.object(triage_module, "active_job", return_value=None)
    handler({"Records": [sqs_record(alarm_event(name="payment-errors"), "a-1")]}, None)
    result = handler({"Records": [sqs_record(alarm_event(name="payment-duration"), "b-1")]}, None)

    assert result == {"batchItemFailures": []}
    [work] = _jobs(clients)
    assert work.alarm.alarm_name == "payment-errors"
    [linked] = clients.table.findings()
    assert linked["alarm_name"] == "payment-duration"
    assert linked["linked_to"] == work.finding_id
    assert clients.table.items[f"active#{FUNCTION_KEY}"]["linked_alarms"] == ["payment-duration"]
    assert clients.table.items[_hour_pk()]["count"] == 1


# Deadline


class _Context:
    def __init__(self, *remaining_ms: int) -> None:
        self.remaining = list(remaining_ms)

    def get_remaining_time_in_millis(self) -> int:
        return self.remaining.pop(0) if len(self.remaining) > 1 else self.remaining[0]


def test_batch_past_the_deadline_reports_unsettled_records(clients: TriageClients) -> None:
    events = [alarm_event(name=f"late-{n}") for n in range(4)]
    result = handler(_batch(*events), _Context(60_000, 25_000, 19_999))
    assert result == {
        "batchItemFailures": [{"itemIdentifier": "msg-3"}, {"itemIdentifier": "msg-4"}]
    }
    assert sorted(work.alarm.alarm_name for work in _jobs(clients)) == ["late-0", "late-1"]


def test_no_time_left_settles_nothing(clients: TriageClients) -> None:
    result = handler(_batch(alarm_event()), _Context(1_000))
    assert result == {"batchItemFailures": [{"itemIdentifier": "msg-1"}]}
    assert clients.cloudwatch.calls == []


# Redelivery


def test_redelivered_failed_record_does_not_duplicate(
    clients: TriageClients, account: Account
) -> None:
    account.broken.add("svc-01-errors")
    first = handler(_batch(*_storm(3)), None)
    assert first == {"batchItemFailures": [{"itemIdentifier": "msg-2"}]}
    account.broken.clear()
    redelivery = {"Records": [sqs_record(alarm_event(name="svc-01-errors"), "msg-2")]}
    assert handler(redelivery, None) == {"batchItemFailures": []}
    names = sorted(work.alarm.alarm_name for work in _jobs(clients))
    assert names == ["svc-00-errors", "svc-01-errors", "svc-02-errors"]
    assert len({work.finding_id for work in _jobs(clients)}) == 3


def test_redelivered_whole_batch_does_not_duplicate(
    clients: TriageClients, account: Account, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(monkeypatch, "staging")
    _same_function(account, "svc-00-errors", "svc-06-errors")
    account.tags["low-floor"] = {"Severity": "low"}
    batch = _batch(*_storm(7), alarm_event(name="low-floor"))
    handler(batch, None)
    findings = sorted(item["pk"] for item in clients.table.findings())
    assert len(findings) == 7

    assert handler(batch, None) == {"batchItemFailures": []}
    assert len(_work(clients)) == 1
    assert sorted(item["pk"] for item in clients.table.findings()) == findings
    assert clients.table.items[_hour_pk()]["count"] == 1


# Partial batch failures


def test_one_failing_alarm_fails_only_its_records(clients: TriageClients, account: Account) -> None:
    account.broken.add("svc-01-errors")
    events = [*_storm(3), alarm_event(name="svc-01-errors")]
    result = handler(_batch(*events), None)
    assert result == {
        "batchItemFailures": [{"itemIdentifier": "msg-2"}, {"itemIdentifier": "msg-4"}]
    }
    assert sorted(work.alarm.alarm_name for work in _jobs(clients)) == [
        "svc-00-errors",
        "svc-02-errors",
    ]


def test_failing_incident_fails_every_storm_record(clients: TriageClients) -> None:
    clients.sqs.send_error = RuntimeError("down")
    result = handler(_batch(*_storm(5)), None)
    assert sorted(f["itemIdentifier"] for f in result["batchItemFailures"]) == [
        f"msg-{n}" for n in range(1, 6)
    ]
    assert clients.table.findings() == []


def test_failing_store_fails_the_record(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(monkeypatch, "dev")
    clients.table.errors["put_item"] = client_error("ProvisionedThroughputExceededException")
    result = handler(_batch(alarm_event()), None)
    assert result == {"batchItemFailures": [{"itemIdentifier": "msg-1"}]}


def test_triage_clients_builds_only_what_triage_reads(mocker: MockerFixture) -> None:
    boto3 = mocker.patch.object(triage_module, "boto3")
    triage_module.triage_clients.cache_clear()
    clients = triage_module.triage_clients("us-east-1", "table")
    assert [call.args[0] for call in boto3.client.call_args_list] == [
        "cloudwatch",
        "lambda",
        "sqs",
        "kinesis",
        "sts",
    ]
    boto3.resource.return_value.Table.assert_called_once_with("table")
    assert clients.table is boto3.resource.return_value.Table.return_value
    triage_module.triage_clients.cache_clear()


def test_triage_imports_no_model_code() -> None:
    source = Path(triage_module.__file__).read_text().lower()
    assert "bedrock" not in source
    assert "devops_agent.agent" not in source


# Opt-out tag


@pytest.mark.parametrize("value", ["off", "OFF", " Off "])
def test_opted_out_alarm_is_skipped(clients: TriageClients, account: Account, value: str) -> None:
    account.tags[ALARM_NAME] = {"DevOpsAgent": value, "Severity": "critical"}
    assert handler(_batch(alarm_event()), None) == {"batchItemFailures": []}
    assert _work(clients) == []
    [item] = clients.table.findings()
    assert item["kind"] == "skipped"
    assert item["outcome"] == "triaged"
    assert item["resource_key"] == FUNCTION_KEY
    assert "opted out by tag" in item["summary"]
    assert not any(pk.startswith("budget#") for pk in clients.table.items)
    tag_calls = [op for op in clients.cloudwatch.operations() if op == "list_tags_for_resource"]
    assert len(tag_calls) == 1


@pytest.mark.parametrize("value", ["on", "", "offline"])
def test_other_devopsagent_values_are_investigated(
    clients: TriageClients, account: Account, value: str
) -> None:
    account.tags[ALARM_NAME] = {"DevOpsAgent": value}
    handler(_batch(alarm_event()), None)
    assert len(_work(clients)) == 1
    assert clients.table.findings() == []


def test_opted_out_alarm_does_not_join_a_storm(clients: TriageClients, account: Account) -> None:
    events = _storm(5)
    account.tags[events[0]["detail"]["alarmName"]] = {"DevOpsAgent": "off"}
    handler(_batch(*events), None)
    assert [job.kind for job in _jobs(clients)] == ["alarm"] * 4
    assert _kinds(clients) == ["skipped"]


# Cooldown after close


def _closed_finding(
    table: FakeTable, finding_id: str, closed_minutes_ago: int, **fields: Any
) -> None:
    now = triage_module.datetime.now(triage_module.UTC)
    _open_finding(
        table,
        finding_id,
        "high",
        **{
            "status": "closed",
            "resolution": "confirmed",
            "alarm_arn": alarm_event()["resources"][0],
            "created_at": (now - timedelta(days=2)).isoformat(),
            "resolved_at": (now - timedelta(minutes=closed_minutes_ago)).isoformat(),
            **fields,
        },
    )


def test_alarm_closed_within_its_cooldown_counts_as_a_repeat(clients: TriageClients) -> None:
    _closed_finding(clients.table, "f-closed", 90)
    assert handler(_batch(alarm_event()), None) == {"batchItemFailures": []}
    assert _work(clients) == []
    item = clients.table.items["finding#f-closed"]
    assert item["recurrence_count"] == 1
    assert item["last_seen_at"]
    assert item["status"] == "closed"
    assert len(clients.table.findings()) == 1


def test_alarm_closed_past_its_cooldown_is_investigated(clients: TriageClients) -> None:
    _closed_finding(clients.table, "f-closed", 121)
    handler(_batch(alarm_event()), None)
    assert len(_work(clients)) == 1
    assert clients.table.items["finding#f-closed"]["recurrence_count"] == 0


def test_resource_closed_within_its_cooldown_counts_as_a_repeat(clients: TriageClients) -> None:
    _closed_finding(
        clients.table,
        "f-sibling",
        45,
        alarm_name="payment-api-duration-prod",
        alarm_arn="arn:aws:cloudwatch:us-east-1:111122223333:alarm:payment-api-duration-prod",
    )
    handler(_batch(alarm_event()), None)
    assert _work(clients) == []
    assert clients.table.items["finding#f-sibling"]["recurrence_count"] == 1


def test_resource_closed_past_its_cooldown_is_investigated(clients: TriageClients) -> None:
    _closed_finding(
        clients.table,
        "f-sibling",
        90,
        alarm_name="payment-api-duration-prod",
        alarm_arn="arn:aws:cloudwatch:us-east-1:111122223333:alarm:payment-api-duration-prod",
    )
    handler(_batch(alarm_event()), None)
    assert len(_work(clients)) == 1
    assert clients.table.items["finding#f-sibling"]["recurrence_count"] == 0


def test_unclosed_finding_takes_the_repeat_over_a_closed_one(clients: TriageClients) -> None:
    _closed_finding(clients.table, "f-closed", 10)
    _open_finding(clients.table, "f-open", "high")
    handler(_batch(alarm_event()), None)
    assert _work(clients) == []
    assert clients.table.items["finding#f-open"]["recurrence_count"] == 1
    assert clients.table.items["finding#f-closed"]["recurrence_count"] == 0


def test_cooldowns_are_configurable(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALARM_COOLDOWN_MINUTES", "0")
    monkeypatch.setenv("RESOURCE_COOLDOWN_MINUTES", "0")
    triage_module.get_triage_settings.cache_clear()
    _closed_finding(clients.table, "f-closed", 10)
    handler(_batch(alarm_event()), None)
    assert len(_work(clients)) == 1


def test_cooldown_defaults() -> None:
    settings = triage_module.get_triage_settings()
    assert settings.alarm_cooldown_minutes == 120
    assert settings.resource_cooldown_minutes == 60
    assert settings.daily_token_budget == 3_000_000


# Daily token budget


def _tokens_pk() -> str:
    return "budget#tokens#day#" + triage_module.datetime.now(triage_module.UTC).strftime("%Y-%m-%d")


def test_spent_daily_token_budget_defers(clients: TriageClients) -> None:
    _budget(clients.table, _tokens_pk(), 3_000_000)
    assert handler(_batch(alarm_event()), None) == {"batchItemFailures": []}
    assert _work(clients) == []
    [item] = clients.table.findings()
    assert item["kind"] == "deferred"
    assert "daily token budget reached" in item["summary"]
    assert _hour_pk() not in clients.table.items
    assert not [pk for pk in clients.table.items if pk.startswith("active#")]


def test_daily_token_budget_below_the_cap_emits(clients: TriageClients) -> None:
    _budget(clients.table, _tokens_pk(), 2_999_999)
    handler(_batch(alarm_event()), None)
    assert len(_work(clients)) == 1
    assert clients.table.items[_tokens_pk()]["count"] == 2_999_999


def test_daily_token_budget_is_configurable(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DAILY_TOKEN_BUDGET", "1000000")
    triage_module.get_triage_settings.cache_clear()
    _budget(clients.table, _tokens_pk(), 1_000_000)
    handler(_batch(alarm_event()), None)
    assert _kinds(clients) == ["deferred"]


def test_token_counter_carries_no_index_attributes(clients: TriageClients) -> None:
    _budget(clients.table, _tokens_pk(), 3_000_000)
    handler(_batch(alarm_event()), None)
    assert not {"status", "resource_key"} & set(clients.table.items[_tokens_pk()])


# Budget-deferred retries

EPISODE = datetime(2026, 9, 29, 14, 5, tzinfo=UTC)


def _firing(
    account: Account, name: str = ALARM_NAME, *, state: str = "ALARM", at: datetime = EPISODE
) -> None:
    """The alarm's current state as DescribeAlarms reports it."""
    function = FUNCTION if name == ALARM_NAME else f"fn-{name}"
    account.alarms[name] = {
        **_metric_alarm(name, "AWS/Lambda", {"FunctionName": function}),
        "StateValue": state,
        "StateTransitionedTimestamp": at,
    }


def _retry_batch(clients: TriageClients, start: int = 1) -> dict[str, Any]:
    """The alarms sent back so far, delivered as one batch, with fresh message ids."""
    return {
        "Records": [
            sqs_record(retry["body"], message_id=f"retry-{n}")
            for n, retry in enumerate(_retries(clients)[start - 1 :], start=start)
        ]
    }


@pytest.mark.parametrize(
    ("pk", "count", "reason"),
    [
        (_hour_pk, 10, "the hourly investigation budget is spent"),
        (_day_pk, 50, "the daily investigation budget is spent"),
        (_tokens_pk, 3_000_000, "daily token budget reached"),
    ],
)
def test_budget_deferral_sends_the_alarm_back_delayed(
    clients: TriageClients, pk: Any, count: int, reason: str
) -> None:
    _budget(clients.table, pk(), count)
    assert handler(_batch(alarm_event()), None) == {"batchItemFailures": []}
    [deferred] = clients.table.findings()
    assert reason in deferred["summary"]
    [retry] = _retries(clients)
    assert retry["DelaySeconds"] == 900
    assert retry["body"] == {
        **alarm_event(),
        "devops_agent_retry": 1,
        "devops_agent_finding_id": deferred["finding_id"],
    }
    assert _work(clients) == []


def test_low_floor_skip_is_not_retried(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(monkeypatch, "dev")
    _budget(clients.table, _hour_pk(), 5)
    handler(_batch(alarm_event()), None)
    assert _kinds(clients) == ["skipped"]
    assert _retries(clients) == []


def test_event_with_retry_fields_still_parses() -> None:
    signal = parse_signal(
        {**alarm_event(), "devops_agent_retry": 3, "devops_agent_finding_id": "f-1"}
    )
    assert signal is not None
    assert signal.name == ALARM_NAME


@pytest.mark.parametrize(
    ("state", "at"),
    [("OK", EPISODE), ("ALARM", EPISODE + timedelta(minutes=40))],
    ids=["back-to-ok", "newer-episode"],
)
def test_retry_outside_its_episode_is_dropped(
    clients: TriageClients, account: Account, state: str, at: datetime
) -> None:
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(alarm_event()), None)
    _firing(account, state=state, at=at)
    clients.table.items[_hour_pk()]["count"] = 0
    puts = len(clients.table.puts)
    assert handler(_retry_batch(clients), None) == {"batchItemFailures": []}
    assert len(clients.table.puts) == puts
    assert _work(clients) == []
    assert len(_retries(clients)) == 1


def test_retry_of_an_alarm_that_no_longer_exists_is_dropped(
    clients: TriageClients, account: Account
) -> None:
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(alarm_event()), None)
    account.alarms[ALARM_NAME] = {}
    handler(_retry_batch(clients), None)
    assert _kinds(clients) == ["deferred"]
    assert len(_retries(clients)) == 1


def test_retry_still_deferred_is_sent_again_with_the_next_count(
    clients: TriageClients, account: Account
) -> None:
    _firing(account)
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(alarm_event()), None)
    handler(_retry_batch(clients), None)
    first, second = _retries(clients)
    assert second["body"]["devops_agent_retry"] == 2
    assert second["body"]["devops_agent_finding_id"] == first["body"]["devops_agent_finding_id"]
    assert second["DelaySeconds"] == 900
    [deferred] = clients.table.findings()
    assert deferred["finding_id"] == first["body"]["devops_agent_finding_id"]


def test_retries_stop_at_the_cap(clients: TriageClients, account: Account) -> None:
    _firing(account)
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(alarm_event()), None)
    for attempt in range(2, 10):
        handler(_retry_batch(clients, start=attempt - 1), None)
    counts = [retry["body"]["devops_agent_retry"] for retry in _retries(clients)]
    assert counts == [1, 2, 3, 4, 5, 6, 7, 8]
    assert _kinds(clients) == ["deferred"]


def test_retry_cap_is_configurable(
    clients: TriageClients, account: Account, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MAX_DEFERRED_RETRIES", "1")
    triage_module.get_triage_settings.cache_clear()
    _firing(account)
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(alarm_event()), None)
    handler(_retry_batch(clients), None)
    assert [retry["body"]["devops_agent_retry"] for retry in _retries(clients)] == [1]


def test_retry_with_budget_left_is_investigated_under_its_own_id(
    clients: TriageClients, account: Account
) -> None:
    _firing(account)
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(alarm_event()), None)
    clients.table.items[_hour_pk()]["count"] = 0
    handler(_retry_batch(clients), None)
    [work] = _jobs(clients)
    [deferred] = clients.table.findings()
    assert deferred["kind"] == "deferred"
    assert work.finding_id != deferred["finding_id"]
    assert work.alarm.alarm_name == ALARM_NAME
    assert len(_retries(clients)) == 1


def test_retried_storm_keeps_one_deferred_finding(clients: TriageClients, account: Account) -> None:
    for event in _storm(5):
        _firing(account, event["detail"]["alarmName"])
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(*_storm(5)), None)
    assert len(_retries(clients)) == 5
    before = clients.table.findings()
    handler(_retry_batch(clients), None)
    assert clients.table.findings() == before
    assert [retry["body"]["devops_agent_retry"] for retry in _retries(clients)] == [1] * 5 + [2] * 5


def test_retry_send_failure_fails_the_record(clients: TriageClients) -> None:
    _budget(clients.table, _hour_pk(), 10)
    clients.sqs.send_error = RuntimeError("down")
    result = handler(_batch(alarm_event()), None)
    assert result == {"batchItemFailures": [{"itemIdentifier": "msg-1"}]}


# Datadog signals


def _datadog(mocker: MockerFixture, monitor: Any = None) -> FakeClient:
    client = FakeClient({"get_monitor": datadog_monitor() if monitor is None else monitor})
    mocker.patch.object(triage_module, "datadog_client", return_value=client)
    return client


def _metrics(capsys: pytest.CaptureFixture[str]) -> list[dict[str, str]]:
    """The decision metrics printed as EMF, as their dimension values."""
    found = []
    for line in capsys.readouterr().out.splitlines():
        if '"_aws"' not in line:
            continue
        blob = json.loads(line)
        [directive] = blob["_aws"]["CloudWatchMetrics"]
        assert directive["Namespace"] == "DevOpsAgent"
        assert directive["Metrics"] == [{"Name": "Decision", "Unit": "Count"}]
        assert blob["Decision"] == [1.0] or blob["Decision"] == 1.0
        found.append({name: blob[name] for name in ("env", "source", "decision")})
    return found


def test_verified_datadog_signal_is_a_job(
    clients: TriageClients, mocker: MockerFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    datadog = _datadog(mocker)
    assert handler(_batch(datadog_event()), None) == {"batchItemFailures": []}
    [work] = _jobs(clients)
    assert work.signal.source == "datadog"
    assert work.alarm is None
    assert work.alarms == []
    assert work.keys == [ECS_SERVICE_KEY]
    assert work.floor == "high"
    assert work.signal.ref["query"].startswith("sum(last_5m)")
    assert datadog.operations() == ["get_monitor"]
    assert clients.cloudwatch.calls == []
    assert _metrics(capsys) == [{"env": "prod", "source": "datadog", "decision": "investigated"}]


def test_unverified_datadog_signal_is_dropped_without_a_finding(
    clients: TriageClients, mocker: MockerFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    _datadog(mocker, datadog_monitor(tags=["env:prod"]))
    assert handler(_batch(datadog_event()), None) == {"batchItemFailures": []}
    assert _work(clients) == []
    assert clients.table.findings() == []
    assert _metrics(capsys) == [
        {"env": "prod", "source": "datadog", "decision": "skipped_unverified"}
    ]


def test_datadog_signal_without_keys_is_dropped(
    clients: TriageClients, mocker: MockerFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    mocker.patch.object(triage_module, "datadog_client", return_value=None)
    handler(_batch(datadog_event()), None)
    assert _work(clients) == []
    assert [metric["decision"] for metric in _metrics(capsys)] == ["skipped_unverified"]


def test_datadog_read_failure_fails_the_record(
    clients: TriageClients, mocker: MockerFixture
) -> None:
    _datadog(mocker, DatadogError("Datadog monitor read failed: HTTP 500", 500))
    result = handler(_batch(datadog_event()), None)
    assert result == {"batchItemFailures": [{"itemIdentifier": "msg-1"}]}


def test_datadog_monitor_opted_out_by_tag_is_skipped(
    clients: TriageClients, mocker: MockerFixture
) -> None:
    tags = ["env:prod", "devops_agent:true", "DevOpsAgent:off"]
    _datadog(mocker, datadog_monitor(tags=tags))
    handler(_batch(datadog_event()), None)
    [item] = clients.table.findings()
    assert item["kind"] == "skipped"
    assert item["source"] == "datadog"
    assert item["alarm_arn"] == f"datadog:monitor/{DATADOG_MONITOR_ID}/service:checkout-api-prod"


def test_ecs_alarm_and_datadog_signal_on_one_service_are_one_job(
    clients: TriageClients, account: Account, mocker: MockerFixture
) -> None:
    _datadog(mocker)
    account.alarms[ALARM_NAME] = {
        **_metric_alarm(
            ALARM_NAME,
            "AWS/ECS",
            {"ClusterName": "acme-prod", "ServiceName": "checkout-api-prod"},
        )
    }
    handler(_batch(alarm_event(), datadog_event()), None)
    [work] = _jobs(clients)
    assert work.keys == [ECS_SERVICE_KEY]
    [linked] = clients.table.findings()
    assert linked["kind"] == "linked"
    assert linked["linked_to"] == work.finding_id


def test_datadog_share_of_the_hourly_budget_defers(
    clients: TriageClients, mocker: MockerFixture
) -> None:
    _datadog(mocker)
    _budget(clients.table, _datadog_hour_pk(), 6)
    handler(_batch(datadog_event()), None)
    assert _work(clients) == []
    [item] = clients.table.findings()
    assert item["kind"] == "deferred"
    assert "Datadog share of the hourly budget is spent" in item["summary"]
    assert clients.table.items[_hour_pk()]["count"] == 0
    assert clients.table.items[_datadog_hour_pk()]["count"] == 6
    [retry] = _retries(clients)
    assert retry["body"]["detail-type"] == "Datadog Alert Notification"


def test_datadog_share_leaves_cloudwatch_alarms_alone(clients: TriageClients) -> None:
    _budget(clients.table, _datadog_hour_pk(), 6)
    handler(_batch(alarm_event()), None)
    assert len(_work(clients)) == 1


def test_datadog_share_is_configurable(
    clients: TriageClients, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATADOG_HOURLY_SHARE", "7")
    triage_module.get_triage_settings.cache_clear()
    _datadog(mocker)
    _budget(clients.table, _datadog_hour_pk(), 6)
    handler(_batch(datadog_event()), None)
    assert len(_work(clients)) == 1


# Priority budget


def _datadog_hour_pk() -> str:
    return "budget#datadog#" + triage_module.datetime.now(triage_module.UTC).strftime("%Y-%m-%dT%H")


def _overflow_pk() -> str:
    return "budget#p1#day#" + triage_module.datetime.now(triage_module.UTC).strftime("%Y-%m-%d")


def test_priority_1_runs_past_the_hourly_budget_on_the_overflow(
    clients: TriageClients, account: Account
) -> None:
    account.tags[ALARM_NAME] = {"Severity": "critical"}
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(alarm_event()), None)
    assert len(_work(clients)) == 1
    assert clients.table.items[_hour_pk()]["count"] == 10
    assert clients.table.items[_overflow_pk()]["count"] == 1
    assert clients.table.items[_day_pk()]["count"] == 1


def test_priority_1_overflow_is_capped(clients: TriageClients, account: Account) -> None:
    account.tags[ALARM_NAME] = {"Severity": "critical"}
    _budget(clients.table, _hour_pk(), 10)
    _budget(clients.table, _overflow_pk(), 10)
    handler(_batch(alarm_event()), None)
    assert _work(clients) == []
    [item] = clients.table.findings()
    assert item["kind"] == "deferred"
    assert "priority 1 overflow" in item["summary"]
    assert clients.table.items[_overflow_pk()]["count"] == 10
    assert len(_retries(clients)) == 1


def test_priority_2_does_not_use_the_overflow(clients: TriageClients) -> None:
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(alarm_event()), None)
    assert _work(clients) == []
    assert _overflow_pk() not in clients.table.items


def test_priority_2_may_use_the_hourly_reserve(clients: TriageClients) -> None:
    _budget(clients.table, _hour_pk(), 9)
    handler(_batch(alarm_event()), None)
    assert len(_work(clients)) == 1


def test_reserve_fraction_is_configurable(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(monkeypatch, "staging")
    monkeypatch.setenv("RESERVE_FRACTION", "0")
    triage_module.get_triage_settings.cache_clear()
    _budget(clients.table, _hour_pk(), 9)
    handler(_batch(alarm_event()), None)
    assert len(_work(clients)) == 1


def test_hardening_defaults() -> None:
    settings = triage_module.get_triage_settings()
    assert settings.p1_daily_overflow == 10
    assert settings.reserve_fraction == 0.3
    assert settings.datadog_hourly_share == 6
    assert settings.storm_rate == 30


# Drop, don't churn


def test_over_budget_low_priority_is_recorded_once_per_key_an_hour(
    clients: TriageClients, account: Account, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(monkeypatch, "staging")
    _same_function(account, "payment-errors", "payment-duration")
    _budget(clients.table, _day_pk(), 50)
    handler({"Records": [sqs_record(alarm_event(name="payment-errors"), "a-1")]}, None)
    handler({"Records": [sqs_record(alarm_event(name="payment-duration"), "b-1")]}, None)
    [item] = clients.table.findings()
    assert item["kind"] == "skipped"
    assert "over budget, the daily investigation budget is spent" in item["summary"]
    assert _retries(clients) == []
    assert clients.table.items[_day_pk()]["count"] == 50
    assert clients.table.items[f"active#{FUNCTION_KEY}"]["ttl"] <= int(time.time())


def test_over_budget_low_priority_on_two_keys_is_two_findings(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(monkeypatch, "staging")
    _budget(clients.table, _tokens_pk(), 3_000_000)
    handler({"Records": [sqs_record(alarm_event(name="a-errors"), "a-1")]}, None)
    handler({"Records": [sqs_record(alarm_event(name="b-errors"), "b-1")]}, None)
    assert _kinds(clients) == ["skipped", "skipped"]
    assert _retries(clients) == []


# Storm mode across batches

FROZEN = datetime(2026, 10, 14, 13, 7, 30, tzinfo=UTC)


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
        return FROZEN


def _rate_pk(at: datetime) -> str:
    return f"rate#{at.strftime('%Y-%m-%dT%H')}:{at.minute - at.minute % 5:02d}"


def _hour_pk_at(at: datetime) -> str:
    return "budget#" + at.strftime("%Y-%m-%dT%H")


@pytest.fixture()
def frozen(monkeypatch: pytest.MonkeyPatch) -> datetime:
    """Staging (medium floor, priority 3) at a fixed time, with a storm rate of 2."""
    monkeypatch.setattr(triage_module, "datetime", _FrozenDatetime)
    monkeypatch.setenv("STORM_RATE", "2")
    _env(monkeypatch, "staging")
    return FROZEN


def _storm_finding(clients: TriageClients) -> dict[str, Any]:
    [storm] = [item for item in clients.table.findings() if item["kind"] == "storm"]
    return storm


def _busy_previous_bucket(clients: TriageClients, at: datetime) -> str:
    previous = _rate_pk(at - timedelta(minutes=5))
    _budget(clients.table, previous, 3)
    return previous


def _open_storm(clients: TriageClients, at: datetime, head_id: str = "f-elsewhere") -> None:
    clients.table.items["storm#active"] = {
        "pk": "storm#active",
        "finding_id": "storm-1",
        "head_id": head_id,
        "ttl": int(at.timestamp()) + 600,
    }


def test_signal_rate_is_counted_per_bucket(clients: TriageClients, frozen: datetime) -> None:
    handler(_batch(*_storm(2)), None)
    assert clients.table.items[_rate_pk(frozen)]["count"] == 2
    assert "storm#active" not in clients.table.items


def test_deferred_retries_are_not_counted_in_the_rate(
    clients: TriageClients, frozen: datetime
) -> None:
    retried = {
        **alarm_event(name="again-errors"),
        "devops_agent_retry": 1,
        "devops_agent_finding_id": "f-0",
    }
    handler(_batch(alarm_event(name="first-errors"), retried), None)
    assert clients.table.items[_rate_pk(frozen)]["count"] == 1


def test_sustained_rate_opens_one_storm_with_one_investigation(
    clients: TriageClients,
    account: Account,
    frozen: datetime,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _busy_previous_bucket(clients, frozen)
    account.tags["svc-02-errors"] = {"Severity": "high"}
    assert handler(_batch(*_storm(3)), None) == {"batchItemFailures": []}

    [work] = _jobs(clients)
    assert work.alarm is not None
    assert work.alarm.alarm_name == "svc-02-errors"
    storm = _storm_finding(clients)
    assert storm["linked_to"] == work.finding_id
    assert f"is investigated as {work.finding_id}" in storm["summary"]
    assert storm["alarm_count"] == 3
    assert storm["source_counts"] == {"cloudwatch": 3}
    assert len(storm["resource_counts"]) == 3
    grouped = [item for item in clients.table.findings() if item["kind"] == "grouped"]
    assert len(grouped) == 2
    assert {item["incident_id"] for item in grouped} == {storm["finding_id"]}
    decisions = sorted(metric["decision"] for metric in _metrics(capsys))
    assert decisions == ["investigated", "storm_grouped", "storm_grouped"]

    handler({"Records": [sqs_record(alarm_event(name="later-errors"), "later-1")]}, None)
    assert len(_jobs(clients)) == 1
    assert _storm_finding(clients)["alarm_count"] == 4
    assert clients.table.items[_hour_pk_at(frozen)]["count"] == 1


@pytest.mark.parametrize("over_budget", [False, True])
def test_priority_1_during_a_storm_goes_through_the_budgets(
    clients: TriageClients, account: Account, frozen: datetime, over_budget: bool
) -> None:
    _open_storm(clients, frozen)
    _busy_previous_bucket(clients, frozen)
    account.tags["db-errors"] = {"Severity": "critical"}
    if over_budget:
        _budget(clients.table, _hour_pk_at(frozen), 10)
        _budget(clients.table, _overflow_pk_at(frozen), 10)
    handler(_batch(alarm_event(name="db-errors"), alarm_event(name="noise-errors")), None)
    kinds = sorted(item["kind"] for item in clients.table.findings())
    if over_budget:
        assert _work(clients) == []
        assert kinds == ["deferred", "grouped"]
        assert len(_retries(clients)) == 1
    else:
        [work] = _jobs(clients)
        assert work.signal.name == "db-errors"
        assert kinds == ["grouped"]
    [grouped] = [item for item in clients.table.findings() if item["kind"] == "grouped"]
    assert grouped["alarm_name"] == "noise-errors"


def test_datadog_priority_2_storm_does_not_group_a_critical_alarm(
    clients: TriageClients, account: Account, frozen: datetime, mocker: MockerFixture
) -> None:
    _datadog(mocker, datadog_monitor(tags=[*datadog_monitor()["tags"][1:], "env:staging"]))
    _busy_previous_bucket(clients, frozen)
    _budget(clients.table, _rate_pk(frozen), 3)
    handler({"Records": [sqs_record(datadog_event(), "dd-1")]}, None)
    assert "storm#active" in clients.table.items
    account.tags["db-errors"] = {"Severity": "critical"}
    handler({"Records": [sqs_record(alarm_event(name="db-errors"), "cw-1")]}, None)
    names = [work.signal.name for work in _jobs(clients)]
    assert "db-errors" in names
    grouped = [item for item in clients.table.findings() if item["kind"] == "grouped"]
    assert "db-errors" not in {item["alarm_name"] for item in grouped}


def _overflow_pk_at(at: datetime) -> str:
    return "budget#p1#day#" + at.strftime("%Y-%m-%d")


def test_deferred_storm_head_is_recorded_as_deferred_and_stays_the_head(
    clients: TriageClients, account: Account, frozen: datetime
) -> None:
    _busy_previous_bucket(clients, frozen)
    for event in _storm(3):
        name = event["detail"]["alarmName"]
        _firing(account, name)
        account.alarms[name]["StateTransitionedTimestamp"] = EPISODE.isoformat()
    account.tags["svc-01-errors"] = {"Severity": "high"}
    _budget(clients.table, _hour_pk_at(frozen), 10)
    handler(_batch(*_storm(3)), None)
    assert _work(clients) == []
    storm = _storm_finding(clients)
    [deferred] = [item for item in clients.table.findings() if item["kind"] == "deferred"]
    assert storm["linked_to"] == deferred["finding_id"]
    assert "was deferred (the hourly investigation budget is spent)" in storm["summary"]
    assert "investigated as" not in storm["summary"]

    clients.table.items[_hour_pk_at(frozen)]["count"] = 0
    [retry] = _retries(clients)
    handler({"Records": [sqs_record(retry["body"], "retry-1")]}, None)
    [work] = _jobs(clients)
    assert work.signal.name == "svc-01-errors"
    storm = _storm_finding(clients)
    assert storm["linked_to"] == work.finding_id
    assert f"is investigated as {work.finding_id}" in storm["summary"]
    grouped = {item["alarm_name"] for item in clients.table.findings() if item["kind"] == "grouped"}
    assert "svc-01-errors" not in grouped


def test_storm_groups_datadog_signals_by_source(
    clients: TriageClients, frozen: datetime, mocker: MockerFixture
) -> None:
    tags = ["env:staging", "devops_agent:true", "source:ecs"]
    _datadog(mocker, datadog_monitor(tags=tags, priority=3))
    _busy_previous_bucket(clients, frozen)
    handler(_batch(*_storm(3)), None)
    handler({"Records": [sqs_record(datadog_event(), "dd-1")]}, None)
    storm = _storm_finding(clients)
    assert storm["source_counts"] == {"cloudwatch": 3, "datadog": 1}
    assert storm["resource_counts"][ECS_SERVICE_KEY] == 1


def test_storm_ends_once_a_full_bucket_falls_to_the_rate(
    clients: TriageClients, frozen: datetime
) -> None:
    previous = _busy_previous_bucket(clients, frozen)
    handler(_batch(*_storm(3)), None)
    assert len(_jobs(clients)) == 1
    clients.table.items[previous]["count"] = 2
    handler({"Records": [sqs_record(alarm_event(name="calm-errors"), "calm-1")]}, None)
    assert clients.table.items["storm#active"]["ttl"] < int(frozen.timestamp())
    assert len(_jobs(clients)) == 2


def test_one_busy_bucket_is_not_a_storm(clients: TriageClients, frozen: datetime) -> None:
    handler(_batch(*_storm(4)), None)
    assert [work.kind for work in _jobs(clients)] == ["alarm"] * 4
    assert "storm#active" not in clients.table.items


def test_storm_opened_elsewhere_groups_this_batch(clients: TriageClients, frozen: datetime) -> None:
    _open_storm(clients, frozen)
    _busy_previous_bucket(clients, frozen)
    handler(_batch(*_storm(2)), None)
    assert _work(clients) == []
    assert _kinds(clients) == ["grouped", "grouped"]


# Datadog outage and verified names


def test_datadog_outage_costs_one_call_and_spares_cloudwatch(
    clients: TriageClients, mocker: MockerFixture
) -> None:
    datadog = _datadog(mocker, DatadogError("Datadog monitor read failed: HTTP 500", 500))
    events = [datadog_event(tags=["env:prod", f"service:svc-{n}"]) for n in range(25)]
    result = handler(_batch(*events, alarm_event()), None)
    assert datadog.operations() == ["get_monitor"]
    failed = {failure["itemIdentifier"] for failure in result["batchItemFailures"]}
    assert failed == {f"msg-{n}" for n in range(1, 26)}
    [work] = _jobs(clients)
    assert work.signal.source == "cloudwatch"


def test_failed_monitor_read_is_cached_across_invocations(
    clients: TriageClients, mocker: MockerFixture
) -> None:
    datadog = _datadog(mocker, DatadogError("Datadog monitor read failed: HTTP 503", 503))
    handler(_batch(datadog_event()), None)
    handler({"Records": [sqs_record(datadog_event(), "again-1")]}, None)
    assert datadog.operations() == ["get_monitor"]


def test_verified_monitor_name_replaces_the_payload_name(
    clients: TriageClients, mocker: MockerFixture
) -> None:
    _datadog(mocker, datadog_monitor(name="checkout-api errors"))
    event = datadog_event()
    event["detail"]["meta"]["monitor"]["name"] = "something else entirely"
    handler(_batch(event), None)
    [work] = _jobs(clients)
    assert work.signal.subject == "checkout-api errors"
    assert work.signal.name == "checkout-api errors (service:checkout-api-prod)"


def test_missing_datadog_keys_warn_once_per_cold_start(
    clients: TriageClients, mocker: MockerFixture
) -> None:
    mocker.patch.object(triage_module, "datadog_client", return_value=None)
    warning = mocker.spy(triage_module.logger, "warning")
    triage_module._warn_missing_datadog_keys.cache_clear()
    handler(_batch(datadog_event()), None)
    handler({"Records": [sqs_record(datadog_event(), "again-1")]}, None)
    messages = [call.args[0] for call in warning.call_args_list]
    assert (
        messages.count(
            "Datadog keys not configured: Datadog signals are dropped as skipped_unverified"
        )
        == 1
    )
    triage_module._warn_missing_datadog_keys.cache_clear()


# Decision metrics


def test_every_decision_emits_a_metric(
    clients: TriageClients, account: Account, capsys: pytest.CaptureFixture[str]
) -> None:
    _same_function(account, "payment-errors", "payment-duration")
    account.tags["opted"] = {"DevOpsAgent": "off"}
    _open_finding(clients.table, "f-open", "high", alarm_name="repeat-errors")
    account.alarms["repeat-errors"] = _metric_alarm(
        "repeat-errors", "AWS/Lambda", {"FunctionName": FUNCTION}
    )
    handler(
        _batch(
            alarm_event(name="payment-errors"),
            alarm_event(name="payment-duration"),
            alarm_event(name="opted"),
            alarm_event(name="repeat-errors"),
        ),
        None,
    )
    decisions = sorted(metric["decision"] for metric in _metrics(capsys))
    assert decisions == ["cooldown", "investigated", "linked", "opted_out"]


def test_deferral_emits_deferred_metrics(
    clients: TriageClients, capsys: pytest.CaptureFixture[str]
) -> None:
    _budget(clients.table, _hour_pk(), 10)
    handler(_batch(alarm_event()), None)
    assert _metrics(capsys) == [{"env": "prod", "source": "cloudwatch", "decision": "deferred"}]


def test_over_budget_skip_emits_skipped_budget(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _env(monkeypatch, "dev")
    _budget(clients.table, _hour_pk(), 5)
    handler(_batch(alarm_event()), None)
    assert _metrics(capsys) == [
        {"env": "dev", "source": "cloudwatch", "decision": "skipped_budget"}
    ]
