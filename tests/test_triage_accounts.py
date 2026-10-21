"""Triage across accounts: accounts of signals, refusals, scoped keys, storms and budgets."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pytest_mock import MockerFixture

from devops_agent import decisions as decisions_module
from devops_agent import triage as triage_module
from devops_agent.accounts import AccountAccessError
from devops_agent.models import InvestigationJob, scoped_key
from devops_agent.triage import TriageClients, handler
from tests.conftest import (
    ALARM_NAME,
    ECS_SERVICE_KEY,
    FUNCTION_KEY,
    MEMBER_ACCOUNT,
    OTHER_ACCOUNT,
    OWN_ACCOUNT,
    WORK_QUEUE_URL,
    FakeClient,
    FakeSession,
    FakeSqs,
    FakeTable,
    alarm_event,
    client_error,
    datadog_event,
    datadog_monitor,
    lambda_context,
    member_alarm_event,
    sqs_record,
)

FUNCTION = "payment-api-prod"
MEMBER_KEY = scoped_key(FUNCTION_KEY, MEMBER_ACCOUNT)
OTHER_KEY = scoped_key(FUNCTION_KEY, OTHER_ACCOUNT)


def _cloudwatch(account: str, tags: dict[str, str]) -> FakeClient:
    """An account whose alarm named ALARM_NAME watches FUNCTION, any other its own function;
    every alarm carries ``tags``."""

    def describe_alarms(**kwargs: Any) -> dict[str, Any]:
        [name] = kwargs["AlarmNames"]
        alarm = {
            "AlarmName": name,
            "AlarmArn": f"arn:aws:cloudwatch:us-east-1:{account}:alarm:{name}",
            "Namespace": "AWS/Lambda",
            "MetricName": "Errors",
            "Dimensions": [
                {"Name": "FunctionName", "Value": FUNCTION if name == ALARM_NAME else f"fn-{name}"}
            ],
        }
        return {"MetricAlarms": [alarm], "CompositeAlarms": []}

    return FakeClient(
        {
            "describe_alarms": describe_alarms,
            "list_tags_for_resource": {
                "Tags": [{"Key": key, "Value": value} for key, value in tags.items()]
            },
        }
    )


@pytest.fixture()
def clients(mocker: MockerFixture) -> TriageClients:
    built = TriageClients(
        cloudwatch=_cloudwatch(OWN_ACCOUNT, {}),
        lambda_=FakeClient({"list_event_source_mappings": {"EventSourceMappings": []}}),
        sqs=FakeSqs(),
        kinesis=FakeClient(),
        sts=FakeClient({"get_caller_identity": {"Account": OWN_ACCOUNT}}),
        table=FakeTable(),
    )
    mocker.patch.object(triage_module, "triage_clients", return_value=built)
    return built


@dataclass
class Members:
    """The member sessions triage opens, by account, and the tags of their alarms."""

    tags: dict[str, dict[str, str]] = field(default_factory=dict)
    opened: dict[str, FakeSession] = field(default_factory=dict)
    arguments: dict[str, dict[str, Any]] = field(default_factory=dict)

    def open_session(self, account_id: str, **kwargs: Any) -> FakeSession:
        session = FakeSession(account_id)
        session.clients["cloudwatch"] = _cloudwatch(account_id, self.tags.get(account_id, {}))
        session.clients["lambda"] = FakeClient(
            {"list_event_source_mappings": {"EventSourceMappings": []}}
        )
        self.opened[account_id] = session
        self.arguments[account_id] = kwargs
        return session


@pytest.fixture()
def members(mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch) -> Members:
    """A deployment serving member accounts through their read-only role."""
    monkeypatch.setenv("MEMBER_ROLE_NAME", "devops-agent-read")
    triage_module.get_triage_settings.cache_clear()
    fake = Members()
    mocker.patch.object(triage_module, "open_session", side_effect=fake.open_session)
    return fake


def _set(monkeypatch: pytest.MonkeyPatch, **env: str) -> None:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    triage_module.get_triage_settings.cache_clear()


def _batch(*events: Any) -> dict[str, Any]:
    return {
        "Records": [
            sqs_record(event, message_id=f"msg-{n}") for n, event in enumerate(events, start=1)
        ]
    }


def _triage(*events: Any) -> dict[str, Any]:
    return handler(_batch(*events), lambda_context())


def _jobs(clients: TriageClients) -> list[InvestigationJob]:
    return [
        InvestigationJob.model_validate(message["body"])
        for message in clients.sqs.sent
        if message["QueueUrl"] == WORK_QUEUE_URL
    ]


def _findings(clients: TriageClients, kind: str) -> list[dict[str, Any]]:
    return [item for item in clients.table.findings() if item["kind"] == kind]


def _decisions(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    """The decision metrics printed as EMF: their dimension values."""
    found = []
    for line in capsys.readouterr().out.splitlines():
        if '"_aws"' not in line:
            continue
        blob = json.loads(line)
        [directive] = blob["_aws"]["CloudWatchMetrics"]
        [dimensions] = directive["Dimensions"]
        found.append({name: blob[name] for name in dimensions})
    return found


def _open_finding(table: FakeTable, finding_id: str, resource_key: str) -> None:
    table.items[f"finding#{finding_id}"] = {
        "pk": f"finding#{finding_id}",
        "finding_id": finding_id,
        "created_at": "2026-09-29T13:00:00+00:00",
        "env": "prod",
        "kind": "alarm",
        "outcome": "reported",
        "status": "open",
        "alarm_name": ALARM_NAME,
        "severity": "high",
        "severity_floor": "high",
        "resource_key": resource_key,
        "recurrence_count": 0,
        "linked_alarms": [],
    }


def _counter(table: FakeTable, pk: str, count: int) -> None:
    table.items[pk] = {"pk": pk, "count": count, "ttl": int(time.time()) + 3600}


def _now() -> datetime:
    return triage_module.datetime.now(triage_module.UTC)


def _hour_pk(account: str = "") -> str:
    scope = f"account#{account}#" if account else ""
    return f"budget#{scope}{_now().strftime('%Y-%m-%dT%H')}"


def _day_pk(account: str = "") -> str:
    scope = f"account#{account}#" if account else ""
    return f"budget#{scope}{_now().strftime('%Y-%m-%d')}"


def _overflow_pk(account: str = "") -> str:
    scope = f"account#{account}#" if account else ""
    return f"budget#{scope}p1#day#{_now().strftime('%Y-%m-%d')}"


# Accounts of signals


def test_member_alarm_is_read_through_its_role_and_keyed_by_account(
    clients: TriageClients, members: Members
) -> None:
    assert _triage(member_alarm_event()) == {"batchItemFailures": []}

    [work] = _jobs(clients)
    assert work.account_id == MEMBER_ACCOUNT
    assert work.region == "us-east-1"
    assert work.keys == [MEMBER_KEY]
    assert work.signal.account_id == MEMBER_ACCOUNT
    assert f"active#{MEMBER_KEY}" in clients.table.items
    assert clients.cloudwatch.calls == []
    assert members.opened[MEMBER_ACCOUNT].clients["cloudwatch"].operations() == [
        "describe_alarms",
        "list_tags_for_resource",
    ]
    arguments = members.arguments[MEMBER_ACCOUNT]
    assert arguments["own"] == OWN_ACCOUNT
    assert arguments["partition"] == "aws"
    assert arguments["name"] == "devops-agent-triage-req-1"
    assert arguments["seconds_left"] == pytest.approx(600.0)


def test_member_alarm_tags_set_its_floor(clients: TriageClients, members: Members) -> None:
    members.tags[MEMBER_ACCOUNT] = {"Severity": "critical"}
    _triage(member_alarm_event())
    [work] = _jobs(clients)
    assert work.floor == "critical"


def test_own_alarm_keeps_its_keys_and_credentials(clients: TriageClients, members: Members) -> None:
    _triage(alarm_event())
    [work] = _jobs(clients)
    assert work.account_id == OWN_ACCOUNT
    assert work.keys == [FUNCTION_KEY]
    assert members.opened == {}
    assert clients.cloudwatch.operations() == ["describe_alarms", "list_tags_for_resource"]


def test_one_member_session_serves_its_account_for_the_invocation(
    clients: TriageClients, members: Members
) -> None:
    _triage(member_alarm_event(name="a-errors"), member_alarm_event(name="b-errors"))
    assert triage_module.open_session.call_count == 1  # type: ignore[attr-defined]
    assert len(_jobs(clients)) == 2


@pytest.mark.usefixtures("members")
def test_same_alarm_and_resource_in_three_accounts_do_not_collide(clients: TriageClients) -> None:
    _triage(alarm_event(), member_alarm_event(), member_alarm_event(account=OTHER_ACCOUNT))
    jobs = _jobs(clients)
    assert sorted(work.resource_key for work in jobs) == sorted(
        [FUNCTION_KEY, MEMBER_KEY, OTHER_KEY]
    )
    assert clients.table.findings() == []


@pytest.mark.usefixtures("members")
def test_open_finding_in_one_account_is_no_repeat_in_another(clients: TriageClients) -> None:
    _open_finding(clients.table, "f-own", FUNCTION_KEY)
    _open_finding(clients.table, "f-member", MEMBER_KEY)
    _triage(member_alarm_event(), member_alarm_event(account=OTHER_ACCOUNT))
    [work] = _jobs(clients)
    assert work.resource_key == OTHER_KEY
    assert clients.table.items["finding#f-member"]["recurrence_count"] == 1
    assert clients.table.items["finding#f-own"]["recurrence_count"] == 0


@pytest.mark.usefixtures("members")
def test_running_job_in_one_account_links_no_signal_of_another(clients: TriageClients) -> None:
    clients.table.items[f"active#{FUNCTION_KEY}"] = {
        "pk": f"active#{FUNCTION_KEY}",
        "finding_id": "f-running",
        "linked_alarms": [],
        "ttl": int(time.time()) + 600,
    }
    _triage(member_alarm_event())
    [work] = _jobs(clients)
    assert work.resource_key == MEMBER_KEY
    assert clients.table.items[f"active#{FUNCTION_KEY}"]["linked_alarms"] == []


@pytest.mark.usefixtures("members")
def test_running_job_in_the_same_account_links_the_signal(clients: TriageClients) -> None:
    clients.table.items[f"active#{MEMBER_KEY}"] = {
        "pk": f"active#{MEMBER_KEY}",
        "finding_id": "f-running",
        "linked_alarms": [],
        "ttl": int(time.time()) + 600,
    }
    _triage(member_alarm_event())
    assert _jobs(clients) == []
    [linked] = _findings(clients, "linked")
    assert linked["linked_to"] == "f-running"
    assert linked["account_id"] == MEMBER_ACCOUNT
    assert linked["resource_key"] == MEMBER_KEY


@pytest.mark.usefixtures("members")
def test_an_incident_never_mixes_accounts(clients: TriageClients) -> None:
    own = [alarm_event(name=f"own-{n}-errors") for n in range(5)]
    member = [member_alarm_event(name=f"member-{n}-errors") for n in range(5)]
    _triage(*own, *member)
    jobs = _jobs(clients)
    assert [work.kind for work in jobs] == ["incident", "incident"]
    assert {work.account_id for work in jobs} == {OWN_ACCOUNT, MEMBER_ACCOUNT}
    for work in jobs:
        assert {signal.account_id for signal in work.signals} == {work.account_id}
    grouped = _findings(clients, "grouped")
    member_grouped = [item for item in grouped if item["account_id"] == MEMBER_ACCOUNT]
    assert len(member_grouped) == 4
    assert all(item["resource_key"].startswith(f"{MEMBER_ACCOUNT}|") for item in member_grouped)


def test_one_account_deployment_keys_and_counts_as_before(
    clients: TriageClients, capsys: pytest.CaptureFixture[str]
) -> None:
    _triage(alarm_event())
    [work] = _jobs(clients)
    assert work.keys == [FUNCTION_KEY]
    assert _decisions(capsys) == [
        {"env": "prod", "source": "cloudwatch", "decision": "investigated"}
    ]
    assert not [pk for pk in clients.table.items if pk.startswith("budget#account#")]


# Refused accounts


def _refused(clients: TriageClients, capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    assert _jobs(clients) == []
    assert clients.table.findings() == []
    return _decisions(capsys)


def test_member_alarm_without_a_member_role_is_refused(
    clients: TriageClients, capsys: pytest.CaptureFixture[str], mocker: MockerFixture
) -> None:
    opened = mocker.patch.object(triage_module, "open_session")
    info = mocker.spy(decisions_module.logger, "info")
    assert _triage(member_alarm_event()) == {"batchItemFailures": []}
    assert _refused(clients, capsys) == [
        {"env": "prod", "source": "cloudwatch", "decision": "skipped_account"}
    ]
    opened.assert_not_called()
    [call] = [
        call for call in info.call_args_list if call.args[0] == "dropped: account not investigated"
    ]
    assert call.kwargs["extra"]["account_id"] == MEMBER_ACCOUNT
    assert "MEMBER_ROLE_NAME is not set" in call.kwargs["extra"]["reason"]


@pytest.mark.usefixtures("members")
def test_account_outside_the_allow_list_is_refused(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _set(monkeypatch, ALLOWED_ACCOUNT_IDS=f"{OWN_ACCOUNT},{MEMBER_ACCOUNT}")
    _triage(member_alarm_event(account=OTHER_ACCOUNT))
    assert _refused(clients, capsys) == [
        {
            "env": "prod",
            "source": "cloudwatch",
            "decision": "skipped_account",
            "account": OTHER_ACCOUNT,
        }
    ]


@pytest.mark.usefixtures("members")
@pytest.mark.parametrize(
    "change",
    [
        {"account": ""},
        {"account": OTHER_ACCOUNT},
        {"region": "eu-west-1"},
        {
            "region": "eu-west-1",
            "resources": [f"arn:aws:cloudwatch:eu-west-1:{OWN_ACCOUNT}:alarm:{ALARM_NAME}"],
        },
    ],
)
def test_alarm_without_a_trusted_account_or_from_another_region_is_refused(
    clients: TriageClients, capsys: pytest.CaptureFixture[str], change: dict[str, Any]
) -> None:
    _triage({**alarm_event(), **change})
    [decision] = _refused(clients, capsys)
    assert decision["decision"] == "skipped_account"


def test_signal_naming_an_account_is_refused_when_sts_cannot_tell_the_own_account(
    clients: TriageClients, capsys: pytest.CaptureFixture[str], mocker: MockerFixture
) -> None:
    clients.sts.responses["get_caller_identity"] = client_error("AccessDenied")
    info = mocker.spy(decisions_module.logger, "info")
    assert handler(_batch(alarm_event()), None) == {"batchItemFailures": []}
    assert _refused(clients, capsys) == [
        {"env": "prod", "source": "cloudwatch", "decision": "skipped_account"}
    ]
    assert clients.cloudwatch.calls == []
    [call] = [
        call for call in info.call_args_list if call.args[0] == "dropped: account not investigated"
    ]
    assert call.kwargs["extra"]["reason"] == (
        f"the agent's own account is unknown, so account {OWN_ACCOUNT} is not read"
    )


def test_own_account_outside_lambda_comes_from_sts(clients: TriageClients) -> None:
    assert handler(_batch(alarm_event()), None) == {"batchItemFailures": []}
    [work] = _jobs(clients)
    assert work.account_id == OWN_ACCOUNT
    assert work.keys == [FUNCTION_KEY]
    assert clients.sts.operations() == ["get_caller_identity"]


@pytest.mark.usefixtures("members")
@pytest.mark.parametrize("code", ["Throttling", "EndpointConnectionError"])
def test_transient_assume_role_failure_fails_the_record_for_retry(
    clients: TriageClients, mocker: MockerFixture, code: str
) -> None:
    error = AccountAccessError(f"AssumeRole failed ({code})", code=code, transient=True)
    mocker.patch.object(triage_module, "open_session", side_effect=error)
    result = _triage(member_alarm_event(), alarm_event(name="own-errors"))
    assert result == {"batchItemFailures": [{"itemIdentifier": "msg-1"}]}
    [work] = _jobs(clients)
    assert work.account_id == OWN_ACCOUNT


def test_a_refused_member_role_is_assumed_once_per_invocation(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _set(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read")
    clients.sts.responses["assume_role"] = client_error("AccessDenied")
    names = ("a-errors", "b-errors", "c-errors")
    result = _triage(*(member_alarm_event(name=name) for name in names))
    assert result == {"batchItemFailures": []}
    assert clients.sts.operations().count("assume_role") == 1
    decisions = _refused(clients, capsys)
    assert [item["decision"] for item in decisions] == ["skipped_account"] * 3


def test_a_transient_assume_role_failure_is_tried_again_for_the_next_alarm(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read")
    clients.sts.responses["assume_role"] = client_error("Throttling")
    result = _triage(member_alarm_event(name="a-errors"), member_alarm_event(name="b-errors"))
    assert result == {
        "batchItemFailures": [{"itemIdentifier": "msg-1"}, {"itemIdentifier": "msg-2"}]
    }
    assert clients.sts.operations().count("assume_role") == 2


@pytest.mark.usefixtures("members")
@pytest.mark.parametrize("code", ["AccessDenied", "RegionDisabledException", "MalformedPolicy"])
def test_member_role_that_refuses_to_be_assumed_is_a_skipped_account(
    clients: TriageClients, mocker: MockerFixture, capsys: pytest.CaptureFixture[str], code: str
) -> None:
    arn = f"arn:aws:iam::{MEMBER_ACCOUNT}:role/devops-agent-read"
    error = AccountAccessError(f"AssumeRole of {arn} failed ({code})", code=code)
    mocker.patch.object(triage_module, "open_session", side_effect=error)
    info = mocker.spy(decisions_module.logger, "info")
    assert _triage(member_alarm_event()) == {"batchItemFailures": []}
    assert _refused(clients, capsys) == [
        {
            "env": "prod",
            "source": "cloudwatch",
            "decision": "skipped_account",
            "account": MEMBER_ACCOUNT,
        }
    ]
    [call] = [
        call for call in info.call_args_list if call.args[0] == "dropped: account not investigated"
    ]
    assert call.kwargs["extra"]["reason"] == f"AssumeRole of {arn} failed ({code})"


# Datadog accounts

MONITOR_TAGS = ["env:prod", "devops_agent:true", "source:ecs"]


def _datadog(mocker: MockerFixture, *tags: str) -> None:
    client = FakeClient({"get_monitor": datadog_monitor(tags=[*MONITOR_TAGS, *tags])})
    mocker.patch.object(triage_module, "datadog_client", return_value=client)


@pytest.mark.usefixtures("members")
def test_datadog_monitor_account_tag_scopes_its_signal(
    clients: TriageClients, mocker: MockerFixture
) -> None:
    _datadog(mocker, f"aws_account:{MEMBER_ACCOUNT}")
    _triage(datadog_event())
    [work] = _jobs(clients)
    assert work.account_id == MEMBER_ACCOUNT
    assert work.region == "us-east-1"
    assert work.keys == [scoped_key(ECS_SERVICE_KEY, MEMBER_ACCOUNT)]


@pytest.mark.usefixtures("members")
def test_datadog_account_tag_key_is_configurable(
    clients: TriageClients, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set(monkeypatch, DATADOG_ACCOUNT_TAG="account")
    _datadog(mocker, f"account:{MEMBER_ACCOUNT}")
    _triage(datadog_event())
    [work] = _jobs(clients)
    assert work.account_id == MEMBER_ACCOUNT


@pytest.mark.usefixtures("members")
def test_datadog_monitor_without_the_tag_is_the_agents_account(
    clients: TriageClients, mocker: MockerFixture
) -> None:
    _datadog(mocker)
    _triage(datadog_event())
    [work] = _jobs(clients)
    assert work.account_id == OWN_ACCOUNT
    assert work.keys == [ECS_SERVICE_KEY]


@pytest.mark.usefixtures("members")
def test_datadog_payload_cannot_choose_the_account(
    clients: TriageClients, mocker: MockerFixture
) -> None:
    _datadog(mocker)
    event = datadog_event()
    event["detail"]["tags"] = [*event["detail"]["tags"], f"aws_account:{MEMBER_ACCOUNT}"]
    _triage(event)
    [work] = _jobs(clients)
    assert work.account_id == OWN_ACCOUNT


@pytest.mark.usefixtures("members")
@pytest.mark.parametrize("tag", ["aws_account:prod", f"aws_account:{OTHER_ACCOUNT}"])
def test_datadog_monitor_of_an_unusable_account_is_refused(
    clients: TriageClients,
    mocker: MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tag: str,
) -> None:
    _set(monkeypatch, ALLOWED_ACCOUNT_IDS=f"{OWN_ACCOUNT},{MEMBER_ACCOUNT}")
    _datadog(mocker, tag)
    _triage(datadog_event())
    [decision] = _refused(clients, capsys)
    assert decision["decision"] == "skipped_account"
    assert decision["source"] == "datadog"


# Budgets per account


@pytest.mark.usefixtures("members")
def test_jobs_count_against_their_accounts_share_and_the_global_budgets(
    clients: TriageClients,
) -> None:
    _triage(alarm_event(), member_alarm_event())
    items = clients.table.items
    assert items[_hour_pk(MEMBER_ACCOUNT)]["count"] == 1
    assert items[_day_pk(MEMBER_ACCOUNT)]["count"] == 1
    assert items[_hour_pk(OWN_ACCOUNT)]["count"] == 1
    assert items[_hour_pk()]["count"] == 2
    assert items[_day_pk()]["count"] == 2


@pytest.mark.usefixtures("members")
def test_a_noisy_account_cannot_spend_the_others_hourly_budget(
    clients: TriageClients, capsys: pytest.CaptureFixture[str]
) -> None:
    _counter(clients.table, _hour_pk(MEMBER_ACCOUNT), 5)
    _triage(member_alarm_event(), member_alarm_event(account=OTHER_ACCOUNT))
    [work] = _jobs(clients)
    assert work.account_id == OTHER_ACCOUNT
    [deferred] = _findings(clients, "deferred")
    assert deferred["account_id"] == MEMBER_ACCOUNT
    assert f"account {MEMBER_ACCOUNT}'s share of the hourly budget is spent" in deferred["summary"]
    items = clients.table.items
    assert items[_hour_pk(MEMBER_ACCOUNT)]["count"] == 5
    assert items[_hour_pk()]["count"] == 1
    decisions = sorted((item["decision"], item["account"]) for item in _decisions(capsys))
    assert decisions == [("deferred", MEMBER_ACCOUNT), ("investigated", OTHER_ACCOUNT)]


@pytest.mark.usefixtures("members")
def test_account_share_of_the_daily_budget_refuses_and_refunds(clients: TriageClients) -> None:
    _counter(clients.table, _day_pk(MEMBER_ACCOUNT), 25)
    _triage(member_alarm_event())
    assert _jobs(clients) == []
    [deferred] = _findings(clients, "deferred")
    assert f"account {MEMBER_ACCOUNT}'s share of the daily budget is spent" in deferred["summary"]
    items = clients.table.items
    assert items[_hour_pk()]["count"] == 0
    assert items[_day_pk()]["count"] == 0
    assert items[_hour_pk(MEMBER_ACCOUNT)]["count"] == 0
    assert items[_day_pk(MEMBER_ACCOUNT)]["count"] == 25


@pytest.mark.usefixtures("members")
def test_account_shares_are_configurable(
    clients: TriageClients, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set(monkeypatch, ACCOUNT_HOURLY_BUDGET="1")
    _triage(member_alarm_event(name="a-errors"), member_alarm_event(name="b-errors"))
    assert len(_jobs(clients)) == 1


def test_priority_1_past_its_accounts_share_takes_the_overflow(
    clients: TriageClients, members: Members
) -> None:
    members.tags[MEMBER_ACCOUNT] = {"Severity": "critical"}
    _counter(clients.table, _hour_pk(MEMBER_ACCOUNT), 5)
    _triage(member_alarm_event())
    [work] = _jobs(clients)
    assert work.floor == "critical"
    items = clients.table.items
    assert items[_overflow_pk()]["count"] == 1
    assert items[_overflow_pk(MEMBER_ACCOUNT)]["count"] == 1
    assert items[_hour_pk(MEMBER_ACCOUNT)]["count"] == 5


def test_one_account_cannot_take_the_whole_priority_1_overflow(
    clients: TriageClients, members: Members
) -> None:
    for account in (MEMBER_ACCOUNT, OTHER_ACCOUNT):
        members.tags[account] = {"Severity": "critical"}
        _counter(clients.table, _hour_pk(account), 5)
    _counter(clients.table, _overflow_pk(MEMBER_ACCOUNT), 5)
    _triage(member_alarm_event(), member_alarm_event(account=OTHER_ACCOUNT))
    [work] = _jobs(clients)
    assert work.account_id == OTHER_ACCOUNT
    [deferred] = _findings(clients, "deferred")
    assert deferred["account_id"] == MEMBER_ACCOUNT
    assert (
        f"account {MEMBER_ACCOUNT}'s share of the hourly budget is spent and so is account "
        f"{MEMBER_ACCOUNT}'s priority 1 overflow" in deferred["summary"]
    )
    items = clients.table.items
    assert items[_overflow_pk()]["count"] == 1
    assert items[_overflow_pk(MEMBER_ACCOUNT)]["count"] == 5
    assert items[_overflow_pk(OTHER_ACCOUNT)]["count"] == 1
    assert items[_hour_pk()]["count"] == 0
    assert items[_day_pk()]["count"] == 1


def test_account_priority_1_overflow_is_configurable(
    clients: TriageClients, members: Members, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set(monkeypatch, ACCOUNT_HOURLY_BUDGET="0", ACCOUNT_P1_DAILY_OVERFLOW="1")
    members.tags[MEMBER_ACCOUNT] = {"Severity": "critical"}
    _triage(member_alarm_event(name="a-errors"), member_alarm_event(name="b-errors"))
    assert len(_jobs(clients)) == 1
    assert clients.table.items[_overflow_pk(MEMBER_ACCOUNT)]["count"] == 1


def test_global_priority_1_overflow_still_caps_every_account(
    clients: TriageClients, members: Members
) -> None:
    members.tags[MEMBER_ACCOUNT] = {"Severity": "critical"}
    _counter(clients.table, _hour_pk(MEMBER_ACCOUNT), 5)
    _counter(clients.table, _overflow_pk(), 10)
    _triage(member_alarm_event())
    assert _jobs(clients) == []
    [deferred] = _findings(clients, "deferred")
    assert "and so is the priority 1 overflow" in deferred["summary"]
    assert clients.table.items[_overflow_pk()]["count"] == 10
    assert _overflow_pk(MEMBER_ACCOUNT) not in clients.table.items


# Storms per account

FROZEN = datetime(2026, 10, 14, 13, 7, 30, tzinfo=UTC)


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
        return FROZEN


def _rate_pk(at: datetime, account: str = "") -> str:
    prefix = f"rate#{account}#" if account else "rate#"
    return f"{prefix}{at.strftime('%Y-%m-%dT%H')}:{at.minute - at.minute % 5:02d}"


@pytest.fixture()
def storms(monkeypatch: pytest.MonkeyPatch) -> None:
    """Staging (medium floor, priority 3) at a fixed time, with a storm rate of 2."""
    monkeypatch.setattr(triage_module, "datetime", _FrozenDatetime)
    _set(
        monkeypatch,
        STORM_RATE="2",
        ENVIRONMENT="staging",
        SLACK_TOPIC_ARN=f"arn:aws:sns:us-east-1:{OWN_ACCOUNT}:ops-alerts-staging",
    )


@pytest.mark.usefixtures("members", "storms")
def test_storm_in_one_account_groups_only_that_accounts_signals(clients: TriageClients) -> None:
    _counter(clients.table, _rate_pk(FROZEN - timedelta(minutes=5), MEMBER_ACCOUNT), 3)
    member = [member_alarm_event(name=f"svc-{n}-errors") for n in range(3)]
    _triage(*member, alarm_event(name="own-errors"))

    items = clients.table.items
    assert items[_rate_pk(FROZEN, MEMBER_ACCOUNT)]["count"] == 3
    assert items[_rate_pk(FROZEN)]["count"] == 1
    assert "storm#active" not in items
    [storm] = _findings(clients, "storm")
    assert storm["finding_id"] == items[f"storm#active#{MEMBER_ACCOUNT}"]["finding_id"]
    assert storm["account_id"] == MEMBER_ACCOUNT
    assert all(key.startswith(f"{MEMBER_ACCOUNT}|") for key in storm["resource_counts"])
    assert sorted(work.account_id for work in _jobs(clients)) == [OWN_ACCOUNT, MEMBER_ACCOUNT]
    grouped = _findings(clients, "grouped")
    assert len(grouped) == 2
    assert {item["account_id"] for item in grouped} == {MEMBER_ACCOUNT}


@pytest.mark.usefixtures("members", "storms")
def test_member_storm_ends_on_its_own_rate(clients: TriageClients) -> None:
    clients.table.items[f"storm#active#{MEMBER_ACCOUNT}"] = {
        "pk": f"storm#active#{MEMBER_ACCOUNT}",
        "finding_id": "storm-1",
        "head_id": "f-elsewhere",
        "ttl": int(FROZEN.timestamp()) + 600,
    }
    _triage(member_alarm_event())
    assert clients.table.items[f"storm#active#{MEMBER_ACCOUNT}"]["ttl"] < FROZEN.timestamp()
    [work] = _jobs(clients)
    assert work.account_id == MEMBER_ACCOUNT


@pytest.mark.usefixtures("members", "storms")
def test_storm_another_invocation_opened_in_the_account_is_joined(
    clients: TriageClients, mocker: MockerFixture
) -> None:
    _counter(clients.table, _rate_pk(FROZEN - timedelta(minutes=5), MEMBER_ACCOUNT), 3)
    _counter(clients.table, _rate_pk(FROZEN, MEMBER_ACCOUNT), 3)
    storm_pk = f"storm#active#{MEMBER_ACCOUNT}"
    put_item = clients.table.put_item

    def racing_put(**kwargs: Any) -> dict[str, Any]:
        if kwargs["Item"]["pk"] == storm_pk:
            clients.table.items[storm_pk] = {
                **kwargs["Item"],
                "finding_id": "storm-first",
                "head_id": "f-first",
            }
        return put_item(**kwargs)

    mocker.patch.object(clients.table, "put_item", side_effect=racing_put)
    _triage(member_alarm_event(name="svc-errors"))
    [grouped] = _findings(clients, "grouped")
    assert grouped["incident_id"] == "storm-first"
