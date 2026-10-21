"""Accounts: a signal's account, refusals, scoped keys and per-account sessions."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import EndpointConnectionError, NoCredentialsError
from pydantic import ValidationError

from devops_agent import accounts
from devops_agent.accounts import (
    MAX_SESSION_SECONDS,
    MIN_SESSION_SECONDS,
    AccountAccessError,
    AccountSession,
    alarm_origin,
    function_account,
    function_partition,
    is_member,
    monitor_account,
    open_session,
    own_account,
    refusal,
    role_arn,
    session_name,
    session_seconds,
)
from devops_agent.config import Settings, get_settings
from devops_agent.models import (
    AlarmStateChangeEvent,
    Severity,
    SignalRef,
    local_key,
    scoped_key,
)
from tests.conftest import (
    MEMBER_ACCOUNT,
    OTHER_ACCOUNT,
    OWN_ACCESS_KEY,
    OWN_ACCOUNT,
    FakeClient,
    alarm_event,
    lambda_context,
    member_credentials,
    signing_key,
    stubbed_sts,
)

OWN, MEMBER, OTHER = OWN_ACCOUNT, MEMBER_ACCOUNT, OTHER_ACCOUNT
pytestmark = pytest.mark.usefixtures("own_credentials")


def configure(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()
    return get_settings()


def _alarm_ref(account: str = OWN, region: str = "us-east-1", arn_account: str = OWN) -> SignalRef:
    event = alarm_event()
    event["account"] = account
    event["region"] = region
    event["resources"] = [f"arn:aws:cloudwatch:us-east-1:{arn_account}:alarm:x"]
    return SignalRef.for_alarm(AlarmStateChangeEvent.model_validate(event), Severity.LOW)


# The agent's own account


def test_function_account_and_partition_come_from_the_function_arn() -> None:
    gov = lambda_context(f"arn:aws-us-gov:lambda:us-gov-west-1:{OWN}:function:f")
    assert function_account(gov) == OWN
    assert function_partition(gov) == "aws-us-gov"


@pytest.mark.parametrize("arn", [None, "", "not-an-arn", "arn:aws:lambda:us-east-1:12:function:f"])
def test_without_a_function_arn_the_account_is_unknown(arn: str | None) -> None:
    assert function_account(lambda_context(arn)) == ""
    assert function_partition(None) == "aws"


def test_own_account_needs_no_call_in_lambda(monkeypatch: pytest.MonkeyPatch) -> None:
    sts = FakeClient()
    settings = configure(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read")
    assert own_account(lambda_context(), settings, sts) == OWN
    assert sts.calls == []


def test_own_account_stays_unknown_outside_lambda_with_one_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sts = FakeClient()
    assert own_account(None, configure(monkeypatch), sts) == ""
    assert sts.calls == []


def test_own_account_is_read_from_sts_outside_lambda_with_members(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sts = FakeClient({"get_caller_identity": {"Account": OWN}})
    settings = configure(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read")
    assert own_account(None, settings, sts) == OWN


@pytest.mark.parametrize(
    ("account", "own", "member"),
    [
        (MEMBER, OWN, True),
        (OWN, OWN, False),
        ("", OWN, False),
        (MEMBER, "", False),
    ],
)
def test_a_member_is_a_known_account_other_than_the_agents(
    account: str, own: str, member: bool
) -> None:
    assert is_member(account, own) is member


# Signal accounts


def test_alarm_event_account_matching_its_arn_is_trusted() -> None:
    assert alarm_origin(_alarm_ref()) is None


def test_alarm_event_without_an_account_is_not_trusted() -> None:
    assert alarm_origin(_alarm_ref(account="")) == "the alarm event names no account"


def test_alarm_event_account_must_match_the_alarm_arn() -> None:
    reason = alarm_origin(_alarm_ref(account=MEMBER, arn_account=OTHER))
    assert reason == f"the event's account {MEMBER} is not its alarm's ({OTHER})"


def test_alarm_event_region_must_match_the_alarm_arn() -> None:
    reason = alarm_origin(_alarm_ref(region="eu-west-1"))
    assert reason == "the event's region eu-west-1 is not its alarm's (us-east-1)"


def test_monitor_without_the_account_tag_is_the_agents_own() -> None:
    assert monitor_account({"service": "x"}, "aws_account", OWN) == (OWN, None)


def test_monitor_account_tag_names_its_account() -> None:
    assert monitor_account({"aws_account": MEMBER}, "AWS_Account", OWN) == (
        MEMBER,
        None,
    )


def test_monitor_account_tag_that_is_not_an_account_is_refused() -> None:
    assert monitor_account({"aws_account": "prod"}, "aws_account", OWN) == (
        "",
        "the monitor's aws_account tag is not an account id",
    )


# Refusals


def test_own_account_signal_is_not_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    assert refusal(OWN, "us-east-1", OWN, configure(monkeypatch)) is None


def test_another_region_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    reason = refusal(OWN, "eu-west-1", OWN, configure(monkeypatch))
    assert reason == "the signal is from eu-west-1; the agent reads us-east-1 only"


def test_account_outside_the_allow_list_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = configure(
        monkeypatch,
        MEMBER_ROLE_NAME="devops-agent-read",
        ALLOWED_ACCOUNT_IDS=f"{OWN},{MEMBER}",
    )
    assert refusal(MEMBER, "us-east-1", OWN, settings) is None
    assert refusal(OTHER, "us-east-1", OWN, settings) == (
        f"account {OTHER} is not in ALLOWED_ACCOUNT_IDS"
    )
    assert refusal("", "", OWN, settings) == "account unknown is not in ALLOWED_ACCOUNT_IDS"


def test_member_account_without_a_member_role_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    reason = refusal(MEMBER, "us-east-1", OWN, configure(monkeypatch))
    assert reason == f"account {MEMBER} is not the agent's and MEMBER_ROLE_NAME is not set"


def test_any_account_reads_as_the_agents_own_when_its_own_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert refusal(MEMBER, "us-east-1", "", configure(monkeypatch)) is None


# Settings


def test_allowed_account_ids_are_a_comma_list(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = configure(monkeypatch, ALLOWED_ACCOUNT_IDS=f" {OWN}, {MEMBER} ,")
    assert settings.allowed_account_ids == frozenset({OWN, MEMBER})


def test_allowed_account_ids_reject_what_is_not_an_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ALLOWED_ACCOUNT_IDS", f"{OWN},prod")
    with pytest.raises(ValidationError, match="not 12-digit account ids: prod"):
        Settings()  # type: ignore[call-arg]


def test_allowed_account_ids_take_a_list() -> None:
    settings = Settings(findings_table="t", allowed_account_ids=[OWN])  # type: ignore[arg-type]
    assert settings.allowed_account_ids == frozenset({OWN})


def test_multi_account_settings_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = configure(monkeypatch)
    assert settings.member_role_name is None
    assert settings.member_external_id is None
    assert settings.allowed_account_ids == frozenset()
    assert settings.datadog_account_tag == "aws_account"
    assert settings.multi_account is False
    assert configure(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read").multi_account is True


def test_external_id_is_a_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = configure(monkeypatch, MEMBER_EXTERNAL_ID="org-external-1")
    assert "org-external-1" not in repr(settings)
    assert settings.member_external_id is not None
    assert settings.member_external_id.get_secret_value() == "org-external-1"


def test_invalid_external_id_is_not_echoed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEMBER_EXTERNAL_ID", "secret value")
    with pytest.raises(ValidationError) as raised:
        Settings()  # type: ignore[call-arg]
    assert "secret value" not in str(raised.value)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MEMBER_ROLE_NAME", "role with spaces"),
        ("MEMBER_EXTERNAL_ID", "x"),
        ("MEMBER_EXTERNAL_ID", "has spaces"),
        ("DATADOG_ACCOUNT_TAG", "Account"),
    ],
)
def test_multi_account_settings_are_validated(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        Settings()  # type: ignore[call-arg]


# Keys


def test_member_keys_are_scoped_and_own_keys_are_not() -> None:
    key = "AWS/Lambda:FunctionName=payment-api-prod"
    assert scoped_key(key, "") == key
    assert scoped_key(key, MEMBER) == f"{MEMBER}|{key}"
    assert local_key(f"{MEMBER}|{key}") == key
    assert local_key(key) == key
    assert local_key("alarm:a/b") == "alarm:a/b"


@pytest.mark.parametrize(
    "key",
    [
        f"{MEMBER}/Custom:Name=x",
        f"{MEMBER}/Custom/Errors:Queue=a|b",
        "alarm:123456789012|errors",
        "datadog:monitor=7/env:prod",
    ],
)
def test_an_own_key_that_starts_with_an_account_id_is_not_read_as_scoped(key: str) -> None:
    assert local_key(key) == key
    assert local_key(scoped_key(key, MEMBER)) == key


# Sessions


def test_session_name_keeps_allowed_characters_within_64() -> None:
    assert session_name("devops-agent", "f 1/2") == "devops-agent-f-1-2"
    assert session_name("devops-agent-triage", "") == "devops-agent-triage"
    assert len(session_name("devops-agent", "x" * 100)) == 64


@pytest.mark.parametrize(
    ("left", "seconds"),
    [
        (float("inf"), MAX_SESSION_SECONDS),
        (5.0, MIN_SESSION_SECONDS),
        (1800.2, 1801),
        (99_999.0, MAX_SESSION_SECONDS),
    ],
)
def test_session_covers_the_invocation_within_sts_limits(left: float, seconds: int) -> None:
    assert session_seconds(left) == seconds


def test_account_session_builds_each_client_once() -> None:
    session = MagicMock()
    account = AccountSession(MEMBER, "us-east-1", session)
    assert account.client("ec2") is account.client("ec2")
    assert account.aws_call_client("ec2") is account.aws_call_client("ec2")
    calls = session.client.call_args_list
    assert [(call.args[0], call.kwargs["config"]) for call in calls] == [
        ("ec2", None),
        ("ec2", accounts.AWS_CALL_CLIENT_CONFIG),
    ]
    assert all(call.kwargs["region_name"] == "us-east-1" for call in calls)


def test_aws_call_clients_have_short_timeouts_and_two_attempts() -> None:
    config = accounts.AWS_CALL_CLIENT_CONFIG
    assert config.connect_timeout == 5
    assert config.read_timeout == 20
    assert config.retries == {"max_attempts": 2, "mode": "standard"}


def _open(settings: Settings, sts: Any, account: str = MEMBER, **kwargs: Any) -> AccountSession:
    return open_session(
        account,
        own=kwargs.get("own", OWN),
        settings=settings,
        sts=sts,
        partition="aws",
        name="devops-agent-f-1",
        seconds_left=kwargs.get("seconds_left", 600.0),
    )


def test_own_account_session_uses_the_agents_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    sts = FakeClient()
    session = _open(configure(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read"), sts, OWN)
    assert sts.calls == []
    assert session.account_id == OWN
    assert signing_key(session.client("cloudwatch")) == OWN_ACCESS_KEY


def test_unknown_account_session_is_the_agents_own(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _open(configure(monkeypatch), FakeClient(), "", own="")
    assert session.account_id == ""
    assert signing_key(session.aws_call_client("ec2")) == OWN_ACCESS_KEY


def test_member_session_assumes_the_member_role_with_the_external_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = configure(
        monkeypatch, MEMBER_ROLE_NAME="devops-agent-read", MEMBER_EXTERNAL_ID="org-external-1"
    )
    sts, stubber = stubbed_sts()
    stubber.add_response(
        "assume_role",
        {"Credentials": member_credentials(MEMBER)},
        {
            "RoleArn": f"arn:aws:iam::{MEMBER}:role/devops-agent-read",
            "RoleSessionName": "devops-agent-f-1",
            "DurationSeconds": MIN_SESSION_SECONDS,
            "ExternalId": "org-external-1",
        },
    )
    session = _open(settings, sts)
    stubber.assert_no_pending_responses()
    assert session.account_id == MEMBER
    assert signing_key(session.client("logs")) == f"member-key-{MEMBER}"
    assert signing_key(session.aws_call_client("rds")) == f"member-key-{MEMBER}"


def test_member_session_without_an_external_id_sends_none(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = configure(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read")
    sts, stubber = stubbed_sts()
    stubber.add_response(
        "assume_role",
        {"Credentials": member_credentials(MEMBER)},
        {
            "RoleArn": f"arn:aws:iam::{MEMBER}:role/devops-agent-read",
            "RoleSessionName": "devops-agent-f-1",
            "DurationSeconds": 1200,
        },
    )
    _open(settings, sts, seconds_left=1200.0)
    stubber.assert_no_pending_responses()


def test_member_session_needs_a_member_role(monkeypatch: pytest.MonkeyPatch) -> None:
    sts = FakeClient()
    with pytest.raises(AccountAccessError, match="needs MEMBER_ROLE_NAME, which is not set"):
        _open(configure(monkeypatch), sts)
    assert sts.calls == []


def test_account_outside_the_allow_list_gets_no_session(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = configure(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read", ALLOWED_ACCOUNT_IDS=OWN)
    with pytest.raises(AccountAccessError, match=f"account {MEMBER} is not allowed"):
        _open(settings, FakeClient())


def test_refused_assume_role_names_the_role_and_the_code(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = configure(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read")
    sts, stubber = stubbed_sts()
    stubber.add_client_error("assume_role", "AccessDenied", "not authorized: private detail")
    with pytest.raises(AccountAccessError) as raised:
        _open(settings, sts)
    arn = role_arn("aws", MEMBER, "devops-agent-read")
    assert str(raised.value) == f"AssumeRole of {arn} failed (AccessDenied)"
    assert raised.value.code == "AccessDenied"
    assert not raised.value.transient


@pytest.mark.parametrize(
    ("code", "transient"),
    [
        ("Throttling", True),
        ("ServiceUnavailable", True),
        ("RegionDisabledException", False),
        ("MalformedPolicyDocument", False),
        ("PackedPolicyTooLarge", False),
    ],
)
def test_only_transient_assume_role_errors_are_marked_for_retry(
    monkeypatch: pytest.MonkeyPatch, code: str, transient: bool
) -> None:
    settings = configure(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read")
    sts, stubber = stubbed_sts()
    stubber.add_client_error("assume_role", code, "detail")
    with pytest.raises(AccountAccessError) as raised:
        _open(settings, sts)
    assert raised.value.code == code
    assert raised.value.transient is transient


def test_refusal_by_settings_is_not_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(AccountAccessError) as raised:
        _open(configure(monkeypatch), FakeClient())
    assert raised.value.code == ""
    assert not raised.value.transient


def test_unreachable_sts_is_an_account_access_error(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = configure(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read")
    sts = FakeClient({"assume_role": EndpointConnectionError(endpoint_url="https://sts")})
    with pytest.raises(AccountAccessError, match=r"failed \(EndpointConnectionError\)") as raised:
        _open(settings, sts)
    assert raised.value.code == "EndpointConnectionError"
    assert raised.value.transient


def test_botocore_error_other_than_a_connection_is_not_transient(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = configure(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read")
    sts = FakeClient({"assume_role": NoCredentialsError()})
    with pytest.raises(AccountAccessError) as raised:
        _open(settings, sts)
    assert raised.value.code == "NoCredentialsError"
    assert not raised.value.transient


def test_sessions_never_share_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = configure(monkeypatch, MEMBER_ROLE_NAME="devops-agent-read")
    sts, stubber = stubbed_sts()
    stubber.add_response("assume_role", {"Credentials": member_credentials(MEMBER)})
    stubber.add_response("assume_role", {"Credentials": member_credentials(OTHER)})
    first = _open(settings, sts, MEMBER)
    second = _open(settings, sts, OTHER)
    own = _open(settings, sts, OWN)
    assert signing_key(first.client("ec2")) == f"member-key-{MEMBER}"
    assert signing_key(second.client("ec2")) == f"member-key-{OTHER}"
    assert signing_key(own.client("ec2")) == OWN_ACCESS_KEY
    assert signing_key(first.client("ec2")) == f"member-key-{MEMBER}"
