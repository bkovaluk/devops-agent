"""Accounts: which AWS account a signal is about, and the credentials that read it.

One deployment can serve several accounts of an organization. Member accounts forward
their alarm events to the agent's account and lend it a read-only role
(``MEMBER_ROLE_NAME``). A CloudWatch signal's account is its event's ``account`` field,
cross-checked with the alarm ARN; a Datadog signal's is the value of its monitor's
``DATADOG_ACCOUNT_TAG`` tag, else the agent's own. Triage refuses a signal whose account
cannot be told, is not in ``ALLOWED_ACCOUNT_IDS`` when that is set, or is another account
while no member role is configured, and one from another region.

A member account's resource keys are scoped as ``<account id>/<key>`` (models.scoped_key),
so findings, claims, cooldowns, links and remembered sources of two accounts never meet;
the agent's own account keeps its keys as they are.

Every read of an account goes through an ``AccountSession``: a boto3 session of its own,
on the agent's credentials for its own account or on the member role's for a member
account, built for one job (or one triage invocation) and never shared, so credentials
cannot pass from one job or account to the next in a warm Lambda.
"""

from __future__ import annotations

import math
import re
from typing import Any

import boto3
import botocore.session
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from devops_agent.config import Settings
from devops_agent.models import SignalRef
from devops_agent.tools import botocore_session

ACCOUNT_ID = re.compile(r"^\d{12}$")
# AssumeRole's shortest session, and the longest a role assumed by another role's session
# may have (role chaining).
MIN_SESSION_SECONDS = 900
MAX_SESSION_SECONDS = 3600
MAX_SESSION_NAME_CHARS = 64
_SESSION_NAME_CHARS = re.compile(r"[^\w+=,.@-]")
AWS_CALL_CLIENT_CONFIG = Config(
    connect_timeout=5, read_timeout=20, retries={"max_attempts": 2, "mode": "standard"}
)


class AccountAccessError(Exception):
    """The job's account cannot be read. The message names the account, the role and an
    AWS error code only, so it is safe to store on a finding."""


def _arn_field(arn: str, index: int) -> str:
    parts = arn.split(":")
    return parts[index] if arn.startswith("arn:") and len(parts) > index else ""


def _function_arn(context: Any) -> str:
    arn = getattr(context, "invoked_function_arn", None)
    return arn if isinstance(arn, str) else ""


def function_account(context: Any) -> str:
    """The account the Lambda runs in, from its function ARN; empty outside Lambda."""
    account = _arn_field(_function_arn(context), 4)
    return account if ACCOUNT_ID.match(account) else ""


def function_partition(context: Any) -> str:
    return _arn_field(_function_arn(context), 1) or "aws"


def own_account(context: Any, settings: Settings, sts: Any) -> str:
    """The agent's account. With member accounts it must be known, so outside Lambda it
    is read from STS; otherwise it may stay empty (unknown)."""
    account = function_account(context)
    if account or not settings.multi_account:
        return account
    return str(sts.get_caller_identity()["Account"])


def is_member(account_id: str, own: str) -> bool:
    """True when the account is known and is not the agent's own."""
    return bool(account_id) and bool(own) and account_id != own


def alarm_origin(signal: SignalRef) -> str | None:
    """Why a CloudWatch signal's account and region cannot be trusted; None when they can.

    The event's ``account`` must be an account id, and its account and region must agree
    with the alarm ARN's.
    """
    if not ACCOUNT_ID.match(signal.account_id):
        return "the alarm event names no account"
    arn = str(signal.ref.get("alarm_arn") or "")
    arn_account, arn_region = _arn_field(arn, 4), _arn_field(arn, 3)
    if arn_account and arn_account != signal.account_id:
        return f"the event's account {signal.account_id} is not its alarm's ({arn_account})"
    if arn_region and arn_region != signal.region:
        return f"the event's region {signal.region or 'none'} is not its alarm's ({arn_region})"
    return None


def monitor_account(tags: dict[str, str], tag_key: str, own: str) -> tuple[str, str | None]:
    """A Datadog monitor's account, from its tags (keys lowercased): the account tag's
    value, else the agent's own; and why it cannot be used, when the tag is not an id."""
    value = tags.get(tag_key.lower())
    if value is None:
        return own, None
    if not ACCOUNT_ID.match(value):
        return "", f"the monitor's {tag_key} tag is not an account id"
    return value, None


def refusal(account_id: str, region: str, own: str, settings: Settings) -> str | None:
    """Why the agent will not investigate a signal from this account and region."""
    if region and region != settings.aws_region:
        return f"the signal is from {region}; the agent reads {settings.aws_region} only"
    allowed = settings.allowed_account_ids
    if allowed and account_id not in allowed:
        return f"account {account_id or 'unknown'} is not in ALLOWED_ACCOUNT_IDS"
    if is_member(account_id, own) and not settings.member_role_name:
        return f"account {account_id} is not the agent's and MEMBER_ROLE_NAME is not set"
    return None


def session_name(*parts: str) -> str:
    """An STS role session name: allowed characters only, at most 64."""
    name = _SESSION_NAME_CHARS.sub("-", "-".join(part for part in parts if part))
    return name[:MAX_SESSION_NAME_CHARS]


def session_seconds(seconds_left: float) -> int:
    """A session length covering the rest of the invocation, within what STS allows."""
    if not math.isfinite(seconds_left):
        return MAX_SESSION_SECONDS
    return min(MAX_SESSION_SECONDS, max(MIN_SESSION_SECONDS, math.ceil(seconds_left)))


def role_arn(partition: str, account_id: str, role_name: str) -> str:
    return f"arn:{partition}:iam::{account_id}:role/{role_name}"


def _botocore() -> botocore.session.Session:
    """A botocore session of its own that loads models through the guard's data loader,
    so aws_call's guard and its clients read the same service models."""
    session = botocore.session.get_session()
    session.register_component("data_loader", botocore_session().get_component("data_loader"))
    return session


class AccountSession:
    """One account's credentials for one job or one triage invocation, and the clients
    built from them, each once."""

    def __init__(self, account_id: str, region: str, session: boto3.session.Session) -> None:
        self.account_id = account_id
        self.region = region
        self._session = session
        self._clients: dict[tuple[str, bool], Any] = {}

    def client(self, service: str) -> Any:
        return self._build(service, aws_call=False)

    def aws_call_client(self, service: str) -> Any:
        """A client for aws_call: short timeouts and at most two attempts."""
        return self._build(service, aws_call=True)

    def _build(self, service: str, *, aws_call: bool) -> Any:
        key = (service, aws_call)
        if key not in self._clients:
            config = AWS_CALL_CLIENT_CONFIG if aws_call else None
            self._clients[key] = self._session.client(
                service, region_name=self.region, config=config
            )
        return self._clients[key]


def _assume(sts: Any, arn: str, name: str, seconds: int, external_id: str | None) -> dict[str, str]:
    params: dict[str, Any] = {"RoleArn": arn, "RoleSessionName": name, "DurationSeconds": seconds}
    if external_id:
        params["ExternalId"] = external_id
    try:
        credentials: dict[str, str] = sts.assume_role(**params)["Credentials"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code") or "ClientError"
        raise AccountAccessError(f"AssumeRole of {arn} failed ({code})") from None
    except BotoCoreError as exc:
        raise AccountAccessError(f"AssumeRole of {arn} failed ({type(exc).__name__})") from None
    return credentials


def open_session(
    account_id: str,
    *,
    own: str,
    settings: Settings,
    sts: Any,
    partition: str,
    name: str,
    seconds_left: float,
) -> AccountSession:
    """The session that reads ``account_id``: the agent's own credentials for its own
    account (or an unknown one), the member role's for a member account.

    Raises AccountAccessError when the account is not allowed, no member role is
    configured, or AssumeRole fails; it never falls back to the agent's own credentials.
    """
    allowed = settings.allowed_account_ids
    if allowed and account_id not in allowed:
        raise AccountAccessError(f"account {account_id or 'unknown'} is not allowed")
    region = settings.aws_region
    if not is_member(account_id, own):
        session = boto3.session.Session(botocore_session=_botocore(), region_name=region)
        return AccountSession(account_id or own, region, session)
    if not settings.member_role_name:
        raise AccountAccessError(f"account {account_id} needs MEMBER_ROLE_NAME, which is not set")
    arn = role_arn(partition, account_id, settings.member_role_name)
    credentials = _assume(
        sts, arn, name, session_seconds(seconds_left), settings.member_external_id
    )
    session = boto3.session.Session(
        botocore_session=_botocore(),
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )
    return AccountSession(account_id, region, session)
