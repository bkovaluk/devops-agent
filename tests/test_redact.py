"""Credential-shape redaction."""

from __future__ import annotations

import pytest

from devops_agent.redact import REDACTED, redact, redact_value


@pytest.mark.parametrize(
    "secret",
    ["AKIA" + "ABCDEFGHIJKLMNOP", "ASIA" + "QRSTUVWXYZ234567"],
)
def test_access_key_ids(secret: str) -> None:
    assert redact(f"key={secret} used") == f"key={REDACTED} used"


def test_bearer_token() -> None:
    assert redact("Authorization: Bearer eyJhbGciOi.abc-def_ghi") == (
        f"Authorization: Bearer {REDACTED}"
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password=hunter2 next", f"password={REDACTED} next"),
        ("password: hunter2", f"password: {REDACTED}"),
        ("db_secret=abc123&x=1", f"db_secret={REDACTED}&x=1"),
        ("token=abc.def", f"token={REDACTED}"),
        ("API_KEY=k-123", f"API_KEY={REDACTED}"),
        ('{"password": "hunter2"}', f'{{"password": "{REDACTED}"}}'),
        ('{"password": "hunter two"}', f'{{"password": "{REDACTED}"}}'),
        ("password='hunter two' next", f"password='{REDACTED}' next"),
        ('{"password": "cut mid val', f'{{"password": "{REDACTED}'),
        ("pass=abc", f"pass={REDACTED}"),
        ("passwd: abc", f"passwd: {REDACTED}"),
        ("passphrase=abc", f"passphrase={REDACTED}"),
        ("pwd=abc", f"pwd={REDACTED}"),
        ("client_secret: abc", f"client_secret: {REDACTED}"),
        ("api-key=abc", f"api-key={REDACTED}"),
        ("apikey=abc", f"apikey={REDACTED}"),
        ("X-Api-Key: abc123", f"X-Api-Key: {REDACTED}"),
        ("auth=abc", f"auth={REDACTED}"),
        ("authorization=abc", f"authorization={REDACTED}"),
        ("credential=abc", f"credential={REDACTED}"),
        ('"credentials": "a b c"', f'"credentials": "{REDACTED}"'),
    ],
)
def test_key_value_secrets(text: str, expected: str) -> None:
    assert redact(text) == expected


def test_basic_credentials() -> None:
    assert redact("Authorization: Basic dXNlcjpwYXNzd29yZA==") == (
        f"Authorization: Basic {REDACTED}"
    )


@pytest.mark.parametrize("text", ["Basic Auth is off", "a basic check failed"])
def test_basic_in_prose_is_kept(text: str) -> None:
    assert redact(text) == text


@pytest.mark.parametrize(
    "token",
    [
        "xox" + "b-123456789012-abcdEFGHijkl",
        "xoxp-1-2-3-abc",
        "ghp_" + "a1B2" * 9,
        "ghs_" + "Z" * 40,
        "sk-" + "abc_DEF-123" * 2,
    ],
)
def test_prefixed_tokens(token: str) -> None:
    assert redact(f"using {token} now") == f"using {REDACTED} now"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("postgres://admin:hunter2@db:5432/app", f"postgres://admin:{REDACTED}@db:5432/app"),
        ("https://u:p%40ss@example.com/x", f"https://u:{REDACTED}@example.com/x"),
    ],
)
def test_url_userinfo_password(text: str, expected: str) -> None:
    assert redact(text) == expected


def test_datadog_api_key_hex() -> None:
    assert redact("DD key 0123456789abcdef0123456789abcdef set") == f"DD key {REDACTED} set"


@pytest.mark.parametrize(
    "text",
    [
        "commit 3f786850e387550fdab836ed7e6dc881de23001b deployed",
        "digest sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "request c4c1c1c9-6542-e61b-6ef0-8c4d36933a92 failed",
        "RequestId: 5f1b2e3a-9c4d-4e8f-a1b2-c3d4e5f60718",
        "arn:aws:lambda:us-east-1:111122223333:function:payment-api-prod",
        "https://console.aws.amazon.com/cloudwatch/home",
        "task-runner-1234567890123456789012345",
        "0123456789ABCDEF0123456789ABCDEF",
    ],
)
def test_identifiers_are_kept(text: str) -> None:
    assert redact(text) == text


def test_pem_private_key_block() -> None:
    pem = "-----BEGIN RSA PRIVATE" + " KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----"
    assert redact(f"before {pem} after") == f"before {REDACTED} after"


def test_truncated_pem_block_redacts_to_end() -> None:
    assert redact("x -----BEGIN PRIVATE" + " KEY-----\nMIIEvQIBADANBg") == f"x {REDACTED}"


def test_high_entropy_base64_run() -> None:
    blob = "q8Zt3VbN1xLr7YkP0aWc5HsJ2fGd9UeM4oTiRlQy6KnA"
    assert redact(f"value {blob} end") == f"value {REDACTED} end"


def test_low_entropy_and_hex_runs_are_kept() -> None:
    sha = "3f786850e387550fdab836ed7e6dc881de23001b"
    assert redact(sha) == sha
    repeated = "A1" * 30
    assert redact(repeated) == repeated


def test_plain_text_is_untouched() -> None:
    text = "Task timed out after 30.03 seconds in payment-api-prod"
    assert redact(text) == text


def test_redact_value_walks_nested_structures() -> None:
    value = {"a": ["password=x", 3, {"b": "AKIA" + "ABCDEFGHIJKLMNOP"}], "n": None}
    assert redact_value(value) == {
        "a": [f"password={REDACTED}", 3, {"b": REDACTED}],
        "n": None,
    }
