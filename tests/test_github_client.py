"""GitHub client: App JWT, installation token exchange and cache, requests, HTTP failures."""

from __future__ import annotations

import base64
import io
import json
import logging
import urllib.error
import urllib.parse
from datetime import datetime
from email.message import Message
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from pydantic import SecretStr
from pytest_mock import MockerFixture

from devops_agent import github as github_module
from devops_agent.config import Settings
from devops_agent.github import (
    REQUEST_TIMEOUT_SECONDS,
    GitHubClient,
    GitHubError,
    app_jwt,
    github_client,
)
from tests.conftest import (
    GITHUB_APP_ID,
    GITHUB_INSTALLATION_ID,
    GITHUB_ORG,
    github_private_key,
    github_private_pem,
)

NOW = 1_790_000_000.0
TOKEN = "ghs_" + "A1b2C3d4E5f6" * 3
EXPIRES_AT = "2026-09-21T15:00:00Z"
EXPIRES_TS = datetime.fromisoformat(EXPIRES_AT).timestamp()


def _decode(segment: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def _client() -> GitHubClient:
    return GitHubClient(
        app_id=GITHUB_APP_ID,
        installation_id=GITHUB_INSTALLATION_ID,
        org=GITHUB_ORG,
        private_key=github_private_pem(),
    )


def _response(payload: Any) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return response


def _token_response(token: str = TOKEN, expires_at: str = EXPIRES_AT) -> MagicMock:
    return _response({"token": token, "expires_at": expires_at})


def _http_error(code: int, headers: dict[str, str] | None = None) -> urllib.error.HTTPError:
    message = Message()
    for name, value in (headers or {}).items():
        message[name] = value
    body = io.BytesIO(json.dumps({"message": f"token {TOKEN} bad"}).encode())
    return urllib.error.HTTPError("https://api.github.com/x", code, "Error", message, body)


def test_jwt_claims_and_signature_verify_with_the_public_key() -> None:
    jwt = app_jwt(GITHUB_APP_ID, github_private_pem(), NOW)
    header, claims, signature = jwt.split(".")
    assert _decode(header) == {"alg": "RS256", "typ": "JWT"}
    assert _decode(claims) == {
        "iat": int(NOW) - 60,
        "exp": int(NOW) + 540,
        "iss": int(GITHUB_APP_ID),
    }
    raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    public = github_private_key().public_key()
    public.verify(raw, f"{header}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidSignature):
        public.verify(raw, f"{header}.x{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
    assert "=" not in jwt


def test_an_unreadable_key_is_an_error_without_its_contents() -> None:
    with pytest.raises(GitHubError) as raised:
        app_jwt(GITHUB_APP_ID, "-----BEGIN PRIVATE KEY-----\nnotakey\n", NOW)
    assert str(raised.value) == "GitHub App private key could not be loaded"


def test_a_non_rsa_key_is_refused() -> None:
    pem = (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        .decode()
    )
    with pytest.raises(GitHubError, match="not an RSA key"):
        app_jwt(GITHUB_APP_ID, pem, NOW)


def test_token_exchange_then_get_with_the_installation_token(mocker: MockerFixture) -> None:
    mocker.patch.object(github_module.time, "time", return_value=NOW)
    urlopen = mocker.patch.object(
        github_module.urllib.request,
        "urlopen",
        side_effect=[_token_response(), _response([{"sha": "abc"}])],
    )
    commits = _client().list_commits(repo="chat-lambda", params={"per_page": "5"})
    assert commits == [{"sha": "abc"}]
    exchange, read = (call.args[0] for call in urlopen.call_args_list)
    assert exchange.get_method() == "POST"
    assert exchange.full_url == (
        f"https://api.github.com/app/installations/{GITHUB_INSTALLATION_ID}/access_tokens"
    )
    jwt = exchange.get_header("Authorization").removeprefix("Bearer ")
    assert _decode(jwt.split(".")[1])["iss"] == int(GITHUB_APP_ID)
    assert read.get_method() == "GET"
    assert read.data is None
    assert read.full_url == ("https://api.github.com/repos/acme/chat-lambda/commits?per_page=5")
    assert read.get_header("Authorization") == f"Bearer {TOKEN}"
    for request in (exchange, read):
        assert request.get_header("Accept") == "application/vnd.github+json"
        assert request.get_header("X-github-api-version") == "2022-11-28"
        assert request.get_header("User-agent") == "devops-agent"
    assert all(call.kwargs["timeout"] == REQUEST_TIMEOUT_SECONDS for call in urlopen.call_args_list)


def test_token_is_cached_until_five_minutes_before_expiry(mocker: MockerFixture) -> None:
    clock = mocker.patch.object(github_module.time, "time", return_value=NOW)
    second = "ghs_" + "Z9y8X7w6V5u4" * 3
    urlopen = mocker.patch.object(
        github_module.urllib.request,
        "urlopen",
        side_effect=[_token_response(), _token_response(second)],
    )
    client = _client()
    assert client.installation_token() == TOKEN
    clock.return_value = EXPIRES_TS - 301
    assert _client().installation_token() == TOKEN
    assert urlopen.call_count == 1
    clock.return_value = EXPIRES_TS - 300
    assert client.installation_token() == second
    assert urlopen.call_count == 2


def test_a_401_drops_the_cached_token(mocker: MockerFixture) -> None:
    mocker.patch.object(github_module.time, "time", return_value=NOW)
    urlopen = mocker.patch.object(
        github_module.urllib.request,
        "urlopen",
        side_effect=[_token_response(), _http_error(401), _token_response(), _response([])],
    )
    client = _client()
    with pytest.raises(GitHubError, match=r"HTTP 401 \(credentials rejected\)"):
        client.list_commits(repo="r", params={})
    assert client.list_commits(repo="r", params={}) == []
    assert urlopen.call_count == 4


@pytest.mark.parametrize(
    "payload",
    [{"expires_at": EXPIRES_AT}, {"token": TOKEN}, {"token": TOKEN, "expires_at": "soon"}],
)
def test_a_token_response_without_token_or_expiry_is_an_error(
    mocker: MockerFixture, payload: dict[str, str]
) -> None:
    mocker.patch.object(github_module.urllib.request, "urlopen", return_value=_response(payload))
    with pytest.raises(GitHubError, match="GitHub token exchange failed: no"):
        _client().installation_token()


def test_a_failed_exchange_is_an_error(mocker: MockerFixture) -> None:
    mocker.patch.object(github_module.urllib.request, "urlopen", side_effect=_http_error(401))
    with pytest.raises(GitHubError, match=r"^GitHub token exchange failed: HTTP 401"):
        _client().list_org_repos()


def test_repo_list_pages_up_to_three_and_is_read_once(mocker: MockerFixture) -> None:
    mocker.patch.object(github_module.time, "time", return_value=NOW)
    pages = [[{"name": f"r{page}-{i}"} for i in range(100)] for page in range(4)]
    urlopen = mocker.patch.object(
        github_module.urllib.request,
        "urlopen",
        side_effect=[_token_response(), *(_response(page) for page in pages)],
    )
    client = _client()
    assert len(client.list_org_repos()) == 300
    assert len(client.list_org_repos()) == 300
    urls = [call.args[0].full_url for call in urlopen.call_args_list[1:]]
    assert urls == [
        f"https://api.github.com/orgs/acme/repos?per_page=100&page={page}" for page in (1, 2, 3)
    ]


def test_repo_list_stops_at_a_short_page(mocker: MockerFixture) -> None:
    mocker.patch.object(github_module.time, "time", return_value=NOW)
    urlopen = mocker.patch.object(
        github_module.urllib.request,
        "urlopen",
        side_effect=[_token_response(), _response([{"name": "a"}])],
    )
    assert _client().list_org_repos() == [{"name": "a"}]
    assert urlopen.call_count == 2


def test_requests_build_org_scoped_paths(mocker: MockerFixture) -> None:
    mocker.patch.object(github_module.time, "time", return_value=NOW)
    urlopen = mocker.patch.object(
        github_module.urllib.request,
        "urlopen",
        side_effect=[_token_response(), *(_response({}) for _ in range(7))],
    )
    client = _client()
    client.search_code(params={"q": "proxy error org:acme"})
    client.get_contents(repo="r", path="src/app.py", ref="v1.2")
    client.get_contents(repo="r", path="README.md", ref=None)
    client.get_commit(repo="r", sha="abc1234")
    client.get_pull(repo="r", number=12)
    client.list_pull_files(repo="r", number=12, params={"per_page": "30"})
    client.list_workflow_runs(
        repo="r", params={"created": "2026-09-20T00:00:00Z..2026-09-21T00:00:00Z"}
    )
    requests = [call.args[0] for call in urlopen.call_args_list[1:]]
    assert [request.full_url for request in requests[:6]] == [
        "https://api.github.com/search/code?q=proxy+error+org%3Aacme",
        "https://api.github.com/repos/acme/r/contents/src/app.py?ref=v1.2",
        "https://api.github.com/repos/acme/r/contents/README.md",
        "https://api.github.com/repos/acme/r/commits/abc1234",
        "https://api.github.com/repos/acme/r/pulls/12",
        "https://api.github.com/repos/acme/r/pulls/12/files?per_page=30",
    ]
    runs = urllib.parse.urlsplit(requests[6].full_url)
    assert runs.path == "/repos/acme/r/actions/runs"
    assert urllib.parse.parse_qs(runs.query) == {
        "created": ["2026-09-20T00:00:00Z..2026-09-21T00:00:00Z"]
    }
    assert requests[0].get_header("Accept") == "application/vnd.github.text-match+json"
    assert {request.get_method() for request in requests} == {"GET"}


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (_http_error(401), "GitHub commit list failed: HTTP 401 (credentials rejected)"),
        (_http_error(403), "GitHub commit list failed: HTTP 403 (not permitted)"),
        (
            _http_error(403, {"x-ratelimit-remaining": "0"}),
            "GitHub commit list failed: HTTP 403 (rate limited, try again later)",
        ),
        (
            _http_error(403, {"retry-after": "60"}),
            "GitHub commit list failed: HTTP 403 (rate limited, try again later)",
        ),
        (_http_error(404), "GitHub commit list failed: HTTP 404 (not found)"),
        (_http_error(422), "GitHub commit list failed: HTTP 422 (request rejected)"),
        (
            _http_error(429),
            "GitHub commit list failed: HTTP 429 (rate limited, try again later)",
        ),
        (_http_error(500), "GitHub commit list failed: HTTP 500"),
        (TimeoutError("timed out"), "GitHub commit list failed: TimeoutError"),
        (urllib.error.URLError("dns"), "GitHub commit list failed: URLError"),
    ],
)
def test_http_failures_name_the_status_without_credentials(
    mocker: MockerFixture,
    caplog: pytest.LogCaptureFixture,
    failure: Exception,
    message: str,
) -> None:
    mocker.patch.object(github_module.time, "time", return_value=NOW)
    mocker.patch.object(
        github_module.urllib.request, "urlopen", side_effect=[_token_response(), failure]
    )
    with caplog.at_level(logging.DEBUG), pytest.raises(GitHubError) as raised:
        _client().list_commits(repo="r", params={})
    assert str(raised.value) == message
    assert raised.value.__cause__ is None
    assert TOKEN not in caplog.text


def test_repr_holds_no_key() -> None:
    text = repr(_client())
    assert "PRIVATE KEY" not in text
    assert GITHUB_ORG in text


def _settings(**fields: Any) -> Settings:
    return Settings(
        findings_table="t",
        slack_topic_arn="arn:aws:sns:us-east-1:111122223333:ops-alerts-prod",
        slack_channel="#c",
        **fields,
    )


@pytest.mark.parametrize(
    "missing", ["gh_app_id", "gh_app_installation_id", "gh_app_private_key", "gh_org"]
)
def test_no_client_without_every_credential(missing: str) -> None:
    fields: dict[str, Any] = {
        "gh_org": GITHUB_ORG,
        "gh_app_id": GITHUB_APP_ID,
        "gh_app_installation_id": GITHUB_INSTALLATION_ID,
        "gh_app_private_key": SecretStr(github_private_pem()),
    }
    assert github_client(_settings(**fields)) is not None
    fields[missing] = None
    assert github_client(_settings(**fields)) is None


def test_settings_mask_the_private_key_and_leave_the_org_unset() -> None:
    settings = _settings(
        gh_app_id=GITHUB_APP_ID,
        gh_app_installation_id=GITHUB_INSTALLATION_ID,
        gh_app_private_key=SecretStr(github_private_pem()),
    )
    assert settings.gh_org is None
    assert "PRIVATE KEY" not in repr(settings)
    assert "PRIVATE KEY" not in str(settings.model_dump())
