"""The GitHub read APIs the agent calls, authenticated as a GitHub App installation.

Every request goes to ``https://api.github.com``. The only POST is the installation token
exchange at ``/app/installations/{id}/access_tokens``; every other request is a GET on the
paths below, always under ``GH_ORG``: the client builds the owner, and callers pass only a
repo name. The App private key, the JWT and the installation token go in the request
headers and nowhere else: never into a log line, an error message or a tool result.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from devops_agent.config import Settings

API_ROOT = "https://api.github.com"
ACCESS_TOKENS_PATH = "/app/installations/{installation_id}/access_tokens"
ORG_REPOS_PATH = "/orgs/{org}/repos"
SEARCH_CODE_PATH = "/search/code"
CONTENTS_PATH = "/repos/{owner}/{repo}/contents/{path}"
COMMITS_PATH = "/repos/{owner}/{repo}/commits"
COMMIT_PATH = "/repos/{owner}/{repo}/commits/{sha}"
PULLS_PATH = "/repos/{owner}/{repo}/pulls"
PULL_PATH = "/repos/{owner}/{repo}/pulls/{number}"
PULL_FILES_PATH = "/repos/{owner}/{repo}/pulls/{number}/files"
WORKFLOW_RUNS_PATH = "/repos/{owner}/{repo}/actions/runs"
REQUEST_TIMEOUT_SECONDS = 10.0
API_VERSION = "2022-11-28"
USER_AGENT = "devops-agent"
JSON_MEDIA_TYPE = "application/vnd.github+json"
TEXT_MATCH_MEDIA_TYPE = "application/vnd.github.text-match+json"
JWT_BACKDATE_SECONDS = 60
JWT_LIFETIME_SECONDS = 540
# An installation token is replaced this long before GitHub expires it.
TOKEN_REFRESH_SECONDS = 300
REPO_PAGE_SIZE = 100
MAX_REPO_PAGES = 3

# Installation id -> (token, expiry as a Unix time). Kept across warm invocations.
_installation_tokens: dict[str, tuple[str, float]] = {}


class GitHubError(Exception):
    """A failed request, described by its HTTP status or error class only."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def app_jwt(app_id: str, private_key: str, now: float) -> str:
    """An RS256 JWT that authenticates as the App for the token exchange."""
    try:
        key = serialization.load_pem_private_key(private_key.encode(), password=None)
    except (ValueError, TypeError):
        raise GitHubError("GitHub App private key could not be loaded") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise GitHubError("GitHub App private key is not an RSA key")
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {
        "iat": int(now) - JWT_BACKDATE_SECONDS,
        "exp": int(now) + JWT_LIFETIME_SECONDS,
        "iss": int(app_id),
    }
    signing_input = ".".join(
        _b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims)
    )
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(signature)}"


def _status_hint(exc: urllib.error.HTTPError) -> str:
    headers = exc.headers
    rate_limited = exc.code == 429 or (
        exc.code == 403
        and headers is not None
        and (headers.get("x-ratelimit-remaining") == "0" or bool(headers.get("retry-after")))
    )
    if rate_limited:
        return " (rate limited, try again later)"
    return {
        401: " (credentials rejected)",
        403: " (not permitted)",
        404: " (not found)",
        422: " (request rejected)",
    }.get(exc.code, "")


@dataclass(frozen=True)
class GitHubClient:
    app_id: str
    installation_id: str
    org: str
    private_key: str = field(repr=False)
    _repos: list[Any] = field(default_factory=list, init=False, repr=False, compare=False)

    def list_org_repos(self) -> list[Any]:
        """The org's repos, up to three pages of 100, read once per client."""
        if not self._repos:
            path = ORG_REPOS_PATH.format(org=self.org)
            for page in range(1, MAX_REPO_PAGES + 1):
                params = {"per_page": str(REPO_PAGE_SIZE), "page": str(page)}
                rows = _array(self._get(path, params, "GitHub repo list"))
                self._repos.extend(rows)
                if len(rows) < REPO_PAGE_SIZE:
                    break
        return list(self._repos)

    def search_code(self, *, params: dict[str, str]) -> dict[str, Any]:
        payload = self._get(SEARCH_CODE_PATH, params, "GitHub code search", TEXT_MATCH_MEDIA_TYPE)
        return _object(payload)

    def get_contents(self, *, repo: str, path: str, ref: str | None) -> Any:
        url_path = CONTENTS_PATH.format(
            owner=self.org, repo=repo, path=urllib.parse.quote(path, safe="/")
        )
        params = {} if ref is None else {"ref": ref}
        return self._get(url_path, params, "GitHub file read")

    def list_commits(self, *, repo: str, params: dict[str, str]) -> list[Any]:
        path = COMMITS_PATH.format(owner=self.org, repo=repo)
        return _array(self._get(path, params, "GitHub commit list"))

    def get_commit(self, *, repo: str, sha: str) -> dict[str, Any]:
        path = COMMIT_PATH.format(owner=self.org, repo=repo, sha=sha)
        return _object(self._get(path, {}, "GitHub commit read"))

    def list_pulls(self, *, repo: str, params: dict[str, str]) -> list[Any]:
        path = PULLS_PATH.format(owner=self.org, repo=repo)
        return _array(self._get(path, params, "GitHub pull request list"))

    def get_pull(self, *, repo: str, number: int) -> dict[str, Any]:
        path = PULL_PATH.format(owner=self.org, repo=repo, number=number)
        return _object(self._get(path, {}, "GitHub pull request read"))

    def list_pull_files(self, *, repo: str, number: int, params: dict[str, str]) -> list[Any]:
        path = PULL_FILES_PATH.format(owner=self.org, repo=repo, number=number)
        return _array(self._get(path, params, "GitHub pull request files"))

    def list_workflow_runs(self, *, repo: str, params: dict[str, str]) -> dict[str, Any]:
        path = WORKFLOW_RUNS_PATH.format(owner=self.org, repo=repo)
        return _object(self._get(path, params, "GitHub Actions runs"))

    def installation_token(self) -> str:
        """The cached installation token, exchanged again near its expiry."""
        cached = _installation_tokens.get(self.installation_id)
        now = time.time()
        if cached is not None and now < cached[1] - TOKEN_REFRESH_SECONDS:
            return cached[0]
        jwt = app_jwt(self.app_id, self.private_key, now)
        path = ACCESS_TOKENS_PATH.format(installation_id=self.installation_id)
        payload = _object(
            self._send("POST", f"{API_ROOT}{path}", "GitHub token exchange", f"Bearer {jwt}")
        )
        token = payload.get("token")
        if not isinstance(token, str) or not token:
            raise GitHubError("GitHub token exchange failed: no token")
        try:
            expires = datetime.fromisoformat(str(payload.get("expires_at"))).timestamp()
        except ValueError:
            raise GitHubError("GitHub token exchange failed: no expiry") from None
        _installation_tokens[self.installation_id] = (token, expires)
        return token

    def _get(
        self, path: str, params: dict[str, str], label: str, accept: str = JSON_MEDIA_TYPE
    ) -> Any:
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        authorization = f"Bearer {self.installation_token()}"
        return self._send("GET", f"{API_ROOT}{path}{query}", label, authorization, accept)

    def _send(
        self,
        method: str,
        url: str,
        label: str,
        authorization: str,
        accept: str = JSON_MEDIA_TYPE,
    ) -> Any:
        request = urllib.request.Request(
            url,
            data=b"" if method == "POST" else None,
            method=method,
            headers={
                "Accept": accept,
                "Authorization": authorization,
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                _installation_tokens.pop(self.installation_id, None)
            raise GitHubError(f"{label} failed: HTTP {exc.code}{_status_hint(exc)}") from None
        except (OSError, ValueError) as exc:
            raise GitHubError(f"{label} failed: {type(exc).__name__}") from None
        return payload


def _object(payload: Any) -> dict[str, Any]:
    return payload if isinstance(payload, dict) else {}


def _array(payload: Any) -> list[Any]:
    return payload if isinstance(payload, list) else []


def github_client(settings: Settings) -> GitHubClient | None:
    """The client, or None when an App credential or the org is missing and the GitHub tools
    are not offered."""
    private_key = (
        settings.gh_app_private_key.get_secret_value() if settings.gh_app_private_key else ""
    )
    if (
        not settings.gh_app_id
        or not settings.gh_app_installation_id
        or not private_key
        or not settings.gh_org
    ):
        return None
    return GitHubClient(
        app_id=settings.gh_app_id,
        installation_id=settings.gh_app_installation_id,
        org=settings.gh_org,
        private_key=private_key,
    )
