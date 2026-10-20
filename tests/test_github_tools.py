"""GitHub tools: validation, request building, windows, projections, failures, offering."""

from __future__ import annotations

import base64
import dataclasses
import io
import json
import logging
import urllib.error
from datetime import UTC, datetime, timedelta
from email.message import Message
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from devops_agent import github as github_module
from devops_agent.github import GitHubClient, GitHubError
from devops_agent.redact import REDACTED
from devops_agent.tools import (
    GITHUB_TOOLS,
    MAX_GITHUB_FILES,
    MAX_GITHUB_PATCH_CHARS,
    MAX_GITHUB_PATCHES_CHARS,
    ToolContext,
    offered_tools,
    run_tool,
)
from tests.conftest import GITHUB_APP_ID, GITHUB_INSTALLATION_ID, GITHUB_ORG, github_private_pem

REPO = "chat-lambda"
ALARM_TIME = datetime(2026, 9, 29, 14, 5, tzinfo=UTC)
SECRET = "password=hunter2hunter2"
TOKEN = "ghs_" + "Q1w2E3r4T5y6" * 3


def _ctx(tool_ctx: ToolContext) -> ToolContext:
    return dataclasses.replace(tool_ctx, alarm_time=ALARM_TIME)


def _file(text: str, size: int | None = None) -> dict[str, Any]:
    data = text.encode()
    return {
        "type": "file",
        "size": len(data) if size is None else size,
        "encoding": "base64",
        "content": base64.b64encode(data).decode(),
    }


def test_github_tools_are_offered_only_with_a_client(tool_ctx: ToolContext) -> None:
    assert {tool.name for tool in offered_tools(tool_ctx)} >= GITHUB_TOOLS
    without = dataclasses.replace(tool_ctx, github=None)
    assert not GITHUB_TOOLS & {tool.name for tool in offered_tools(without)}
    result = run_tool("github_list_repos", {}, without)
    assert result.content == {"error": "unknown tool 'github_list_repos'"}


@pytest.mark.parametrize(
    ("name", "tool_input"),
    [
        ("github_get_file", {"repo": "acme/chat-lambda", "path": "a.py"}),
        ("github_get_file", {"repo": "other-org/x", "path": "a.py"}),
        ("github_get_file", {"repo": "..", "path": "a.py"}),
        ("github_get_file", {"repo": "bad name", "path": "a.py"}),
        ("github_get_file", {"repo": "r" * 101, "path": "a.py"}),
        ("github_get_file", {"repo": REPO, "path": "../etc/passwd"}),
        ("github_get_file", {"repo": REPO, "path": "src/../../x"}),
        ("github_get_file", {"repo": REPO, "path": "/abs/path.py"}),
        ("github_get_file", {"repo": REPO, "path": "a b.py"}),
        ("github_get_file", {"repo": REPO, "path": "a.py?ref=x"}),
        ("github_get_file", {"repo": REPO, "path": "a.py", "ref": "main..dev"}),
        ("github_get_file", {"repo": REPO, "path": "a.py", "ref": "refs heads"}),
        ("github_get_file", {"repo": REPO, "path": "a.py", "line": 0}),
        ("github_get_file", {"repo": REPO, "path": "a.py", "context": 81}),
        ("github_recent_changes", {"repo": REPO, "hours": 169}),
        ("github_recent_changes", {"repo": REPO, "hours": 0}),
        ("github_recent_changes", {"repo": REPO, "limit": 31}),
        ("github_recent_changes", {"repo": REPO, "path": "components/../x"}),
        ("github_recent_changes", {"repo": REPO, "owner": "acme"}),
        ("github_get_change", {"repo": REPO, "sha": "abc12"}),
        ("github_get_change", {"repo": REPO, "sha": "not-a-sha"}),
        ("github_get_change", {"repo": REPO, "sha": "a" * 41}),
        ("github_get_change", {"repo": REPO, "number": 0}),
        ("github_get_change", {"repo": "x/y", "number": 1}),
        ("github_list_repos", {"name": "a/b"}),
        ("github_list_repos", {"limit": 51}),
        ("github_list_repos", {"sort": "stars"}),
        ("github_search_code", {"query": "x", "limit": 21}),
        ("github_search_code", {"query": "x", "repo": "org/x"}),
        ("github_search_code", {"query": "x", "path": "../x"}),
    ],
)
def test_bad_inputs_are_refused_before_any_request(
    tool_ctx: ToolContext, name: str, tool_input: dict[str, Any]
) -> None:
    result = run_tool(name, tool_input, tool_ctx)
    assert result.status == "error"
    assert result.content["error"].startswith("invalid input:")
    assert tool_ctx.github.calls == []


@pytest.mark.parametrize(
    "tool_input", [{"repo": REPO}, {"repo": REPO, "sha": "abcdef1", "number": 1}]
)
def test_get_change_needs_exactly_one_of_sha_or_number(
    tool_ctx: ToolContext, tool_input: dict[str, Any]
) -> None:
    result = run_tool("github_get_change", tool_input, tool_ctx)
    assert result.status == "error"
    assert "give exactly one of sha or number" in result.content["error"]
    assert tool_ctx.github.calls == []


def test_an_owner_in_the_repo_names_the_rule(tool_ctx: ToolContext) -> None:
    result = run_tool("github_get_file", {"repo": f"{GITHUB_ORG}/{REPO}", "path": "a"}, tool_ctx)
    assert "give the repo name only" in result.content["error"]


@pytest.mark.parametrize(
    "query",
    [
        "error org:other",
        "repo:acme/x error",
        "error path:src",
        "error language python",
        "extension py proxy",
        "filename handler",
        "proxy OR error",
        "proxy AND error",
        "NOT proxy",
        "proxy -error",
        '"unbalanced phrase',
        "back\\slash",
        "new\nline",
        "x" * 129,
    ],
)
def test_search_rejects_qualifiers_and_operators(tool_ctx: ToolContext, query: str) -> None:
    result = run_tool("github_search_code", {"query": query}, tool_ctx)
    assert result.status == "error"
    assert result.content["error"].startswith("invalid input:")
    assert tool_ctx.github.calls == []


@pytest.mark.parametrize("query", ["proxy error not found", "KeyError('id')", "or and"])
def test_search_allows_lowercase_words_and_punctuation(tool_ctx: ToolContext, query: str) -> None:
    assert run_tool("github_search_code", {"query": query}, tool_ctx).status == "success"


def _repos() -> list[Any]:
    return [
        {
            "name": "chat-lambda",
            "description": "Chat Lambda " + "x" * 200,
            "default_branch": "main",
            "archived": False,
            "pushed_at": "2026-09-20T10:00:00Z",
            "language": "Python",
            "owner": {"login": "acme"},
            "clone_url": "https://github.com/acme/chat-lambda.git",
        },
        {
            "name": "infra",
            "pushed_at": "2026-09-29T10:00:00Z",
            "default_branch": "develop",
        },
        {"name": "Acme-Chat-API", "pushed_at": "2026-09-25T10:00:00Z", "archived": True},
        {"pushed_at": "2026-09-29T10:00:00Z"},
        "not a repo",
    ]


def test_list_repos_filters_by_substring_and_sorts_by_push(tool_ctx: ToolContext) -> None:
    tool_ctx.github.responses["list_org_repos"] = _repos()
    result = run_tool("github_list_repos", {"name": "chat"}, tool_ctx)
    assert result.status == "success"
    assert result.content["org"] == GITHUB_ORG
    assert [repo["name"] for repo in result.content["repos"]] == [
        "Acme-Chat-API",
        "chat-lambda",
    ]
    lambda_row = result.content["repos"][1]
    assert set(lambda_row) == {
        "name",
        "description",
        "default_branch",
        "archived",
        "pushed_at",
        "language",
    }
    assert len(lambda_row["description"]) == 120
    assert result.content["truncated"] is False


def test_list_repos_sorts_by_name_and_caps_at_limit(tool_ctx: ToolContext) -> None:
    tool_ctx.github.responses["list_org_repos"] = _repos()
    result = run_tool("github_list_repos", {"sort": "name", "limit": 2}, tool_ctx)
    assert [repo["name"] for repo in result.content["repos"]] == [
        "Acme-Chat-API",
        "chat-lambda",
    ]
    assert result.content["count"] == 2
    assert result.content["truncated"] is True


def test_list_repos_flags_a_listing_at_the_page_limit(tool_ctx: ToolContext) -> None:
    tool_ctx.github.responses["list_org_repos"] = [{"name": f"r{i}"} for i in range(300)]
    result = run_tool("github_list_repos", {"name": "r1"}, tool_ctx)
    assert result.content["truncated"] is True


def test_search_builds_the_query_with_org_repo_and_path(tool_ctx: ToolContext) -> None:
    run_tool(
        "github_search_code",
        {"query": '"Bugsnag proxy error"', "repo": REPO, "path": "src/app/", "limit": 5},
        tool_ctx,
    )
    [(operation, kwargs)] = tool_ctx.github.calls
    assert operation == "search_code"
    assert kwargs == {
        "params": {
            "q": f'"Bugsnag proxy error" org:{GITHUB_ORG} repo:{GITHUB_ORG}/{REPO} path:src/app',
            "per_page": "5",
        }
    }


def test_search_without_scope_is_org_wide(tool_ctx: ToolContext) -> None:
    result = run_tool("github_search_code", {"query": "proxy error"}, tool_ctx)
    assert result.content["query"] == f"proxy error org:{GITHUB_ORG}"
    assert tool_ctx.github.calls[0][1]["params"]["per_page"] == "10"


def test_search_projects_repo_path_and_two_fragments(tool_ctx: ToolContext) -> None:
    tool_ctx.github.responses["search_code"] = {
        "total_count": 3,
        "incomplete_results": False,
        "items": [
            {
                "name": "proxy.py",
                "path": "src/proxy.py",
                "sha": "deadbeef",
                "html_url": "https://github.com/acme/x/blob/main/src/proxy.py",
                "repository": {"name": "acme-proxy", "owner": {"login": "acme"}},
                "text_matches": [
                    {"fragment": f"raise ProxyError() # {SECRET}"},
                    {"fragment": "y" * 400},
                    {"fragment": "third"},
                ],
            },
            {"path": "README.md", "repository": {"name": "docs"}},
        ],
    }
    result = run_tool("github_search_code", {"query": "proxy error"}, tool_ctx)
    first, second = result.content["results"]
    assert first["repo"] == "acme-proxy"
    assert first["path"] == "src/proxy.py"
    assert "html_url" not in first
    assert len(first["fragments"]) == 2
    assert first["fragments"][0] == f"raise ProxyError() # password={REDACTED}"
    assert len(first["fragments"][1]) == 300
    assert second == {"repo": "docs", "path": "README.md"}
    assert result.content["total"] == 3
    assert result.content["truncated"] is True


def _numbered(count: int) -> str:
    return "".join(f"line {number}\n" for number in range(1, count + 1))


def test_get_file_returns_a_line_window(tool_ctx: ToolContext) -> None:
    tool_ctx.github.responses["get_contents"] = _file(_numbered(200))
    result = run_tool(
        "github_get_file",
        {"repo": REPO, "path": "src/handler.py", "ref": "prod-20260929", "line": 100, "context": 2},
        tool_ctx,
    )
    assert result.status == "success"
    assert tool_ctx.github.calls == [
        ("get_contents", {"repo": REPO, "path": "src/handler.py", "ref": "prod-20260929"})
    ]
    assert result.content["lines"] == [f"{n}: line {n}" for n in range(98, 103)]
    assert result.content["from_line"] == 98
    assert result.content["to_line"] == 102
    assert result.content["total_lines"] == 200
    assert result.content["ref"] == "prod-20260929"


def test_get_file_window_is_clamped_to_the_file(tool_ctx: ToolContext) -> None:
    tool_ctx.github.responses["get_contents"] = _file(_numbered(10))
    result = run_tool("github_get_file", {"repo": REPO, "path": "a.py", "line": 2}, tool_ctx)
    assert (result.content["from_line"], result.content["to_line"]) == (1, 10)


def test_get_file_without_a_line_returns_the_first_80(tool_ctx: ToolContext) -> None:
    tool_ctx.github.responses["get_contents"] = _file(_numbered(500))
    result = run_tool("github_get_file", {"repo": REPO, "path": "a.py"}, tool_ctx)
    assert len(result.content["lines"]) == 80
    assert result.content["lines"][-1] == "80: line 80"
    assert "ref" not in result.content
    assert tool_ctx.github.calls[0][1]["ref"] is None


def test_get_file_redacts_and_cuts_lines(tool_ctx: ToolContext) -> None:
    tool_ctx.github.responses["get_contents"] = _file(f"DB = '{SECRET}'\n{'z' * 500}\n")
    result = run_tool("github_get_file", {"repo": REPO, "path": "a.py"}, tool_ctx)
    first, second = result.content["lines"]
    assert "hunter2" not in first
    assert REDACTED in first
    assert second == "2: " + "z" * 200


def test_get_file_line_past_the_end_is_an_error(tool_ctx: ToolContext) -> None:
    tool_ctx.github.responses["get_contents"] = _file(_numbered(5))
    result = run_tool("github_get_file", {"repo": REPO, "path": "a.py", "line": 6}, tool_ctx)
    assert result.content == {"error": "a.py has 5 lines; line 6 is past the end"}


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (_file("x", size=200 * 1024 + 1), "big.bin is 204801 bytes; files over 200 KB"),
        ([{"type": "file", "name": "a"}], "big.bin is a directory"),
        ({"type": "symlink"}, "big.bin is not a file"),
        ({"type": "file", "size": 10, "encoding": "none"}, "big.bin has no readable content"),
        (_file("\x00\x01binary"), "big.bin is a binary file"),
    ],
)
def test_get_file_refuses_what_it_cannot_show(
    tool_ctx: ToolContext, response: Any, message: str
) -> None:
    tool_ctx.github.responses["get_contents"] = response
    result = run_tool("github_get_file", {"repo": REPO, "path": "big.bin"}, tool_ctx)
    assert result.status == "error"
    assert result.content["error"].startswith(message)


def _commit(sha: str, message: str, login: str | None = "dev1") -> dict[str, Any]:
    return {
        "sha": sha,
        "commit": {
            "message": message,
            "author": {"name": "Dev", "email": "dev@example.com", "date": "2026-09-29T11:00:00Z"},
            "committer": {"date": "2026-09-29T12:00:00Z"},
        },
        "author": {"login": login} if login else None,
    }


def _pull(number: int, merged_at: str | None) -> dict[str, Any]:
    return {
        "number": number,
        "title": f"PR {number} " + "t" * 300,
        "merged_at": merged_at,
        "base": {"ref": "main"},
        "user": {"login": "dev2"},
        "body": "never returned here",
    }


def test_recent_changes_window_ends_at_the_alarm(tool_ctx: ToolContext) -> None:
    run_tool(
        "github_recent_changes",
        {"repo": REPO, "path": "stacks/orders/", "hours": 6, "limit": 5},
        _ctx(tool_ctx),
    )
    calls = dict(tool_ctx.github.calls)
    assert calls["list_commits"] == {
        "repo": REPO,
        "params": {
            "since": "2026-09-29T08:05:00Z",
            "until": "2026-09-29T14:05:00Z",
            "per_page": "6",
            "path": "stacks/orders",
        },
    }
    assert calls["list_pulls"] == {
        "repo": REPO,
        "params": {"state": "closed", "sort": "updated", "direction": "desc", "per_page": "30"},
    }
    assert calls["list_workflow_runs"] == {
        "repo": REPO,
        "params": {"created": "2026-09-29T08:05:00Z..2026-09-29T14:05:00Z", "per_page": "20"},
    }


def test_recent_changes_window_ends_now_without_an_alarm_time(tool_ctx: ToolContext) -> None:
    before = datetime.now(UTC).replace(microsecond=0)
    result = run_tool("github_recent_changes", {"repo": REPO}, tool_ctx)
    until = datetime.fromisoformat(result.content["window"]["end"])
    since = datetime.fromisoformat(result.content["window"]["start"])
    assert until >= before
    assert until - since == timedelta(hours=24)


def test_recent_changes_projects_each_section(tool_ctx: ToolContext) -> None:
    tool_ctx.github.responses.update(
        {
            "list_commits": [
                _commit("0123456789abcdef", f"Fix proxy {SECRET}\n\nlong body"),
                _commit("fedcba9876543210", "m" * 300, login=None),
            ],
            "list_pulls": [
                _pull(41, "2026-09-29T13:00:00Z"),
                _pull(40, None),
                _pull(39, "2026-09-20T13:00:00Z"),
                _pull(38, "2026-09-29T15:00:00Z"),
            ],
            "list_workflow_runs": {
                "total_count": 1,
                "workflow_runs": [
                    {
                        "name": "Deploy Lambda Pipeline",
                        "event": "push",
                        "head_branch": "prod-20260929-fix",
                        "status": "completed",
                        "conclusion": "success",
                        "created_at": "2026-09-29T13:10:00Z",
                        "run_number": 88,
                        "head_commit": {"message": "not returned"},
                        "actor": {"login": "dev3"},
                    }
                ],
            },
        }
    )
    result = run_tool("github_recent_changes", {"repo": REPO}, _ctx(tool_ctx))
    assert result.status == "success"
    first, second = result.content["commits"]
    assert first == {
        "sha7": "0123456",
        "date": "2026-09-29T12:00:00Z",
        "author": "dev1",
        "message": f"Fix proxy password={REDACTED}",
    }
    assert "author" not in second
    assert len(second["message"]) == 200
    [merged] = result.content["merged_pulls"]
    assert merged["number"] == 41
    assert merged["base"] == "main"
    assert merged["author"] == "dev2"
    assert len(merged["title"]) == 200
    assert "body" not in merged
    assert result.content["workflow_runs"] == [
        {
            "name": "Deploy Lambda Pipeline",
            "event": "push",
            "head_branch": "prod-20260929-fix",
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-09-29T13:10:00Z",
            "run_number": 88,
        }
    ]
    assert result.content["truncated"] == []
    assert "errors" not in result.content


def test_recent_changes_flags_sections_past_the_limit(tool_ctx: ToolContext) -> None:
    tool_ctx.github.responses["list_commits"] = [_commit(f"{i:040x}", "m") for i in range(3)]
    result = run_tool("github_recent_changes", {"repo": REPO, "limit": 2}, _ctx(tool_ctx))
    assert len(result.content["commits"]) == 2
    assert result.content["truncated"] == ["commits"]


def test_recent_changes_reports_a_failed_section_and_keeps_the_others(
    tool_ctx: ToolContext,
) -> None:
    tool_ctx.github.responses.update(
        {
            "list_pulls": GitHubError("GitHub pull request list failed: HTTP 403 (not permitted)"),
            "list_commits": [_commit("0123456789", "ok")],
        }
    )
    result = run_tool("github_recent_changes", {"repo": REPO}, _ctx(tool_ctx))
    assert result.status == "success"
    assert result.content["errors"] == {
        "merged_pulls": "GitHub pull request list failed: HTTP 403 (not permitted)"
    }
    assert len(result.content["commits"]) == 1
    assert "merged_pulls" not in result.content
    assert result.content["workflow_runs"] == []


def test_recent_changes_with_every_section_failing_is_an_error(tool_ctx: ToolContext) -> None:
    failure = GitHubError("GitHub token exchange failed: HTTP 401 (credentials rejected)")
    tool_ctx.github.responses.update(
        {"list_commits": failure, "list_pulls": failure, "list_workflow_runs": failure}
    )
    result = run_tool("github_recent_changes", {"repo": REPO}, tool_ctx)
    assert result.status == "error"
    assert "HTTP 401" in result.content["error"]


def _files(count: int, patch: str = "@@ -1 +1 @@\n-a\n+b") -> list[dict[str, Any]]:
    return [
        {
            "filename": f"src/f{i}.py",
            "status": "modified",
            "additions": 1,
            "deletions": 1,
            "changes": 2,
            "patch": patch,
            "blob_url": "https://github.com/x",
            "sha": "abc",
        }
        for i in range(count)
    ]


def test_get_commit_projects_message_and_capped_files(tool_ctx: ToolContext) -> None:
    commit = _commit("0123456789abcdef", "Bump timeout\n\n" + "b" * 2000)
    tool_ctx.github.responses["get_commit"] = {**commit, "files": _files(35)}
    result = run_tool("github_get_change", {"repo": REPO, "sha": "0123456"}, tool_ctx)
    assert tool_ctx.github.calls == [("get_commit", {"repo": REPO, "sha": "0123456"})]
    content = result.content
    assert content["sha7"] == "0123456"
    assert content["author"] == "dev1"
    assert len(content["message"]) == 1000
    assert content["message"].startswith("Bump timeout\n\n")
    assert len(content["files"]) == MAX_GITHUB_FILES
    assert content["files"][0] == {
        "filename": "src/f0.py",
        "status": "modified",
        "additions": 1,
        "deletions": 1,
        "patch": "@@ -1 +1 @@\n-a\n+b",
    }
    assert content["truncated"] is True


def test_patches_are_cut_redacted_and_kept_within_a_total(tool_ctx: ToolContext) -> None:
    patch = f"+{SECRET}\n" + "+" * 3000
    tool_ctx.github.responses["get_commit"] = {**_commit("abcdef1", "m"), "files": _files(5, patch)}
    result = run_tool("github_get_change", {"repo": REPO, "sha": "abcdef1"}, tool_ctx)
    files = result.content["files"]
    kept = [changed for changed in files if "patch" in changed]
    assert len(kept[0]["patch"]) == MAX_GITHUB_PATCH_CHARS
    assert "hunter2" not in kept[0]["patch"]
    assert sum(len(changed["patch"]) for changed in kept) <= MAX_GITHUB_PATCHES_CHARS
    assert len(kept) == MAX_GITHUB_PATCHES_CHARS // MAX_GITHUB_PATCH_CHARS
    assert all(changed["patch_omitted"] for changed in files if "patch" not in changed)
    assert result.content["truncated"] is False


def test_get_pull_request_reads_the_pull_and_its_files(tool_ctx: ToolContext) -> None:
    tool_ctx.github.responses.update(
        {
            "get_pull": {
                "number": 12,
                "title": "Raise proxy timeout",
                "body": f"Fixes the proxy. {SECRET} " + "b" * 2000,
                "state": "closed",
                "merged_at": "2026-09-29T13:00:00Z",
                "base": {"ref": "main", "sha": "x"},
                "head": {"ref": "fix/proxy-timeout"},
                "user": {"login": "dev2"},
                "changed_files": 40,
                "requested_reviewers": [{"login": "x"}],
            },
            "list_pull_files": _files(30),
        }
    )
    result = run_tool("github_get_change", {"repo": REPO, "number": 12}, tool_ctx)
    assert tool_ctx.github.calls == [
        ("get_pull", {"repo": REPO, "number": 12}),
        ("list_pull_files", {"repo": REPO, "number": 12, "params": {"per_page": "30"}}),
    ]
    content = result.content
    assert content["title"] == "Raise proxy timeout"
    assert len(content["body"]) == 1500
    assert "hunter2" not in content["body"]
    assert (content["base"], content["head"], content["author"]) == (
        "main",
        "fix/proxy-timeout",
        "dev2",
    )
    assert content["changed_files"] == 40
    assert len(content["files"]) == 30
    assert content["truncated"] is True
    assert "requested_reviewers" not in content


def _http_ctx(tool_ctx: ToolContext) -> ToolContext:
    client = GitHubClient(
        app_id=GITHUB_APP_ID,
        installation_id=GITHUB_INSTALLATION_ID,
        org=GITHUB_ORG,
        private_key=github_private_pem(),
    )
    return dataclasses.replace(tool_ctx, github=client, alarm_time=ALARM_TIME)


def _response(payload: Any) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return response


def _token() -> MagicMock:
    return _response({"token": TOKEN, "expires_at": "2099-01-01T00:00:00Z"})


def _http_error(code: int, headers: dict[str, str] | None = None) -> urllib.error.HTTPError:
    message = Message()
    for name, value in (headers or {}).items():
        message[name] = value
    body = io.BytesIO(b'{"message": "Bad credentials"}')
    return urllib.error.HTTPError("https://api.github.com/x", code, "Error", message, body)


@pytest.mark.parametrize(
    ("name", "tool_input", "failure", "message"),
    [
        (
            "github_search_code",
            {"query": "proxy error"},
            _http_error(403, {"x-ratelimit-remaining": "0"}),
            "GitHub code search failed: HTTP 403 (rate limited, try again later)",
        ),
        (
            "github_search_code",
            {"query": "proxy error"},
            _http_error(422),
            "GitHub code search failed: HTTP 422 (request rejected)",
        ),
        (
            "github_get_file",
            {"repo": REPO, "path": "missing.py"},
            _http_error(404),
            "GitHub file read failed: HTTP 404 (not found)",
        ),
        (
            "github_get_change",
            {"repo": REPO, "sha": "abcdef1"},
            _http_error(401),
            "GitHub commit read failed: HTTP 401 (credentials rejected)",
        ),
        (
            "github_get_change",
            {"repo": REPO, "number": 3},
            _http_error(429),
            "GitHub pull request read failed: HTTP 429 (rate limited, try again later)",
        ),
        (
            "github_list_repos",
            {},
            _http_error(403),
            "GitHub repo list failed: HTTP 403 (not permitted)",
        ),
    ],
)
def test_http_failures_become_error_results_without_credentials(
    tool_ctx: ToolContext,
    mocker: MockerFixture,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    name: str,
    tool_input: dict[str, Any],
    failure: Exception,
    message: str,
) -> None:
    mocker.patch.object(github_module.urllib.request, "urlopen", side_effect=[_token(), failure])
    with caplog.at_level(logging.DEBUG):
        result = run_tool(name, tool_input, _http_ctx(tool_ctx))
    assert result.status == "error"
    assert result.content == {"error": message}
    captured = capsys.readouterr()
    for text in (json.dumps(result.content), caplog.text, captured.out, captured.err):
        assert TOKEN not in text
        assert "PRIVATE KEY" not in text


def test_recent_changes_through_the_client_reports_a_rate_limited_section(
    tool_ctx: ToolContext, mocker: MockerFixture
) -> None:
    mocker.patch.object(
        github_module.urllib.request,
        "urlopen",
        side_effect=[
            _token(),
            _response([_commit("0123456789", "ok")]),
            _http_error(403, {"retry-after": "30"}),
            _response({"workflow_runs": []}),
        ],
    )
    result = run_tool("github_recent_changes", {"repo": REPO}, _http_ctx(tool_ctx))
    assert result.status == "success"
    assert result.content["errors"] == {
        "merged_pulls": "GitHub pull request list failed: HTTP 403 (rate limited, try again later)"
    }
    assert TOKEN not in json.dumps(result.content)
