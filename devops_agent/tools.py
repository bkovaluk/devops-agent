"""Read-only investigation tools.

Every tool in READ_ONLY_TOOLS only reads: none creates, changes or deletes
anything, and READ_ONLY_OPERATIONS names every client operation they call, the boto3
ones and the Datadog and GitHub reads (a test pins the two together). The one exception
is aws_call, which runs an operation named at run time and only when aws_guard allows
it. Write safety does not rest on this module; the execution role grants no write
outside the findings table and the Slack topic. Output is projected to small JSON before
the model sees it, and everything returned is untrusted data.
"""

from __future__ import annotations

import base64
import contextlib
import difflib
import html
import json
import math
import os
import re
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from itertools import zip_longest
from operator import itemgetter
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import botocore.session
from botocore import xform_name
from botocore.exceptions import ClientError, DataNotFoundError, ParamValidationError
from botocore.loaders import JSONFileLoader
from botocore.model import ServiceModel
from botocore.response import StreamingBody
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from devops_agent import aws_guard
from devops_agent.catalog import load_catalog
from devops_agent.datadog import DatadogError
from devops_agent.github import MAX_REPO_PAGES, REPO_PAGE_SIZE, GitHubError
from devops_agent.models import ToolCallDescriptor
from devops_agent.redact import redact, redact_value

READ_ONLY_OPERATIONS = frozenset(
    {
        "describe_alarms",
        "describe_alarm_history",
        "list_tags_for_resource",
        "get_metric_data",
        "start_query",
        "get_query_results",
        "stop_query",
        "lookup_events",
        "describe_log_groups",
        "list_event_source_mappings",
        "get_queue_url",
        "get_queue_attributes",
        "get_bucket_versioning",
        "list_object_versions",
        "list_objects_v2",
        "describe_stream_summary",
        "describe_db_clusters",
        "describe_db_instances",
        "describe_events",
        "get_resource_metrics",
        "describe_domain",
        "describe_domain_health",
        "describe_load_balancers",
        "describe_target_groups",
        "describe_target_health",
        "describe_replication_groups",
        "describe_cache_clusters",
        "describe_state_machine",
        "list_executions",
        "list_state_machines",
        "get_stages",
        "describe_instances",
        "list_rules",
        "list_targets_by_rule",
        "list_schedules",
        "get_schedule",
        "search_logs",
        "aggregate_logs",
        "search_events",
        "query_metrics",
        "list_org_repos",
        "search_code",
        "get_contents",
        "list_commits",
        "get_commit",
        "list_pulls",
        "get_pull",
        "list_pull_files",
        "list_workflow_runs",
    }
)

MAX_ALARM_HISTORY = 10
MAX_METRIC_POINTS = 200
METRIC_PERIODS = (60, 300)
MAX_WINDOW_DAYS = 14
MAX_METRIC_MINUTES = 360
MAX_LOG_MINUTES = 180
MAX_CHANGE_MINUTES = 180
MAX_LOG_ROWS = 50
MAX_LOG_FIELD_CHARS = 500
MAX_CHANGE_EVENTS = 50
MAX_REASON_CHARS = 300
MAX_LOG_SOURCES = 10
MAX_EVENT_SOURCE_MAPPINGS = 10
MAX_DB_MEMBERS = 20
MAX_DB_EVENTS = 20
DB_EVENT_PAGE = 100
DB_EVENT_HOURS = 24
MAX_PI_KEYS = 5
MAX_STATEMENT_CHARS = 300
MAX_TARGET_GROUPS = 10
MAX_TARGETS = 50
MAX_EXECUTIONS = 20
MAX_STATE_MACHINE_PAGES = 5
MAX_S3_VERSIONS = 10
S3_VERSION_PAGE = 20
MAX_SIMILAR_KEYS = 10
MAX_SCHEDULE_HOURS = 24
MAX_SCHEDULES = 20
MAX_FIRE_TIMES = 5
MAX_RULE_TARGETS = 5
MAX_TARGET_INPUT_CHARS = 200
SCHEDULE_PAGE = 100
MAX_SCHEDULE_PAGES = 5
MAX_SCHEDULER_LOOKUPS = 100
QUERY_POLL_SECONDS = 20.0
QUERY_POLL_INTERVAL = 1.0
MAX_DATADOG_LOGS = 50
MAX_DATADOG_LOG_MINUTES = 180
MAX_DATADOG_HOST_CHARS = 200
SEARCH_DATADOG_LOGS = "search_datadog_logs"
MAX_DATADOG_SERVICES = 25
MAX_DATADOG_EVENTS = 50
MAX_DATADOG_EVENT_MINUTES = 360
MAX_DATADOG_EVENT_CHARS = 400
# Kept from an event's tags; every other tag is dropped.
DATADOG_EVENT_TAGS = (
    "kube_namespace",
    "kube_deployment",
    "pod_name",
    "service",
    "env",
    "kube_cluster",
)
DATADOG_EVENTS = "datadog_events"
MAX_TOP_PODS = 10
MAX_TOP_POD_MINUTES = 180
DATADOG_TOP_PODS = "datadog_top_pods"
DATADOG_TOOLS = frozenset(
    {
        SEARCH_DATADOG_LOGS,
        DATADOG_EVENTS,
        DATADOG_TOP_PODS,
    }
)
GITHUB_LIST_REPOS = "github_list_repos"
GITHUB_SEARCH_CODE = "github_search_code"
GITHUB_GET_FILE = "github_get_file"
GITHUB_RECENT_CHANGES = "github_recent_changes"
GITHUB_GET_CHANGE = "github_get_change"
GITHUB_TOOLS = frozenset(
    {
        GITHUB_LIST_REPOS,
        GITHUB_SEARCH_CODE,
        GITHUB_GET_FILE,
        GITHUB_RECENT_CHANGES,
        GITHUB_GET_CHANGE,
    }
)
MAX_GITHUB_REPOS = 50
# A listing this long may have stopped at the client's page limit.
REPO_LISTING_LIMIT = MAX_REPO_PAGES * REPO_PAGE_SIZE
MAX_GITHUB_DESCRIPTION_CHARS = 120
MAX_GITHUB_SEARCH_RESULTS = 20
MAX_GITHUB_FRAGMENTS = 2
MAX_GITHUB_FRAGMENT_CHARS = 300
MAX_GITHUB_FILE_BYTES = 200 * 1024
MAX_GITHUB_CONTEXT_LINES = 40  # 81 lines stays under the 8,000-char tool result cap
GITHUB_FIRST_LINES = 80
MAX_GITHUB_LINE_CHARS = 200
MAX_GITHUB_HOURS = 168
MAX_GITHUB_CHANGES = 30
GITHUB_PULLS_PAGE = 30
GITHUB_RUNS_PAGE = 20
MAX_GITHUB_TITLE_CHARS = 200
MAX_GITHUB_COMMIT_MESSAGE_CHARS = 1000
MAX_GITHUB_BODY_CHARS = 1500
MAX_GITHUB_FILES = 30
MAX_GITHUB_PATCH_CHARS = 1500
# Patches past this total are left out, so a large change still fits one tool result.
MAX_GITHUB_PATCHES_CHARS = 3000
AWS_CALL = "aws_call"
AWS_TOOLS = frozenset({AWS_CALL})
AWS_DOC_WORD_CHARS = 300
MAX_AWS_CLOSE_MATCHES = 5
MAX_AWS_PAGE_TOKEN_BYTES = 4096
# Under the 8,000-char tool result cap, so a capped result still parses as JSON.
MAX_AWS_RESULT_CHARS = 7000
# A response key whose lowercased name contains one of these, or equals one of
# SENSITIVE_KEYS, has its value replaced at any depth: such keys carry secrets,
# credentials, environment variables, user data or job arguments. Pagination tokens are
# lifted out as next_token before this runs.
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "privatekey",
    "presharedkey",
    "authkey",
    "environment",
    "userdata",
    "arguments",
    "connectorconfiguration",
    "providerdetails",
    "basicauth",
    "kdcadmin",
    "apikey",
)
# variables / stagevariables: API Gateway stage variables; input: event and schedule
# target payloads.
SENSITIVE_KEYS = frozenset(
    {"env", "environmentvariables", "variables", "stagevariables", "input", "inputtemplate"}
)
REMOVED = "<removed>"
# A string under one of these keys that parses as a JSON object or array longer than
# MIN_EMBEDDED_DOCUMENT_CHARS is a whole definition or configuration; it is replaced.
EMBEDDED_DOCUMENT_KEYS = frozenset(
    {
        "configuration",
        "definition",
        "pipelinedefinition",
        "properties",
        "actualproperties",
        "expectedproperties",
        "parameters",
        "content",
    }
)
MIN_EMBEDDED_DOCUMENT_CHARS = 200
REMOVED_DOCUMENT = "<removed: embedded document>"
MAX_AWS_STRING_CHARS = 500
MAX_DESCRIPTOR_NAME_CHARS = 64
MAX_LABEL_CHARS = 140
MAX_SUBJECT_CHARS = 200
MAX_REFUSED_CHARS = 120
# Slicing or rebuilding a field can cut a secret below what redaction recognizes.
_FORBIDDEN_QUERY = re.compile(
    r"(?i)(?:^|\|)\s*parse\b"
    r"|\b(?:substr|replace|concat|trim|ltrim|rtrim|toupper|tolower|strlen)\s*\("
)


@dataclass(frozen=True)
class ToolContext:
    """The clients a tool may read through, plus the alarm under investigation.

    ``datadog`` is None when the Datadog keys are not configured, and ``github`` when the
    GitHub App credentials are not; their tools are then not offered. ``aws_client``
    returns the client for a botocore service name, for aws_call; when it is None
    aws_call is not offered. ``alarm_time`` is when the alarm entered ALARM, if
    known.
    """

    cloudwatch: Any
    logs: Any
    cloudtrail: Any
    lambda_: Any
    sqs: Any
    kinesis: Any
    rds: Any
    pi: Any
    opensearch: Any
    elbv2: Any
    elasticache: Any
    stepfunctions: Any
    apigatewayv2: Any
    ec2: Any
    s3: Any
    events: Any
    scheduler: Any
    alarm_name: str
    datadog: Any = None
    github: Any = None
    aws_client: Callable[[str], Any] | None = None
    alarm_time: datetime | None = None


class ToolError(Exception):
    """A failure the model is told about in a tool result."""


@dataclass(frozen=True)
class ToolResult:
    status: Literal["success", "error"]
    content: dict[str, Any]
    # A describe tool that succeeded found its resource: that is data, whatever its lists.
    found: bool = False


Provider = Literal["aws", "datadog", "github"]

_SUBJECT_FIELD = re.compile(r"\{(\w+)\}")


def _subject_text(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def call_descriptor(
    provider: Provider,
    service: str,
    action: str,
    subject: str | None = None,
    refused: str | None = None,
) -> ToolCallDescriptor:
    return ToolCallDescriptor(
        provider=provider,
        service=service,
        action=action,
        label=f"{provider}.{service}.{action}",
        subject=subject,
        refused=refused,
    )


@dataclass(frozen=True)
class CallSpec:
    """A tool's fixed call descriptor. ``action`` defaults to the tool name.

    ``subject_keys`` are tried in order and the first whose fields are all present wins:
    an input field name, or a template such as ``"{bucket}/{key}"``.
    """

    provider: Provider
    service: str
    action: str | None = None
    subject_keys: tuple[str, ...] = ()

    def subject(self, values: dict[str, Any]) -> str | None:
        for key in self.subject_keys:
            fields = _SUBJECT_FIELD.findall(key) or [key]
            parts = {field: _subject_text(values.get(field)) for field in fields}
            if all(parts.values()):
                return key.format(**parts) if "{" in key else parts[key]
        return None


@dataclass(frozen=True)
class ReadTool:
    """A read tool. ``call`` is its fixed descriptor, or a function of its input for a
    tool whose service and action depend on the input."""

    name: str
    description: str
    input_model: type[BaseModel]
    run: Callable[[Any, ToolContext], dict[str, Any]]
    call: CallSpec | Callable[[dict[str, Any]], ToolCallDescriptor]
    # Reads one named resource: a success returned data even when its lists are empty
    # (a database with no recent events still has its status).
    describes_resource: bool = False

    def descriptor(self, values: dict[str, Any]) -> ToolCallDescriptor:
        """The call descriptor for one call with these input values."""
        if not isinstance(self.call, CallSpec):
            return self.call(values)
        spec = self.call
        return call_descriptor(
            spec.provider, spec.service, spec.action or self.name, spec.subject(values)
        )

    def spec(self) -> dict[str, Any]:
        """The Bedrock Converse toolSpec for this tool."""
        return {
            "toolSpec": {
                "name": self.name,
                "description": self.description,
                "inputSchema": {"json": self.input_model.model_json_schema()},
            }
        }


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AlarmInput(_Input):
    alarm_name: str = Field(min_length=1, max_length=255)


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


class _WindowInput(_Input):
    """An input with an optional explicit window; times without a zone are UTC."""

    start: datetime | None = Field(
        default=None,
        description=(
            f"Window start, ISO 8601 UTC (e.g. 2026-10-02T03:10:00Z), within the last "
            f"{MAX_WINDOW_DAYS} days."
        ),
    )
    end: datetime | None = Field(
        default=None,
        description=(
            f"Window end, ISO 8601 UTC, within the last {MAX_WINDOW_DAYS} days; a future end "
            "is cut to now."
        ),
    )

    @field_validator("start", "end")
    @classmethod
    def _as_utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value)


class MetricInput(_WindowInput):
    namespace: str = Field(min_length=1, max_length=255)
    metric_name: str = Field(min_length=1, max_length=255)
    dimensions: dict[str, str] = Field(default_factory=dict, max_length=30)
    stat: str = Field(
        default="Average",
        pattern=r"^(Average|Sum|Minimum|Maximum|SampleCount|p\d{1,2}(\.\d{1,2})?)$",
    )
    period_seconds: int = Field(default=60, ge=60, le=86400, multiple_of=60)
    minutes: int = Field(default=60, ge=1, le=MAX_METRIC_MINUTES)


class LogsQueryInput(_WindowInput):
    log_group: str = Field(min_length=1, max_length=512)
    query: str = Field(min_length=1, max_length=2000)
    minutes: int = Field(default=60, ge=1, le=MAX_LOG_MINUTES)

    @field_validator("query")
    @classmethod
    def _no_field_rewriting(cls, query: str) -> str:
        if _FORBIDDEN_QUERY.search(query):
            raise ValueError(
                "parse and string functions (substr, replace, concat, trim, ltrim, rtrim, "
                "toupper, tolower, strlen) are not allowed; use fields, filter, stats and "
                "pattern"
            )
        return query


class ChangesInput(_WindowInput):
    minutes: int = Field(default=60, ge=1, le=MAX_CHANGE_MINUTES)


class S3KeyInput(_Input):
    bucket: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
    key: str = Field(min_length=1, max_length=1024, pattern=r"^[^\x00-\x1f\x7f]+$")


class DatabaseInput(_Input):
    identifier: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9-]{0,62}$")
    minutes: int = Field(default=60, ge=1, le=360)


class SearchDomainInput(_Input):
    domain_name: str = Field(pattern=r"^[a-z][a-z0-9-]{2,27}$")


class TargetsInput(_Input):
    load_balancer_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9-]{1,32}$")
    target_group_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9-]{1,32}$")

    @model_validator(mode="after")
    def _exactly_one_name(self) -> TargetsInput:
        if (self.load_balancer_name is None) == (self.target_group_name is None):
            raise ValueError("give exactly one of load_balancer_name or target_group_name")
        return self


_INSTANCE_ID = r"^i-[0-9a-f]{8,17}$"


class InstanceInput(_Input):
    instance_id: str = Field(pattern=_INSTANCE_ID)


class ExecutionsInput(_Input):
    state_machine_name: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    status: Literal["RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED", "PENDING_REDRIVE"] = (
        "FAILED"
    )


class ScheduledJobsInput(_WindowInput):
    name_contains: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9_.-]{1,64}$",
        description="A plain part of a schedule or rule name; case-insensitive.",
    )
    hours: int = Field(default=2, ge=1, le=MAX_SCHEDULE_HOURS)


# The model never writes a Datadog query: code builds it from these fields, and free text
# is plain words and quoted phrases only.
_DATADOG_TEXT_OPERATORS = re.compile(r"[:*?()\[\]{}\\]|\b(?:OR|AND|NOT)\b|(?:^|\s)[-+]")


class DatadogLogsInput(_WindowInput):
    service: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,99}$")
    name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_./-]{1,50}$")
    env: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,49}$")
    status: Literal["error", "warn", "info"] | None = None
    text: str | None = Field(default=None, min_length=1, max_length=100)
    minutes: int = Field(default=30, ge=1, le=MAX_DATADOG_LOG_MINUTES)
    limit: int = Field(default=25, ge=1, le=MAX_DATADOG_LOGS)

    @field_validator("text")
    @classmethod
    def _plain_words_and_phrases(cls, text: str | None) -> str | None:
        if text is None:
            return None
        if _DATADOG_TEXT_OPERATORS.search(text) or text.count('"') % 2:
            raise ValueError(
                "use plain words and quoted phrases only: no :, *, ?, brackets, "
                "backslashes, OR, AND, NOT, leading - or +, or unbalanced quotes"
            )
        return text

    @field_validator("name")
    @classmethod
    def _plain_substring(cls, name: str | None) -> str | None:
        if name is not None and _DATADOG_TEXT_OPERATORS.search(name):
            raise ValueError(
                "use a plain part of a service name: no :, *, ?, brackets, backslashes, "
                "OR, AND, NOT, or leading - or +"
            )
        return name

    @model_validator(mode="after")
    def _service_or_services(self) -> DatadogLogsInput:
        if self.service is not None and self.name is not None:
            raise ValueError("give name only without service, to find a service's exact name")
        if self.service is None and self.status is not None:
            raise ValueError("give status only with service; without one, services are ranked")
        return self


_DATADOG_SERVICE = r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,99}$"
_DATADOG_ENV = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,49}$"


class DatadogEventsInput(_WindowInput):
    service: str | None = Field(default=None, pattern=_DATADOG_SERVICE)
    kube_namespace: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
    env: str | None = Field(default=None, pattern=_DATADOG_ENV)
    source: Literal["change_tracking", "alert", "deployment_analysis"] = "change_tracking"
    minutes: int = Field(default=60, ge=1, le=MAX_DATADOG_EVENT_MINUTES)
    limit: int = Field(default=20, ge=1, le=MAX_DATADOG_EVENTS)

    @model_validator(mode="after")
    def _one_scope(self) -> DatadogEventsInput:
        if (self.service is None) == (self.kube_namespace is None):
            raise ValueError("give exactly one of service or kube_namespace")
        return self


_DATADOG_KUBE_NAME = r"^[A-Za-z0-9_.-]{1,100}$"


class DatadogTopPodsInput(_WindowInput):
    host: str | None = Field(
        default=None, pattern=_INSTANCE_ID, description="An EC2 instance id: an EKS node."
    )
    cluster: str | None = Field(
        default=None, pattern=_DATADOG_KUBE_NAME, description="A kube_cluster_name."
    )
    kube_namespace: str | None = Field(default=None, pattern=_DATADOG_KUBE_NAME)
    metric: Literal["cpu", "memory"] = "cpu"
    minutes: int = Field(default=60, ge=1, le=MAX_TOP_POD_MINUTES)

    @model_validator(mode="after")
    def _one_scope(self) -> DatadogTopPodsInput:
        if (self.host is None) == (self.cluster is None):
            raise ValueError("give exactly one of host or cluster")
        return self


_GITHUB_REPO = r"^[A-Za-z0-9_.-]{1,100}$"
_GITHUB_PATH = r"^[A-Za-z0-9_./-]{1,400}$"
_GITHUB_REF = r"^[A-Za-z0-9_./-]{1,100}$"
# Search text is plain words and quoted phrases: code adds every qualifier.
_GITHUB_SEARCH_OPERATORS = re.compile(
    r"(?i:\b(?:org|repo|path|language|extension|filename)\b)"
    r"|:|\b(?:OR|AND|NOT)\b|(?:^|\s)-|[\x00-\x1f\\]"
)


def _repo_name(value: Any) -> Any:
    if isinstance(value, str) and "/" in value:
        raise ValueError("give the repo name only; the owner is always the configured org")
    if isinstance(value, str) and ".." in value:
        raise ValueError("'..' is not allowed")
    return value


def _repo_path(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if ".." in value or value.startswith("/") or "//" in value:
        raise ValueError("give a path relative to the repo root, without '..' or '//'")
    return value.rstrip("/")


class GitHubListReposInput(_Input):
    name: str | None = Field(default=None, pattern=_GITHUB_REPO)
    sort: Literal["pushed", "name"] = "pushed"
    limit: int = Field(default=20, ge=1, le=MAX_GITHUB_REPOS)


class GitHubSearchCodeInput(_Input):
    query: str = Field(min_length=1, max_length=128)
    repo: str | None = Field(default=None, pattern=_GITHUB_REPO)
    path: str | None = Field(default=None, pattern=_GITHUB_PATH)
    limit: int = Field(default=10, ge=1, le=MAX_GITHUB_SEARCH_RESULTS)

    _check_repo = field_validator("repo", mode="before")(_repo_name)
    _check_path = field_validator("path", mode="before")(_repo_path)

    @field_validator("query")
    @classmethod
    def _plain_words_and_phrases(cls, query: str) -> str:
        if _GITHUB_SEARCH_OPERATORS.search(query) or query.count('"') % 2:
            raise ValueError(
                "use plain words and quoted phrases only: no ':', qualifiers (org, repo, "
                "path, language, extension, filename), OR, AND, NOT, leading -, "
                "backslashes or unbalanced quotes"
            )
        return query.strip()


class GitHubFileInput(_Input):
    repo: str = Field(pattern=_GITHUB_REPO)
    path: str = Field(pattern=_GITHUB_PATH)
    ref: str | None = Field(default=None, pattern=_GITHUB_REF)
    line: int | None = Field(default=None, ge=1)
    context: int = Field(default=30, ge=0, le=MAX_GITHUB_CONTEXT_LINES)

    _check_repo = field_validator("repo", mode="before")(_repo_name)
    _check_path = field_validator("path", mode="before")(_repo_path)

    @field_validator("ref", mode="before")
    @classmethod
    def _no_parent_ref(cls, ref: Any) -> Any:
        if isinstance(ref, str) and ".." in ref:
            raise ValueError("'..' is not allowed")
        return ref


class GitHubChangesInput(_WindowInput):
    repo: str = Field(pattern=_GITHUB_REPO)
    path: str | None = Field(default=None, pattern=_GITHUB_PATH)
    hours: int = Field(default=24, ge=1, le=MAX_GITHUB_HOURS)
    limit: int = Field(default=15, ge=1, le=MAX_GITHUB_CHANGES)

    _check_repo = field_validator("repo", mode="before")(_repo_name)
    _check_path = field_validator("path", mode="before")(_repo_path)


class GitHubChangeInput(_Input):
    repo: str = Field(pattern=_GITHUB_REPO)
    sha: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{7,40}$")
    number: int | None = Field(default=None, ge=1, le=10_000_000)

    _check_repo = field_validator("repo", mode="before")(_repo_name)

    @model_validator(mode="after")
    def _one_change(self) -> GitHubChangeInput:
        if (self.sha is None) == (self.number is None):
            raise ValueError("give exactly one of sha or number")
        return self


_AWS_SERVICE = r"^[a-z0-9][a-z0-9-]{0,62}$"


class AwsCallInput(_Input):
    service: str = Field(pattern=_AWS_SERVICE)
    operation: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,127}$")
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("operation")
    @classmethod
    def _snake_case(cls, value: str) -> str:
        return str(xform_name(value))


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return None if value is None else str(value)


def time_window(
    start: datetime | None,
    end: datetime | None,
    length: timedelta,
    longest: timedelta,
    alarm_time: datetime | None,
) -> tuple[datetime, datetime]:
    """The window a time-based tool reads.

    Without start or end it is ``length`` ending when the alarm fired (or now, when that is
    unknown or later). With one of them it is ``length`` from it; with both, exactly those.
    An explicit start or end must be within the last MAX_WINDOW_DAYS days, an end in the
    future is cut to now, and the window is at most ``longest``.
    """
    now = datetime.now(UTC)
    if end is not None:
        end = min(_utc(end), now)
    if start is not None and end is not None:
        start = _utc(start)
    elif start is not None:
        start = _utc(start)
        end = min(start + length, now)
    elif end is not None:
        start = end - length
    else:
        end = now if alarm_time is None else min(_utc(alarm_time), now)
        return end - length, end
    if start < now - timedelta(days=MAX_WINDOW_DAYS):
        raise ToolError(f"start and end must be within the last {MAX_WINDOW_DAYS} days")
    if end <= start:
        raise ToolError("end must be after start, and start before now")
    if end - start > longest:
        raise ToolError(f"the window is at most {longest // timedelta(hours=1)} hours")
    return start, end


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def window_view(start: datetime, end: datetime) -> dict[str, str]:
    """The window a tool read, as it is echoed in the tool result."""
    return {"start": _utc_text(start), "end": _utc_text(end)}


def _project_alarm(alarm: dict[str, Any]) -> dict[str, Any]:
    projected = {
        "name": alarm.get("AlarmName"),
        "arn": alarm.get("AlarmArn"),
        "description": alarm.get("AlarmDescription"),
        "state": alarm.get("StateValue"),
        "state_reason": alarm.get("StateReason"),
        "state_updated": _iso(alarm.get("StateUpdatedTimestamp")),
        "namespace": alarm.get("Namespace"),
        "metric_name": alarm.get("MetricName"),
        "dimensions": {d["Name"]: d["Value"] for d in alarm.get("Dimensions", [])} or None,
        "statistic": alarm.get("Statistic") or alarm.get("ExtendedStatistic"),
        "period": alarm.get("Period"),
        "threshold": alarm.get("Threshold"),
        "comparison": alarm.get("ComparisonOperator"),
        "evaluation_periods": alarm.get("EvaluationPeriods"),
        "datapoints_to_alarm": alarm.get("DatapointsToAlarm"),
        "treat_missing_data": alarm.get("TreatMissingData"),
        "alarm_rule": alarm.get("AlarmRule"),
        "metrics": [_project_metric_query(q) for q in alarm.get("Metrics", [])] or None,
    }
    return {key: value for key, value in projected.items() if value is not None}


def _project_metric_query(query: dict[str, Any]) -> dict[str, Any]:
    stat = query.get("MetricStat") or {}
    metric = stat.get("Metric") or {}
    projected = {
        "id": query.get("Id"),
        "expression": query.get("Expression"),
        "namespace": metric.get("Namespace"),
        "metric_name": metric.get("MetricName"),
        "dimensions": {d["Name"]: d["Value"] for d in metric.get("Dimensions", [])} or None,
        "stat": stat.get("Stat"),
        "period": stat.get("Period"),
    }
    return {key: value for key, value in projected.items() if value is not None}


def describe_alarm(cloudwatch: Any, alarm_name: str) -> dict[str, Any]:
    """The alarm's raw DescribeAlarms entry, metric or composite."""
    response = cloudwatch.describe_alarms(
        AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm", "CompositeAlarm"]
    )
    alarms = response.get("MetricAlarms", []) + response.get("CompositeAlarms", [])
    if not alarms:
        raise ToolError(f"alarm {alarm_name!r} not found")
    alarm: dict[str, Any] = alarms[0]
    return alarm


def get_alarm(params: AlarmInput, ctx: ToolContext) -> dict[str, Any]:
    alarm = describe_alarm(ctx.cloudwatch, params.alarm_name)
    tags = ctx.cloudwatch.list_tags_for_resource(ResourceARN=alarm["AlarmArn"]).get("Tags", [])
    history = ctx.cloudwatch.describe_alarm_history(
        AlarmName=params.alarm_name,
        MaxRecords=MAX_ALARM_HISTORY,
        ScanBy="TimestampDescending",
    ).get("AlarmHistoryItems", [])
    return {
        "alarm": _project_alarm(alarm),
        "tags": {tag["Key"]: tag["Value"] for tag in tags},
        "history": [
            {
                "time": _iso(item.get("Timestamp")),
                "type": item.get("HistoryItemType"),
                "summary": item.get("HistorySummary"),
            }
            for item in history[:MAX_ALARM_HISTORY]
        ],
    }


def _keyed_metric(config: dict[str, Any]) -> tuple[str, dict[str, str]] | None:
    """The metric an alarm is keyed by: its own, or a metric-math alarm's first with
    dimensions."""
    if not config.get("Metrics"):
        metrics = alarm_metrics(config)
        return metrics[0] if metrics else None
    return next(
        (
            (namespace, dimensions)
            for namespace, dimensions in alarm_metrics({"Metrics": config["Metrics"]})
            if dimensions
        ),
        None,
    )


def primary_key(config: dict[str, Any]) -> tuple[str, str, dict[str, str]] | None:
    """(key, namespace, dimensions) for a metric or metric-math alarm; None for composite."""
    if config.get("AlarmRule"):
        return None
    metric = _keyed_metric(config)
    if metric is None:
        return None
    namespace, dimensions = metric
    catalog = load_catalog()
    # The catalog's dimension that names the resource, most specific first; other
    # namespaces use the alarm's first dimension. Keys name the resource, not the metric
    # family: an ECS service keys as AWS/ECS whether its alarm reads the ECS or the
    # Container Insights metrics.
    preferred = catalog.primary_dimensions().get(namespace, ())
    name = next((dim for dim in preferred if dim in dimensions), next(iter(dimensions), None))
    if name is None:
        return None
    key_namespace = catalog.key_namespaces().get(namespace, namespace)
    return f"{key_namespace}:{name}={dimensions[name]}", namespace, dimensions


def firing_alarms(cloudwatch: Any, exclude: str) -> tuple[list[dict[str, Any]], bool]:
    """The raw configs of the alarms in ALARM other than ``exclude``, and whether cut."""
    response = cloudwatch.describe_alarms(
        StateValue="ALARM", AlarmTypes=["MetricAlarm", "CompositeAlarm"], MaxRecords=100
    )
    others = [
        alarm
        for alarm in response.get("MetricAlarms", []) + response.get("CompositeAlarms", [])
        if alarm.get("AlarmName") != exclude
    ]
    return others, "NextToken" in response


def project_firing_alarm(alarm: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": alarm.get("AlarmName"),
        "state_reason": (alarm.get("StateReason") or "")[:MAX_REASON_CHARS],
        "updated": _iso(alarm.get("StateUpdatedTimestamp")),
    }


def metric_points(
    cloudwatch: Any,
    params: MetricInput,
    start: datetime,
    end: datetime,
    max_points: int,
) -> tuple[str | None, list[tuple[Any, float]]]:
    """The series' status and its newest ``max_points`` (timestamp, value), oldest first.

    The status is None when CloudWatch returns no result for the query.
    """
    response = cloudwatch.get_metric_data(
        MetricDataQueries=[
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {
                        "Namespace": params.namespace,
                        "MetricName": params.metric_name,
                        "Dimensions": [
                            {"Name": name, "Value": value}
                            for name, value in params.dimensions.items()
                        ],
                    },
                    "Period": params.period_seconds,
                    "Stat": params.stat,
                },
                "ReturnData": True,
            }
        ],
        StartTime=start,
        EndTime=end,
        ScanBy="TimestampDescending",
        MaxDatapoints=max_points,
    )
    results = response.get("MetricDataResults", [])
    if not results:
        return None, []
    result = results[0]
    newest_first = list(zip(result.get("Timestamps", []), result.get("Values", []), strict=False))
    points = [(ts, float(value)) for ts, value in newest_first[:max_points][::-1]]
    return result.get("StatusCode"), points


def metric_period(requested: int, start: datetime, end: datetime) -> int:
    """The requested period, or the shortest of METRIC_PERIODS that keeps the window's
    series within MAX_METRIC_POINTS."""
    needed = math.ceil((end - start).total_seconds() / MAX_METRIC_POINTS)
    if requested >= needed:
        return requested
    return next(period for period in METRIC_PERIODS if period >= needed)


def get_metric(params: MetricInput, ctx: ToolContext) -> dict[str, Any]:
    start, end = time_window(
        params.start,
        params.end,
        timedelta(minutes=params.minutes),
        timedelta(minutes=MAX_METRIC_MINUTES),
        ctx.alarm_time,
    )
    period = metric_period(params.period_seconds, start, end)
    series = params.model_copy(update={"period_seconds": period})
    status, points = metric_points(ctx.cloudwatch, series, start, end, MAX_METRIC_POINTS)
    window = window_view(start, end)
    if status is None:
        return {"status": "NoData", "window": window, "points": []}
    return {
        "status": status,
        "window": window,
        "stat": params.stat,
        "period_seconds": period,
        "points": [{"t": _iso(ts), "v": round(value, 4)} for ts, value in points],
    }


def _project_log_row(row: list[dict[str, Any]]) -> dict[str, str]:
    # Redacted before the cut: a secret split at the limit is no longer recognizable.
    return {
        field["field"]: redact(str(field.get("value", "")))[:MAX_LOG_FIELD_CHARS]
        for field in row
        if field.get("field") != "@ptr"
    }


def query_logs(params: LogsQueryInput, ctx: ToolContext) -> dict[str, Any]:
    start, end = time_window(
        params.start,
        params.end,
        timedelta(minutes=params.minutes),
        timedelta(minutes=MAX_LOG_MINUTES),
        ctx.alarm_time,
    )
    query_id = ctx.logs.start_query(
        logGroupName=params.log_group,
        startTime=int(start.timestamp()),
        endTime=int(end.timestamp()),
        queryString=params.query,
        limit=MAX_LOG_ROWS,
    )["queryId"]
    deadline = time.monotonic() + QUERY_POLL_SECONDS
    while True:
        response = ctx.logs.get_query_results(queryId=query_id)
        status = response.get("status")
        if status not in ("Scheduled", "Running"):
            break
        if time.monotonic() >= deadline:
            with contextlib.suppress(ClientError):
                ctx.logs.stop_query(queryId=query_id)
            status = "Stopped"
            break
        time.sleep(QUERY_POLL_INTERVAL)
    rows = [_project_log_row(row) for row in response.get("results", [])[:MAX_LOG_ROWS]]
    return {
        "status": status,
        "window": window_view(start, end),
        "row_count": len(rows),
        "rows": rows,
    }


def lookup_changes(cloudtrail: Any, start: datetime, end: datetime, limit: int) -> dict[str, Any]:
    """The newest ``limit`` CloudTrail write events between ``start`` and ``end``."""
    response = cloudtrail.lookup_events(
        LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
        StartTime=start,
        EndTime=end,
        MaxResults=limit,
    )
    events = response.get("Events", [])[:limit]
    return {
        "count": len(events),
        "truncated": "NextToken" in response,
        "events": [
            {
                "time": _iso(event.get("EventTime")),
                "event_name": event.get("EventName"),
                "event_source": event.get("EventSource"),
                "username": event.get("Username"),
                "resources": [
                    resource["ResourceName"]
                    for resource in event.get("Resources", [])
                    if resource.get("ResourceName")
                ],
            }
            for event in events
        ],
    }


def recent_changes(params: ChangesInput, ctx: ToolContext) -> dict[str, Any]:
    start, end = time_window(
        params.start,
        params.end,
        timedelta(minutes=params.minutes),
        timedelta(minutes=MAX_CHANGE_MINUTES),
        ctx.alarm_time,
    )
    return {
        "window": window_view(start, end),
        **lookup_changes(ctx.cloudtrail, start, end, MAX_CHANGE_EVENTS),
    }


_NOT_FOUND_CODES = frozenset(
    {
        "AWS.SimpleQueueService.NonExistentQueue",
        "QueueDoesNotExist",
        "ResourceNotFoundException",
        "NotFoundException",
        "DBClusterNotFoundFault",
        "DBInstanceNotFound",
        "LoadBalancerNotFound",
        "TargetGroupNotFound",
        "ReplicationGroupNotFoundFault",
        "CacheClusterNotFound",
        "StateMachineDoesNotExist",
        "InvalidInstanceID.NotFound",
        "NoSuchBucket",
    }
)
_PI_STATEMENT = "db.sql_tokenized.statement"


def _compact(projected: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in projected.items() if value is not None}


def _error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", "ClientError"))


@contextlib.contextmanager
def _not_found(kind: str, name: str) -> Iterator[None]:
    """Turn a not-found ClientError into a tool error that names the missing resource."""
    try:
        yield
    except ClientError as exc:
        if _error_code(exc) in _NOT_FOUND_CODES:
            raise ToolError(f"{kind} {name!r} not found") from None
        raise


def _log_group_from_arn(arn: str) -> str:
    return arn.split(":log-group:", 1)[-1].removesuffix(":*")


def _function_name(function_arn: str) -> str | None:
    if ":function:" not in function_arn:
        return None
    return function_arn.split(":function:", 1)[1].split(":")[0]


def consumer_functions(lambda_: Any, source_arn: str) -> list[str]:
    """The Lambda functions consuming a queue or stream through event source mappings."""
    response = lambda_.list_event_source_mappings(
        EventSourceArn=source_arn, MaxItems=MAX_EVENT_SOURCE_MAPPINGS
    )
    return [
        function
        for mapping in response.get("EventSourceMappings", [])[:MAX_EVENT_SOURCE_MAPPINGS]
        if (function := _function_name(mapping.get("FunctionArn", "")))
    ]


def _queue_attributes(sqs: Any, queue_name: str, names: tuple[str, ...]) -> dict[str, str]:
    with _not_found("queue", queue_name):
        url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
        response = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=list(names))
    attributes: dict[str, str] = response.get("Attributes", {})
    return attributes


def queue_arn(sqs: Any, queue_name: str) -> str:
    return _queue_attributes(sqs, queue_name, ("QueueArn",))["QueueArn"]


def _stream_summary(kinesis: Any, stream_name: str) -> dict[str, Any]:
    with _not_found("stream", stream_name):
        response = kinesis.describe_stream_summary(StreamName=stream_name)
    summary: dict[str, Any] = response["StreamDescriptionSummary"]
    return summary


def stream_arn(kinesis: Any, stream_name: str) -> str:
    arn: str = _stream_summary(kinesis, stream_name)["StreamARN"]
    return arn


def _search_domain(ctx: ToolContext, domain_name: str) -> dict[str, Any]:
    with _not_found("search domain", domain_name):
        response = ctx.opensearch.describe_domain(DomainName=domain_name)
    status: dict[str, Any] = response["DomainStatus"]
    return status


def _replication_group(ctx: ToolContext, group_id: str) -> dict[str, Any]:
    with _not_found("replication group", group_id):
        response = ctx.elasticache.describe_replication_groups(ReplicationGroupId=group_id)
    group: dict[str, Any] = response["ReplicationGroups"][0]
    return group


def _cloudwatch_log_group(config: dict[str, Any]) -> str | None:
    if config.get("DestinationType") != "cloudwatch-logs":
        return None
    details = (config.get("DestinationDetails") or {}).get("CloudWatchLogsDetails") or {}
    return details.get("LogGroup")


@dataclass(frozen=True)
class _LogCandidate:
    """A log group a metric's resource writes to; prefix matches every group under name."""

    name: str
    why: str
    prefix: bool = False


def _lambda_logs(dims: dict[str, str], ctx: ToolContext) -> list[_LogCandidate]:
    name = dims.get("FunctionName")
    return [_LogCandidate(f"/aws/lambda/{name}", f"Lambda function {name}")] if name else []


def _rds_logs(dims: dict[str, str], ctx: ToolContext) -> list[_LogCandidate]:
    candidates = []
    if cluster := dims.get("DBClusterIdentifier"):
        candidates.append(
            _LogCandidate(f"/aws/rds/cluster/{cluster}/", f"RDS cluster {cluster}", prefix=True)
        )
    if instance := dims.get("DBInstanceIdentifier"):
        candidates.append(
            _LogCandidate(f"/aws/rds/instance/{instance}/", f"RDS instance {instance}", prefix=True)
        )
    return candidates


def _docdb_logs(dims: dict[str, str], ctx: ToolContext) -> list[_LogCandidate]:
    cluster = dims.get("DBClusterIdentifier")
    if not cluster:
        return []
    return [_LogCandidate(f"/aws/docdb/{cluster}/", f"DocumentDB cluster {cluster}", prefix=True)]


def _search_domain_logs(dims: dict[str, str], ctx: ToolContext) -> list[_LogCandidate]:
    domain = dims.get("DomainName")
    if not domain:
        return []
    options = _search_domain(ctx, domain).get("LogPublishingOptions", {})
    return [
        _LogCandidate(
            _log_group_from_arn(option["CloudWatchLogsLogGroupArn"]),
            f"OpenSearch domain {domain} {log_type}",
        )
        for log_type, option in sorted(options.items())
        if option.get("Enabled") and option.get("CloudWatchLogsLogGroupArn")
    ]


def _log_delivery_logs(configs: list[dict[str, Any]], owner: str) -> list[_LogCandidate]:
    return [
        _LogCandidate(group, f"{owner} {config.get('LogType')}")
        for config in configs
        if (group := _cloudwatch_log_group(config))
    ]


def _cache_logs(dims: dict[str, str], ctx: ToolContext) -> list[_LogCandidate]:
    group_id = dims.get("ReplicationGroupId")
    cluster_id = dims.get("CacheClusterId")
    if not group_id and cluster_id:
        with _not_found("cache cluster", cluster_id):
            response = ctx.elasticache.describe_cache_clusters(CacheClusterId=cluster_id)
        cluster = response["CacheClusters"][0]
        group_id = cluster.get("ReplicationGroupId")
        if not group_id:
            return _log_delivery_logs(
                cluster.get("LogDeliveryConfigurations", []), f"ElastiCache cluster {cluster_id}"
            )
    if not group_id:
        return []
    group = _replication_group(ctx, group_id)
    return _log_delivery_logs(
        group.get("LogDeliveryConfigurations", []), f"ElastiCache replication group {group_id}"
    )


def _state_machine_logs(dims: dict[str, str], ctx: ToolContext) -> list[_LogCandidate]:
    arn = dims.get("StateMachineArn")
    if not arn:
        return []
    name = arn.rsplit(":", 1)[-1]
    with _not_found("state machine", name):
        machine = ctx.stepfunctions.describe_state_machine(stateMachineArn=arn)
    logging = machine.get("loggingConfiguration") or {}
    return [
        _LogCandidate(
            _log_group_from_arn(group_arn),
            f"Step Functions state machine {name} (level {logging.get('level')})",
        )
        for destination in logging.get("destinations", [])
        if (group_arn := (destination.get("cloudWatchLogsLogGroup") or {}).get("logGroupArn"))
    ]


def _api_logs(dims: dict[str, str], ctx: ToolContext) -> list[_LogCandidate]:
    api_id = dims.get("ApiId")
    if not api_id:
        return []
    with _not_found("API", api_id):
        stages = ctx.apigatewayv2.get_stages(ApiId=api_id, MaxResults=str(MAX_LOG_SOURCES))
    candidates = [_LogCandidate(f"/aws/apigateway/{api_id}", f"API {api_id}", prefix=True)]
    for stage in stages.get("Items", []):
        destination = (stage.get("AccessLogSettings") or {}).get("DestinationArn") or ""
        if ":log-group:" in destination:
            why = f"API {api_id} stage {stage.get('StageName')} access log"
            candidates.append(_LogCandidate(_log_group_from_arn(destination), why))
    return candidates


def _consumer_logs(ctx: ToolContext, source_arn: str, source: str) -> list[_LogCandidate]:
    return [
        _LogCandidate(f"/aws/lambda/{function}", f"Lambda function {function} consumes {source}")
        for function in consumer_functions(ctx.lambda_, source_arn)
    ]


def _queue_logs(dims: dict[str, str], ctx: ToolContext) -> list[_LogCandidate]:
    name = dims.get("QueueName")
    if not name:
        return []
    return _consumer_logs(ctx, queue_arn(ctx.sqs, name), f"queue {name}")


def _stream_logs(dims: dict[str, str], ctx: ToolContext) -> list[_LogCandidate]:
    name = dims.get("StreamName")
    if not name:
        return []
    return _consumer_logs(ctx, stream_arn(ctx.kinesis, name), f"stream {name}")


def _sagemaker_logs(dims: dict[str, str], ctx: ToolContext) -> list[_LogCandidate]:
    endpoint = dims.get("EndpointName")
    if not endpoint:
        return []
    return [_LogCandidate(f"/aws/sagemaker/Endpoints/{endpoint}", f"SageMaker endpoint {endpoint}")]


def _eks_logs(dims: dict[str, str], ctx: ToolContext) -> list[_LogCandidate]:
    cluster = dims.get("ClusterName")
    if not cluster:
        return []
    return [_LogCandidate(f"/aws/eks/{cluster}/cluster", f"EKS cluster {cluster} control plane")]


_LOG_SOURCE_MAPPERS: dict[str, Callable[[dict[str, str], ToolContext], list[_LogCandidate]]] = {
    "AWS/Lambda": _lambda_logs,
    "AWS/RDS": _rds_logs,
    "AWS/DocDB": _docdb_logs,
    "AWS/ES": _search_domain_logs,
    "AWS/ElastiCache": _cache_logs,
    "AWS/States": _state_machine_logs,
    "AWS/ApiGateway": _api_logs,
    "AWS/SQS": _queue_logs,
    "AWS/Kinesis": _stream_logs,
    "AWS/SageMaker": _sagemaker_logs,
    "AWS/EKS": _eks_logs,
}


def alarm_metrics(alarm: dict[str, Any]) -> list[tuple[str, dict[str, str]]]:
    """The namespace and dimensions of every metric an alarm watches."""
    stats = [alarm] + [
        (query.get("MetricStat") or {}).get("Metric") or {} for query in alarm.get("Metrics", [])
    ]
    return [
        (stat["Namespace"], {d["Name"]: d["Value"] for d in stat.get("Dimensions", [])})
        for stat in stats
        if stat.get("Namespace")
    ]


def _existing_log_groups(ctx: ToolContext, candidate: _LogCandidate) -> list[str]:
    response = ctx.logs.describe_log_groups(
        logGroupNamePrefix=candidate.name, limit=MAX_LOG_SOURCES
    )
    names = [group["logGroupName"] for group in response.get("logGroups", [])]
    return names if candidate.prefix else [name for name in names if name == candidate.name]


def find_log_sources(params: AlarmInput, ctx: ToolContext) -> dict[str, Any]:
    alarm = describe_alarm(ctx.cloudwatch, params.alarm_name)
    if alarm.get("AlarmRule"):
        return {
            "sources": [],
            "unmapped_reason": "composite alarm: no metric of its own to map",
        }
    sources: dict[str, str] = {}
    reasons: list[str] = []
    for namespace, dimensions in alarm_metrics(alarm):
        mapper = _LOG_SOURCE_MAPPERS.get(namespace)
        if mapper is None:
            reasons.append(f"namespace {namespace} has no log-source mapping")
            continue
        candidates = mapper(dimensions, ctx)
        if not candidates:
            reasons.append(f"no {namespace} dimension names a resource with logs")
        for candidate in candidates:
            if len(sources) >= MAX_LOG_SOURCES:
                break
            found = _existing_log_groups(ctx, candidate)
            if not found:
                reasons.append(f"no log group {candidate.name}{'*' if candidate.prefix else ''}")
            for name in found:
                sources.setdefault(name, candidate.why)
    result: dict[str, Any] = {
        "sources": [
            {"log_group": name, "why": why} for name, why in list(sources.items())[:MAX_LOG_SOURCES]
        ]
    }
    if not sources:
        result["unmapped_reason"] = ("; ".join(reasons) or "the alarm watches no metric")[
            :MAX_REASON_CHARS
        ]
    return result


def _key_stem(key: str) -> str:
    """The key without its extension: the text before the last '.' of its final segment."""
    dot = key.rfind(".")
    return key[:dot] if dot > key.rfind("/") + 1 else key


def _project_key_version(entry: dict[str, Any], delete_marker: bool) -> dict[str, Any]:
    if delete_marker:
        return {
            "last_modified": _iso(entry.get("LastModified")),
            "is_latest": bool(entry.get("IsLatest")),
            "delete_marker": True,
        }
    return _compact(
        {
            "last_modified": _iso(entry.get("LastModified")),
            "size": entry.get("Size"),
            "is_latest": bool(entry.get("IsLatest")),
            "storage_class": entry.get("StorageClass"),
        }
    )


def describe_s3_key(params: S3KeyInput, ctx: ToolContext) -> dict[str, Any]:
    with _not_found("bucket", params.bucket):
        versioning = ctx.s3.get_bucket_versioning(Bucket=params.bucket).get("Status") or "Disabled"
        listing = ctx.s3.list_object_versions(
            Bucket=params.bucket, Prefix=params.key, MaxKeys=S3_VERSION_PAGE
        )
        siblings = ctx.s3.list_objects_v2(
            Bucket=params.bucket, Prefix=_key_stem(params.key), MaxKeys=MAX_SIMILAR_KEYS + 1
        )
    entries = [
        (entry, False) for entry in listing.get("Versions", []) if entry.get("Key") == params.key
    ] + [
        (entry, True)
        for entry in listing.get("DeleteMarkers", [])
        if entry.get("Key") == params.key
    ]
    entries.sort(key=lambda item: _iso(item[0].get("LastModified")) or "", reverse=True)
    latest = next((item for item in entries if item[0].get("IsLatest")), None)
    similar = list(
        dict.fromkeys(
            key
            for entry in siblings.get("Contents", [])
            if (key := entry.get("Key")) and key != params.key
        )
    )
    projected: dict[str, Any] = {
        "bucket": params.bucket,
        "key": params.key,
        "versioning": versioning,
        "exists": latest is not None and not latest[1],
        "versions": [
            _project_key_version(entry, marker) for entry, marker in entries[:MAX_S3_VERSIONS]
        ],
        "similar_keys": similar[:MAX_SIMILAR_KEYS],
    }
    if len(entries) > MAX_S3_VERSIONS or (
        listing.get("IsTruncated") and listing.get("NextKeyMarker") == params.key
    ):
        projected["versions_truncated"] = True
    if not entries:
        projected["note"] = (
            "No versions or delete markers: the key most likely never existed "
            "(a lifecycle rule can expire both)"
            if versioning == "Enabled"
            else "Bucket versioning is not enabled: absence cannot tell a key that never "
            "existed from one that was deleted"
        )
    return projected


def _project_cluster(cluster: dict[str, Any], instances: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {instance.get("DBInstanceIdentifier"): instance for instance in instances}
    scaling = cluster.get("ServerlessV2ScalingConfiguration") or {}
    members = []
    for member in cluster.get("DBClusterMembers", [])[:MAX_DB_MEMBERS]:
        instance = by_id.get(member.get("DBInstanceIdentifier"), {})
        members.append(
            _compact(
                {
                    "id": member.get("DBInstanceIdentifier"),
                    "writer": member.get("IsClusterWriter"),
                    "status": instance.get("DBInstanceStatus"),
                    "class": instance.get("DBInstanceClass"),
                    "az": instance.get("AvailabilityZone"),
                    "performance_insights": instance.get("PerformanceInsightsEnabled"),
                }
            )
        )
    return _compact(
        {
            "id": cluster.get("DBClusterIdentifier"),
            "status": cluster.get("Status"),
            "engine": cluster.get("Engine"),
            "engine_version": cluster.get("EngineVersion"),
            "class": cluster.get("DBClusterInstanceClass"),
            "multi_az": cluster.get("MultiAZ"),
            "serverless_v2_capacity": _compact(
                {"min": scaling.get("MinCapacity"), "max": scaling.get("MaxCapacity")}
            )
            or None,
            "performance_insights": cluster.get("PerformanceInsightsEnabled"),
            "members": members,
        }
    )


def _project_instance(instance: dict[str, Any]) -> dict[str, Any]:
    return _compact(
        {
            "id": instance.get("DBInstanceIdentifier"),
            "status": instance.get("DBInstanceStatus"),
            "engine": instance.get("Engine"),
            "engine_version": instance.get("EngineVersion"),
            "class": instance.get("DBInstanceClass"),
            "multi_az": instance.get("MultiAZ"),
            "az": instance.get("AvailabilityZone"),
            "cluster": instance.get("DBClusterIdentifier"),
            "storage_type": instance.get("StorageType"),
            "storage_gb": instance.get("AllocatedStorage"),
            "performance_insights": instance.get("PerformanceInsightsEnabled"),
        }
    )


def database_events(ctx: ToolContext, identifier: str, source_type: str) -> dict[str, Any]:
    length = timedelta(hours=DB_EVENT_HOURS)
    start, end = time_window(None, None, length, length, None)
    response = ctx.rds.describe_events(
        SourceIdentifier=identifier,
        SourceType=source_type,
        StartTime=start,
        EndTime=end,
        MaxRecords=DB_EVENT_PAGE,
    )
    # Events come oldest first; the newest are at the end of the page.
    events = response.get("Events", [])[-MAX_DB_EVENTS:]
    return {
        "truncated": "Marker" in response,
        "items": [
            {
                "time": _iso(event.get("Date")),
                "message": (event.get("Message") or "")[:MAX_REASON_CHARS],
                "categories": event.get("EventCategories", []),
            }
            for event in events
        ],
    }


def _average_load(series: dict[str, Any]) -> float:
    values = [point["Value"] for point in series.get("DataPoints", []) if "Value" in point]
    return round(sum(values) / len(values), 3) if values else 0.0


def _performance_insights(
    ctx: ToolContext, resource_id: str, start: datetime, end: datetime
) -> dict[str, Any]:
    try:
        response = ctx.pi.get_resource_metrics(
            ServiceType="RDS",
            Identifier=resource_id,
            MetricQueries=[
                {
                    "Metric": "db.load.avg",
                    "GroupBy": {
                        "Group": "db.sql_tokenized",
                        "Dimensions": [_PI_STATEMENT],
                        "Limit": MAX_PI_KEYS,
                    },
                },
                {
                    "Metric": "db.load.avg",
                    "GroupBy": {"Group": "db.wait_event", "Limit": MAX_PI_KEYS},
                },
            ],
            StartTime=start,
            EndTime=end,
            PeriodInSeconds=60 if end - start <= timedelta(hours=1) else 300,
        )
    except ClientError as exc:
        return {"error": _error_code(exc)}
    statements: list[dict[str, Any]] = []
    waits: list[dict[str, Any]] = []
    for series in response.get("MetricList", []):
        dimensions = (series.get("Key") or {}).get("Dimensions") or {}
        load = _average_load(series)
        if _PI_STATEMENT in dimensions:
            # Redacted before the cut: a secret split at the limit is no longer recognizable.
            statement = redact(str(dimensions[_PI_STATEMENT]))[:MAX_STATEMENT_CHARS]
            statements.append({"load_avg": load, "statement": statement})
        elif "db.wait_event.name" in dimensions:
            waits.append(
                _compact(
                    {
                        "load_avg": load,
                        "wait_event": dimensions["db.wait_event.name"],
                        "type": dimensions.get("db.wait_event.type"),
                    }
                )
            )
    by_load = itemgetter("load_avg")
    return {
        "window_minutes": int((end - start).total_seconds() // 60),
        "top_sql": sorted(statements, key=by_load, reverse=True)[:MAX_PI_KEYS],
        "top_waits": sorted(waits, key=by_load, reverse=True)[:MAX_PI_KEYS],
    }


def _describe_cluster(ctx: ToolContext, identifier: str) -> dict[str, Any] | None:
    try:
        clusters = ctx.rds.describe_db_clusters(DBClusterIdentifier=identifier)["DBClusters"]
    except ClientError as exc:
        if _error_code(exc) == "DBClusterNotFoundFault":
            return None
        raise
    return clusters[0] if clusters else None


def describe_database(params: DatabaseInput, ctx: ToolContext) -> dict[str, Any]:
    cluster = _describe_cluster(ctx, params.identifier)
    if cluster is not None:
        instances = ctx.rds.describe_db_instances(
            Filters=[{"Name": "db-cluster-id", "Values": [params.identifier]}],
            MaxRecords=MAX_DB_MEMBERS,
        )["DBInstances"]
        writers = {
            member.get("DBInstanceIdentifier")
            for member in cluster.get("DBClusterMembers", [])
            if member.get("IsClusterWriter")
        }
        insights_instance = next(
            (instance for instance in instances if instance.get("DBInstanceIdentifier") in writers),
            None,
        )
        result = {"kind": "cluster", "database": _project_cluster(cluster, instances)}
        source_type = "db-cluster"
    else:
        with _not_found("database", params.identifier):
            instance = ctx.rds.describe_db_instances(DBInstanceIdentifier=params.identifier)[
                "DBInstances"
            ][0]
        insights_instance = instance
        result = {"kind": "instance", "database": _project_instance(instance)}
        source_type = "db-instance"
    result["events"] = database_events(ctx, params.identifier, source_type)
    if insights_instance and insights_instance.get("PerformanceInsightsEnabled"):
        length = timedelta(minutes=params.minutes)
        start, end = time_window(None, None, length, length, ctx.alarm_time)
        result["performance_insights"] = {
            "instance": insights_instance.get("DBInstanceIdentifier"),
            **_performance_insights(ctx, insights_instance["DbiResourceId"], start, end),
        }
    return result


def _domain_health(ctx: ToolContext, domain_name: str) -> dict[str, Any]:
    try:
        health = ctx.opensearch.describe_domain_health(DomainName=domain_name)
    except ClientError as exc:
        return {"error": _error_code(exc)}
    return _compact(
        {
            "state": health.get("DomainState"),
            "cluster_health": health.get("ClusterHealth"),
            "data_nodes": health.get("DataNodeCount"),
            "master_eligible_nodes": health.get("MasterEligibleNodeCount"),
            "master_node": health.get("MasterNode"),
            "active_azs": health.get("ActiveAvailabilityZoneCount"),
            "total_shards": health.get("TotalShards"),
            "unassigned_shards": health.get("TotalUnAssignedShards"),
        }
    )


def describe_search_domain(params: SearchDomainInput, ctx: ToolContext) -> dict[str, Any]:
    status = _search_domain(ctx, params.domain_name)
    cluster = status.get("ClusterConfig") or {}
    ebs = status.get("EBSOptions") or {}
    dedicated_master = bool(cluster.get("DedicatedMasterEnabled"))
    warm = bool(cluster.get("WarmEnabled"))
    return _compact(
        {
            "domain": status.get("DomainName"),
            "engine_version": status.get("EngineVersion"),
            "processing": status.get("Processing"),
            "upgrade_processing": status.get("UpgradeProcessing"),
            "processing_status": status.get("DomainProcessingStatus"),
            "cluster": _compact(
                {
                    "instance_type": cluster.get("InstanceType"),
                    "instance_count": cluster.get("InstanceCount"),
                    "dedicated_master_type": cluster.get("DedicatedMasterType")
                    if dedicated_master
                    else None,
                    "dedicated_master_count": cluster.get("DedicatedMasterCount")
                    if dedicated_master
                    else None,
                    "warm_type": cluster.get("WarmType") if warm else None,
                    "warm_count": cluster.get("WarmCount") if warm else None,
                    "zone_awareness": cluster.get("ZoneAwarenessEnabled"),
                    "multi_az_with_standby": cluster.get("MultiAZWithStandbyEnabled"),
                }
            ),
            "storage": _compact(
                {
                    "volume_type": ebs.get("VolumeType"),
                    "volume_size_gb": ebs.get("VolumeSize"),
                    "iops": ebs.get("Iops"),
                    "throughput": ebs.get("Throughput"),
                }
            )
            if ebs.get("EBSEnabled")
            else None,
            "log_publishing": {
                log_type: _compact(
                    {
                        "enabled": bool(option.get("Enabled")),
                        "log_group": _log_group_from_arn(option["CloudWatchLogsLogGroupArn"])
                        if option.get("CloudWatchLogsLogGroupArn")
                        else None,
                    }
                )
                for log_type, option in sorted((status.get("LogPublishingOptions") or {}).items())
            },
            "health": _domain_health(ctx, params.domain_name),
        }
    )


def _project_target(description: dict[str, Any]) -> dict[str, Any]:
    target = description.get("Target") or {}
    health = description.get("TargetHealth") or {}
    return _compact(
        {
            "id": target.get("Id"),
            "port": target.get("Port"),
            "state": health.get("State"),
            "reason": health.get("Reason"),
            "description": (health.get("Description") or "")[:MAX_REASON_CHARS] or None,
        }
    )


def _project_target_group(
    group: dict[str, Any], health: list[dict[str, Any]], limit: int
) -> dict[str, Any]:
    states = Counter((d.get("TargetHealth") or {}).get("State", "unknown") for d in health)
    # Unhealthy targets first, so the cap drops healthy ones.
    ordered = sorted(health, key=lambda d: (d.get("TargetHealth") or {}).get("State") == "healthy")
    return _compact(
        {
            "name": group.get("TargetGroupName"),
            "protocol": group.get("Protocol"),
            "port": group.get("Port"),
            "target_type": group.get("TargetType"),
            "health_check": _compact(
                {
                    "protocol": group.get("HealthCheckProtocol"),
                    "port": group.get("HealthCheckPort"),
                    "path": group.get("HealthCheckPath"),
                    "interval_seconds": group.get("HealthCheckIntervalSeconds"),
                    "healthy_threshold": group.get("HealthyThresholdCount"),
                    "unhealthy_threshold": group.get("UnhealthyThresholdCount"),
                }
            ),
            "state_counts": dict(states),
            "targets": [_project_target(d) for d in ordered[:limit]],
        }
    )


def describe_targets(params: TargetsInput, ctx: ToolContext) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if params.load_balancer_name is not None:
        with _not_found("load balancer", params.load_balancer_name):
            balancer = ctx.elbv2.describe_load_balancers(Names=[params.load_balancer_name])[
                "LoadBalancers"
            ][0]
        state = balancer.get("State") or {}
        result["load_balancer"] = _compact(
            {
                "name": balancer.get("LoadBalancerName"),
                "type": balancer.get("Type"),
                "scheme": balancer.get("Scheme"),
                "state": state.get("Code"),
                "state_reason": state.get("Reason"),
            }
        )
        groups = ctx.elbv2.describe_target_groups(
            LoadBalancerArn=balancer["LoadBalancerArn"], PageSize=MAX_TARGET_GROUPS
        )
    else:
        target_group_name = str(params.target_group_name)
        with _not_found("target group", target_group_name):
            groups = ctx.elbv2.describe_target_groups(Names=[target_group_name])
    remaining = MAX_TARGETS
    truncated = "NextMarker" in groups
    projected = []
    for group in groups.get("TargetGroups", [])[:MAX_TARGET_GROUPS]:
        health = ctx.elbv2.describe_target_health(TargetGroupArn=group["TargetGroupArn"]).get(
            "TargetHealthDescriptions", []
        )
        truncated = truncated or len(health) > remaining
        projected.append(_project_target_group(group, health, remaining))
        remaining = max(remaining - len(health), 0)
    result["target_groups"] = projected
    result["truncated"] = truncated
    return result


def describe_instance(params: InstanceInput, ctx: ToolContext) -> dict[str, Any]:
    """An EC2 instance's type, state, launch time and the few tags that name it; never its
    other tags."""
    instance_id = params.instance_id
    with _not_found("instance", instance_id):
        reservations = ctx.ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations", [])
    instances = [
        instance for reservation in reservations for instance in reservation.get("Instances", [])
    ]
    if not instances:
        raise ToolError(f"instance {instance_id!r} not found")
    instance = instances[0]
    tags = {tag.get("Key"): tag.get("Value") for tag in instance.get("Tags", [])}
    cluster = tags.get("eks:cluster-name") or tags.get("aws:eks:cluster-name")
    return _compact(
        {
            "instance_id": instance.get("InstanceId", instance_id),
            "instance_type": instance.get("InstanceType"),
            "state": (instance.get("State") or {}).get("Name"),
            "launch_time": _iso(instance.get("LaunchTime")),
            "name": tags.get("Name"),
            "asg": tags.get("aws:autoscaling:groupName"),
            "eks_cluster": cluster,
            "eks_nodegroup": tags.get("eks:nodegroup-name") if cluster else None,
        }
    )


def _state_machine_arn(ctx: ToolContext, name: str) -> str:
    kwargs: dict[str, Any] = {"maxResults": 1000}
    for _ in range(MAX_STATE_MACHINE_PAGES):
        response = ctx.stepfunctions.list_state_machines(**kwargs)
        for machine in response.get("stateMachines", []):
            if machine.get("name") == name:
                return str(machine["stateMachineArn"])
        if not response.get("nextToken"):
            break
        kwargs["nextToken"] = response["nextToken"]
    raise ToolError(f"state machine {name!r} not found")


def recent_executions(params: ExecutionsInput, ctx: ToolContext) -> dict[str, Any]:
    arn = _state_machine_arn(ctx, params.state_machine_name)
    with _not_found("state machine", params.state_machine_name):
        response = ctx.stepfunctions.list_executions(
            stateMachineArn=arn, statusFilter=params.status, maxResults=MAX_EXECUTIONS
        )
    executions = response.get("executions", [])[:MAX_EXECUTIONS]
    return {
        "state_machine": params.state_machine_name,
        "status": params.status,
        "count": len(executions),
        "truncated": "nextToken" in response,
        "executions": [
            _compact(
                {
                    "name": execution.get("name"),
                    "status": execution.get("status"),
                    "start": _iso(execution.get("startDate")),
                    "stop": _iso(execution.get("stopDate")),
                }
            )
            for execution in executions
        ],
    }


# EventBridge cron fields: minute hour day-of-month month day-of-week year. Day of week 1 is
# Sunday.
_CRON_FIELDS: tuple[tuple[int, int, dict[str, int]], ...] = (
    (0, 59, {}),
    (0, 23, {}),
    (1, 31, {}),
    (
        1,
        12,
        {
            name: number
            for number, name in enumerate(
                (
                    "JAN",
                    "FEB",
                    "MAR",
                    "APR",
                    "MAY",
                    "JUN",
                    "JUL",
                    "AUG",
                    "SEP",
                    "OCT",
                    "NOV",
                    "DEC",
                ),
                start=1,
            )
        },
    ),
    (
        1,
        7,
        {
            name: number
            for number, name in enumerate(
                ("SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"), start=1
            )
        },
    ),
    (1970, 2199, {}),
)
_SCHEDULE_EXPRESSION = re.compile(r"^\s*(cron|rate|at)\((.*)\)\s*$")
_RATE = re.compile(r"^\s*(\d+)\s+(minute|minutes|hour|hours|day|days)\s*$")
_RATE_UNITS = {"minute": 60, "hour": 3600, "day": 86400}
_UNIVERSAL_TARGET = re.compile(r"^arn:aws[a-z-]*:scheduler:::aws-sdk:([a-z0-9-]+):([A-Za-z0-9]+)$")
# The only target input keys returned: they name the work a schedule starts. Every other
# key can carry job arguments.
_TARGET_INPUT_KEYS = (
    "JobName",
    "StateMachineArn",
    "FunctionName",
    "TaskDefinition",
    "Cluster",
    "JobQueue",
    "JobDefinition",
    "Name",
)


@dataclass(frozen=True)
class Cron:
    """A parsed EventBridge cron expression: the values each field allows."""

    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]
    years: frozenset[int]

    def matches(self, when: datetime) -> bool:
        return (
            when.minute in self.minutes
            and when.hour in self.hours
            and when.day in self.days
            and when.month in self.months
            and when.isoweekday() % 7 + 1 in self.weekdays
            and when.year in self.years
        )


def _cron_number(text: str, low: int, high: int, names: dict[str, int]) -> int:
    value = names.get(text.upper())
    if value is None:
        if not text.isdigit():
            raise ValueError(f"unsupported cron value {text!r}")
        value = int(text)
    if not low <= value <= high:
        raise ValueError(f"cron value {text!r} is out of range")
    return value


def _cron_field(text: str, low: int, high: int, names: dict[str, int]) -> frozenset[int]:
    values: set[int] = set()
    for item in text.split(","):
        base, _, step_text = item.partition("/")
        step = int(step_text) if step_text.isdigit() and int(step_text) > 0 else None
        if step_text and step is None:
            raise ValueError(f"unsupported cron step {item!r}")
        if base in ("*", "?"):
            first, last = low, high
        else:
            first_text, dash, last_text = base.partition("-")
            first = _cron_number(first_text, low, high, names)
            last = _cron_number(last_text, low, high, names) if dash else first
            if step is not None and not dash:
                last = high
        if last < first:
            raise ValueError(f"unsupported cron range {item!r}")
        values.update(range(first, last + 1, step or 1))
    return frozenset(values)


def parse_cron(body: str) -> Cron:
    """The six fields of ``cron(...)``. L, W and # (last, weekday and nth day) are not
    supported and raise ValueError, like any malformed field."""
    fields = body.split()
    if len(fields) != len(_CRON_FIELDS):
        raise ValueError("a cron expression has six fields")
    return Cron(
        *(
            _cron_field(text, low, high, names)
            for text, (low, high, names) in zip(fields, _CRON_FIELDS, strict=True)
        )
    )


def parse_rate(body: str) -> timedelta:
    match = _RATE.match(body)
    if match is None or int(match.group(1)) < 1:
        raise ValueError(f"unsupported rate {body!r}")
    return timedelta(seconds=int(match.group(1)) * _RATE_UNITS[match.group(2).rstrip("s")])


def cron_fire_times(cron: Cron, start: datetime, end: datetime, zone: ZoneInfo) -> list[datetime]:
    """Each minute in [start, end] at which ``cron`` fires, read on the clock of ``zone``."""
    minute = start.replace(second=0, microsecond=0)
    if minute < start:
        minute += timedelta(minutes=1)
    times = []
    while minute <= end:
        if cron.matches(minute.astimezone(zone)):
            times.append(minute)
        minute += timedelta(minutes=1)
    return times


def _rate_fire_times(
    period: timedelta, anchor: datetime, start: datetime, end: datetime
) -> list[datetime]:
    skipped = max(0, math.ceil((start - anchor) / period))
    times = []
    when = anchor + skipped * period
    while when <= end:
        times.append(when)
        when += period
    return times


def schedule_firing(
    expression: str,
    timezone: str,
    start: datetime,
    end: datetime,
    anchor: datetime | None = None,
) -> dict[str, Any]:
    """How a schedule expression fires inside [start, end]: ``fire_times``, or ``frequent``
    (a rate under an hour), ``fire_times_unknown`` (a rate without a known start) or
    ``unsupported`` instead of times."""
    match = _SCHEDULE_EXPRESSION.match(expression)
    try:
        zone = ZoneInfo(timezone)
        if match is None:
            raise ValueError(expression)
        kind, body = match.groups()
        if kind == "cron":
            return {"fire_times": cron_fire_times(parse_cron(body), start, end, zone)}
        if kind == "at":
            when = datetime.fromisoformat(body.strip()).replace(tzinfo=zone).astimezone(UTC)
            return {"fire_times": [when] if start <= when <= end else []}
        period = parse_rate(body)
    except (ValueError, ZoneInfoNotFoundError):
        return {"unsupported": True}
    if period < timedelta(hours=1):
        return {"frequent": True}
    if anchor is None:
        return {"fire_times_unknown": True}
    return {"fire_times": _rate_fire_times(period, _utc(anchor), start, end)}


def _target_input(raw: Any) -> dict[str, str] | None:
    try:
        data = json.loads(raw) if isinstance(raw, str) else None
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    kept = {
        key: redact(value)[:MAX_TARGET_INPUT_CHARS]
        for key in _TARGET_INPUT_KEYS
        if isinstance(value := data.get(key), str)
    }
    return kept or None


def _scheduler_target(target: dict[str, Any]) -> dict[str, Any]:
    """The target ARN; for a universal target, its service, action and whitelisted input."""
    arn = str(target.get("Arn") or "")
    universal = _UNIVERSAL_TARGET.match(arn)
    if universal is None:
        return {"arn": arn}
    return _compact(
        {
            "arn": arn,
            "service": universal.group(1),
            "action": universal.group(2),
            "input": _target_input(target.get("Input")),
        }
    )


@dataclass(frozen=True)
class _Schedule:
    view: dict[str, Any]
    first_fire: datetime | None
    event_bus: str | None = None


def _schedule(
    view: dict[str, Any], firing: dict[str, Any], event_bus: str | None = None
) -> _Schedule | None:
    """The schedule as returned, or None when it does not fire in the window. A disabled
    schedule is kept only when it would have fired."""
    times: list[datetime] | None = firing.get("fire_times")
    if times is None:
        enabled = str(view.get("state") or "").startswith("ENABLED")
        return _Schedule({**view, **firing}, None, event_bus) if enabled else None
    if not times:
        return None
    projected = {
        **view,
        "fire_times": [_utc_text(when) for when in times[:MAX_FIRE_TIMES]],
        "fire_count": len(times) if len(times) > MAX_FIRE_TIMES else None,
    }
    return _Schedule(_compact(projected), times[0], event_bus)


def _name_matches(name: Any, name_contains: str | None) -> bool:
    return isinstance(name, str) and (
        name_contains is None or name_contains.lower() in name.lower()
    )


def _paged(
    call: Callable[..., dict[str, Any]], key: str, pages: int
) -> tuple[list[dict[str, Any]], bool]:
    """Up to ``pages`` pages of ``key`` items, and whether more remained. ``call`` takes
    the NextToken keyword."""
    items: list[dict[str, Any]] = []
    token: dict[str, str] = {}
    for _ in range(pages):
        response = call(**token)
        items.extend(response.get(key, []))
        if not response.get("NextToken"):
            return items, False
        token = {"NextToken": response["NextToken"]}
    return items, True


def _rule_schedules(
    ctx: ToolContext, name_contains: str | None, start: datetime, end: datetime
) -> tuple[list[_Schedule], bool]:
    rules, more = _paged(
        lambda **token: ctx.events.list_rules(Limit=SCHEDULE_PAGE, **token),
        "Rules",
        MAX_SCHEDULE_PAGES,
    )
    schedules = []
    for rule in rules:
        expression = rule.get("ScheduleExpression")
        if not expression or not _name_matches(rule.get("Name"), name_contains):
            continue
        view = {
            "name": rule["Name"],
            "source": "rule",
            "expression": expression,
            "timezone": "UTC",
            "state": rule.get("State"),
        }
        firing = schedule_firing(expression, "UTC", start, end)
        if (schedule := _schedule(view, firing, rule.get("EventBusName"))) is not None:
            schedules.append(schedule)
    return schedules, more


def _scheduler_firing(
    schedule: dict[str, Any], timezone: str, start: datetime, end: datetime
) -> dict[str, Any]:
    """The schedule's firing inside the window, within its own start and end dates."""
    if schedule.get("StartDate"):
        start = max(start, _utc(schedule["StartDate"]))
    if schedule.get("EndDate"):
        end = min(end, _utc(schedule["EndDate"]))
    if end < start:
        return {"fire_times": []}
    anchor = schedule.get("StartDate") or schedule.get("CreationDate")
    return schedule_firing(
        str(schedule.get("ScheduleExpression") or ""), timezone, start, end, anchor
    )


def _scheduler_schedules(
    ctx: ToolContext, name_contains: str | None, start: datetime, end: datetime
) -> tuple[list[_Schedule], bool]:
    summaries, more = _paged(
        lambda **token: ctx.scheduler.list_schedules(MaxResults=SCHEDULE_PAGE, **token),
        "Schedules",
        MAX_SCHEDULE_PAGES,
    )
    candidates = [
        summary for summary in summaries if _name_matches(summary.get("Name"), name_contains)
    ]
    schedules = []
    for summary in candidates[:MAX_SCHEDULER_LOOKUPS]:
        lookup = {"Name": summary["Name"]}
        if summary.get("GroupName"):
            lookup["GroupName"] = summary["GroupName"]
        detail = ctx.scheduler.get_schedule(**lookup)
        timezone = str(detail.get("ScheduleExpressionTimezone") or "UTC")
        view = {
            "name": summary["Name"],
            "source": "scheduler",
            "expression": detail.get("ScheduleExpression"),
            "timezone": timezone,
            "state": detail.get("State"),
            "target": _scheduler_target(detail.get("Target") or {}),
        }
        firing = _scheduler_firing(detail, timezone, start, end)
        if (schedule := _schedule(view, firing)) is not None:
            schedules.append(schedule)
    return schedules, more or len(candidates) > MAX_SCHEDULER_LOOKUPS


def _rule_target_arns(ctx: ToolContext, schedule: _Schedule) -> list[str]:
    """The rule's target ARNs only: a target's Input and InputTransformer can carry
    arguments."""
    lookup = {"Rule": schedule.view["name"]}
    if schedule.event_bus:
        lookup["EventBusName"] = schedule.event_bus
    targets = ctx.events.list_targets_by_rule(**lookup).get("Targets", [])
    return [str(target["Arn"]) for target in targets[:MAX_RULE_TARGETS] if target.get("Arn")]


def scheduled_jobs(params: ScheduledJobsInput, ctx: ToolContext) -> dict[str, Any]:
    """Schedules firing in the window. A source that fails is reported in ``errors`` and
    the other still returns."""
    start, end = time_window(
        params.start,
        params.end,
        timedelta(hours=params.hours),
        timedelta(hours=MAX_SCHEDULE_HOURS),
        ctx.alarm_time,
    )
    errors: dict[str, str] = {}
    truncated: list[str] = []
    schedules: list[_Schedule] = []
    sources: dict[str, Callable[..., tuple[list[_Schedule], bool]]] = {
        "rules": _rule_schedules,
        "scheduler": _scheduler_schedules,
    }
    for source, fetch in sources.items():
        try:
            found, more = fetch(ctx, params.name_contains, start, end)
        except ClientError as exc:
            errors[source] = _error_code(exc)
            continue
        schedules.extend(found)
        if more:
            truncated.append(source)
    if sources.keys() <= errors.keys():
        raise ToolError("; ".join(f"{source}: {code}" for source, code in errors.items()))
    schedules.sort(
        key=lambda item: (item.first_fire is None, item.first_fire or end, item.view["name"])
    )
    if len(schedules) > MAX_SCHEDULES:
        truncated.append("schedules")
    shown = []
    for schedule in schedules[:MAX_SCHEDULES]:
        view = schedule.view
        if view["source"] == "rule" and "rule_targets" not in errors:
            try:
                view = {**view, "target_arns": _rule_target_arns(ctx, schedule)}
            except ClientError as exc:
                errors["rule_targets"] = _error_code(exc)
        shown.append(view)
    result: dict[str, Any] = {
        "window": window_view(start, end),
        "name_contains": params.name_contains,
        "schedules": shown,
        "truncated": truncated,
    }
    if errors:
        result["errors"] = errors
    return _compact(result)


def datadog_logs_query(params: DatadogLogsInput) -> str:
    """The Datadog query for the input: one service, or every service whose name contains
    name as a wildcard; the status default is errors and warnings."""
    terms = []
    if params.service is not None:
        terms.append(f"service:{params.service}")
    elif params.name is not None:
        terms.append(f"service:*{params.name.lower()}*")
    if params.env is not None:
        terms.append(f"env:{params.env}")
    terms.append(f"status:{params.status}" if params.status else "status:(error OR warn)")
    if params.text is not None:
        terms.append(params.text)
    return " ".join(terms)


def _tag_value(tags: list[Any], name: str) -> str | None:
    prefix = f"{name}:"
    for tag in tags:
        if isinstance(tag, str) and tag.startswith(prefix):
            return tag[len(prefix) :]
    return None


def _log_origin(attributes: dict[str, Any]) -> str | None:
    """The kube pod or ECS task id from the tags when present, else the host."""
    tags = attributes.get("tags") or []
    task_arn = _tag_value(tags, "task_arn")
    origin = (
        _tag_value(tags, "pod_name")
        or (task_arn.rsplit("/", 1)[-1] if task_arn else None)
        or attributes.get("host")
    )
    return None if origin is None else str(origin)[:MAX_DATADOG_HOST_CHARS]


def _project_datadog_log(event: dict[str, Any]) -> dict[str, Any]:
    attributes = event.get("attributes") or {}
    return _compact(
        {
            "timestamp": attributes.get("timestamp"),
            "service": attributes.get("service"),
            "status": attributes.get("status"),
            "host": _log_origin(attributes),
            # Redacted before the cut: a secret split at the limit is no longer recognizable.
            "message": redact(str(attributes.get("message") or ""))[:MAX_LOG_FIELD_CHARS],
        }
    )


def _bucket_count(bucket: dict[str, Any]) -> int:
    value = (bucket.get("computes") or {}).get("c0")
    return int(value) if isinstance(value, int | float) else 0


def _datadog_services(
    query: str, start: datetime, end: datetime, ctx: ToolContext
) -> dict[str, Any]:
    """The services with the most error and warn logs matching the query, most errors
    first."""
    # One more service than is returned, so a full page shows as truncated.
    body = {
        "filter": {"query": query, "from": start.isoformat(), "to": end.isoformat()},
        "compute": [{"aggregation": "count", "type": "total"}],
        "group_by": [
            {
                "facet": "service",
                "limit": MAX_DATADOG_SERVICES + 1,
                "sort": {"aggregation": "count", "order": "desc", "type": "measure"},
            },
            {"facet": "status", "limit": 5},
        ],
    }
    try:
        response = ctx.datadog.aggregate_logs(body=body)
    except DatadogError as exc:
        raise ToolError(str(exc)) from None
    counts: dict[str, Counter[str]] = {}
    for bucket in (response.get("data") or {}).get("buckets") or []:
        if not isinstance(bucket, dict):
            continue
        by = bucket.get("by") or {}
        service = by.get("service")
        if not isinstance(service, str) or not service:
            continue
        statuses = counts.setdefault(service, Counter())
        if by.get("status") in ("error", "warn"):
            statuses[by["status"]] += _bucket_count(bucket)
    ranked = sorted(counts.items(), key=lambda item: (-item[1]["error"], -item[1]["warn"], item[0]))
    rows = [
        {"service": service, "error": statuses["error"], "warn": statuses["warn"]}
        for service, statuses in ranked
    ]
    after = (response.get("meta") or {}).get("page", {}).get("after")
    services = rows[:MAX_DATADOG_SERVICES]
    return {
        "query": query,
        "window": window_view(start, end),
        "count": len(services),
        "truncated": bool(after) or len(rows) > MAX_DATADOG_SERVICES,
        "services": services,
    }


def search_datadog_logs(params: DatadogLogsInput, ctx: ToolContext) -> dict[str, Any]:
    start, end = time_window(
        params.start,
        params.end,
        timedelta(minutes=params.minutes),
        timedelta(minutes=MAX_DATADOG_LOG_MINUTES),
        ctx.alarm_time,
    )
    query = datadog_logs_query(params)
    if params.service is None:
        return _datadog_services(query, start, end, ctx)
    body = {
        "filter": {"query": query, "from": start.isoformat(), "to": end.isoformat()},
        "sort": "-timestamp",
        "page": {"limit": params.limit},
    }
    try:
        response = ctx.datadog.search_logs(body=body)
    except DatadogError as exc:
        raise ToolError(str(exc)) from None
    events = [event for event in response.get("data") or [] if isinstance(event, dict)]
    after = (response.get("meta") or {}).get("page", {}).get("after")
    logs = [_project_datadog_log(event) for event in events[: params.limit]]
    return {
        "query": query,
        "window": window_view(start, end),
        "count": len(logs),
        "truncated": bool(after) or len(events) > params.limit,
        "logs": logs,
    }


def datadog_events_query(params: DatadogEventsInput) -> str:
    """The Datadog events query for the input: one source and one service or namespace."""
    terms = [f"source:{params.source}"]
    if params.service is not None:
        terms.append(f"service:{params.service}")
    if params.kube_namespace is not None:
        terms.append(f"kube_namespace:{params.kube_namespace}")
    if params.env is not None:
        terms.append(f"env:{params.env}")
    return " ".join(terms)


def _kept_tags(tags: Any, names: tuple[str, ...]) -> list[str] | None:
    """The tags with one of the names, or None when there are none."""
    if not isinstance(tags, list):
        return None
    prefixes = tuple(f"{name}:" for name in names)
    kept = [
        tag[:MAX_DATADOG_HOST_CHARS]
        for tag in tags
        if isinstance(tag, str) and tag.startswith(prefixes)
    ]
    return kept or None


def _project_datadog_event(event: dict[str, Any]) -> dict[str, Any]:
    attributes = event.get("attributes") or {}
    inner = attributes.get("attributes") or {}
    title = attributes.get("title") or inner.get("title")
    message = str(attributes.get("message") or "").replace("%%%", "").strip()
    return _compact(
        {
            "timestamp": attributes.get("timestamp"),
            "title": None if title is None else redact(str(title))[:MAX_REASON_CHARS],
            "tags": _kept_tags(attributes.get("tags"), DATADOG_EVENT_TAGS),
            # Redacted before the cut: a secret split at the limit is no longer recognizable.
            "message": redact(message)[:MAX_DATADOG_EVENT_CHARS],
        }
    )


def datadog_events(params: DatadogEventsInput, ctx: ToolContext) -> dict[str, Any]:
    start, end = time_window(
        params.start,
        params.end,
        timedelta(minutes=params.minutes),
        timedelta(minutes=MAX_DATADOG_EVENT_MINUTES),
        ctx.alarm_time,
    )
    query = datadog_events_query(params)
    body = {
        "filter": {"query": query, "from": start.isoformat(), "to": end.isoformat()},
        "sort": "-timestamp",
        "page": {"limit": params.limit},
    }
    try:
        response = ctx.datadog.search_events(body=body)
    except DatadogError as exc:
        raise ToolError(str(exc)) from None
    events = [event for event in response.get("data") or [] if isinstance(event, dict)]
    after = (response.get("meta") or {}).get("page", {}).get("after")
    projected = [_project_datadog_event(event) for event in events[: params.limit]]
    return {
        "query": query,
        "window": window_view(start, end),
        "count": len(projected),
        "truncated": bool(after) or len(events) > params.limit,
        "events": projected,
    }


@dataclass(frozen=True)
class _PodMetric:
    """A Kubernetes metric and how its raw values convert to the unit reported."""

    name: str
    divisor: float
    unit: str
    digits: int


# Raw values are nanocores and bytes.
_POD_METRICS: dict[str, _PodMetric] = {
    "cpu": _PodMetric("kubernetes.cpu.usage.total", 1e9, "cores", 3),
    "memory": _PodMetric("kubernetes.memory.usage", 1024 * 1024, "MiB", 1),
}


def datadog_top_pods_query(params: DatadogTopPodsInput) -> str:
    """The metrics query for the input: one node or cluster, summed per pod."""
    scope = [f"host:{params.host}" if params.host else f"kube_cluster_name:{params.cluster}"]
    if params.kube_namespace is not None:
        scope.append(f"kube_namespace:{params.kube_namespace}")
    metric = _POD_METRICS[params.metric].name
    return f"sum:{metric}{{{','.join(scope)}}} by {{kube_namespace,pod_name}}"


def _series_points(series: dict[str, Any]) -> list[tuple[float, float]]:
    """The (epoch ms, value) points that hold a number."""
    return [
        (float(point[0]), float(point[1]))
        for point in series.get("pointlist") or []
        if isinstance(point, list | tuple)
        and len(point) == 2
        and isinstance(point[0], int | float)
        and isinstance(point[1], int | float)
    ]


def _project_pod(
    series: dict[str, Any], points: list[tuple[float, float]], metric: _PodMetric, before_end: float
) -> dict[str, Any]:
    tag_set = series.get("tag_set")
    tags = tag_set if isinstance(tag_set, list) else []
    values = [value / metric.divisor for _, value in points]
    peak = max(range(len(values)), key=values.__getitem__)
    early = [value / metric.divisor for at, value in points if at < before_end]
    namespace = _tag_value(tags, "kube_namespace")
    pod = _tag_value(tags, "pod_name")
    return _compact(
        {
            "kube_namespace": None
            if namespace is None
            else redact(namespace)[:MAX_DATADOG_HOST_CHARS],
            "pod_name": None if pod is None else redact(pod)[:MAX_DATADOG_HOST_CHARS],
            "max": round(values[peak], metric.digits),
            "max_at": _utc_text(datetime.fromtimestamp(points[peak][0] / 1000, UTC)),
            "avg": round(sum(values) / len(values), metric.digits),
            "last": round(values[-1], metric.digits),
            "before": round(sum(early) / len(early), metric.digits) if early else None,
        }
    )


def datadog_top_pods(params: DatadogTopPodsInput, ctx: ToolContext) -> dict[str, Any]:
    start, end = time_window(
        params.start,
        params.end,
        timedelta(minutes=params.minutes),
        timedelta(minutes=MAX_TOP_POD_MINUTES),
        ctx.alarm_time,
    )
    query = datadog_top_pods_query(params)
    request = {
        "from": str(int(start.timestamp())),
        "to": str(int(end.timestamp())),
        "query": query,
    }
    try:
        response = ctx.datadog.query_metrics(params=request)
    except DatadogError as exc:
        raise ToolError(str(exc)) from None
    if response.get("status") == "error":
        error = redact(str(response.get("error") or "no detail"))[:MAX_REASON_CHARS]
        raise ToolError(f"Datadog metrics query failed: {error}")
    metric = _POD_METRICS[params.metric]
    # The first quarter of the window, before most alarms' rise.
    before_end = (start + (end - start) / 4).timestamp() * 1000
    pods = [
        _project_pod(series, points, metric, before_end)
        for series in response.get("series") or []
        if isinstance(series, dict) and (points := _series_points(series))
    ]
    pods.sort(key=itemgetter("max"), reverse=True)
    return {
        "query": query,
        "window": window_view(start, end),
        "metric": params.metric,
        "unit": metric.unit,
        "count": min(len(pods), MAX_TOP_PODS),
        "truncated": len(pods) > MAX_TOP_PODS,
        "pods": pods[:MAX_TOP_PODS],
    }


def _github_text(value: Any, limit: int) -> str:
    # Redacted before the cut: a secret split at the limit is no longer recognizable.
    return redact(str(value or ""))[:limit]


def _login(user: Any) -> str | None:
    login = user.get("login") if isinstance(user, dict) else None
    return login if isinstance(login, str) else None


def _project_repo(repo: dict[str, Any]) -> dict[str, Any]:
    description = repo.get("description")
    return _compact(
        {
            "name": repo.get("name"),
            "description": (
                _github_text(description, MAX_GITHUB_DESCRIPTION_CHARS) if description else None
            ),
            "default_branch": repo.get("default_branch"),
            "archived": repo.get("archived"),
            "pushed_at": repo.get("pushed_at"),
            "language": repo.get("language"),
        }
    )


def github_list_repos(params: GitHubListReposInput, ctx: ToolContext) -> dict[str, Any]:
    try:
        listed = _rows(ctx.github.list_org_repos())
    except GitHubError as exc:
        raise ToolError(str(exc)) from None
    repos = [repo for repo in listed if repo.get("name")]
    if params.name is not None:
        needle = params.name.lower()
        repos = [repo for repo in repos if needle in str(repo["name"]).lower()]
    if params.sort == "name":
        repos.sort(key=lambda repo: str(repo["name"]).lower())
    else:
        repos.sort(key=lambda repo: str(repo.get("pushed_at") or ""), reverse=True)
    return {
        "org": ctx.github.org,
        "count": min(len(repos), params.limit),
        "truncated": len(repos) > params.limit or len(listed) >= REPO_LISTING_LIMIT,
        "repos": [_project_repo(repo) for repo in repos[: params.limit]],
    }


def github_code_query(params: GitHubSearchCodeInput, org: str) -> str:
    """The code search query: the input words, then the org, repo and path qualifiers."""
    terms = [params.query, f"org:{org}"]
    if params.repo is not None:
        terms.append(f"repo:{org}/{params.repo}")
    if params.path is not None:
        terms.append(f"path:{params.path}")
    return " ".join(terms)


def _project_code_match(item: dict[str, Any]) -> dict[str, Any]:
    repository = item.get("repository") or {}
    matches = [match for match in item.get("text_matches") or [] if isinstance(match, dict)]
    fragments = [
        _github_text(match.get("fragment"), MAX_GITHUB_FRAGMENT_CHARS)
        for match in matches[:MAX_GITHUB_FRAGMENTS]
    ]
    return _compact(
        {
            "repo": repository.get("name") if isinstance(repository, dict) else None,
            "path": item.get("path"),
            "fragments": fragments or None,
        }
    )


def github_search_code(params: GitHubSearchCodeInput, ctx: ToolContext) -> dict[str, Any]:
    query = github_code_query(params, ctx.github.org)
    try:
        response = ctx.github.search_code(params={"q": query, "per_page": str(params.limit)})
    except GitHubError as exc:
        raise ToolError(str(exc)) from None
    items = [item for item in response.get("items") or [] if isinstance(item, dict)]
    total = response.get("total_count")
    total = total if isinstance(total, int) else len(items)
    results = [_project_code_match(item) for item in items[: params.limit]]
    return {
        "query": query,
        "total": total,
        "count": len(results),
        "truncated": total > len(results) or bool(response.get("incomplete_results")),
        "results": results,
    }


def _file_text(response: Any, path: str) -> tuple[str, int]:
    """The decoded text of a contents response and its size, or a ToolError."""
    if isinstance(response, list):
        raise ToolError(f"{path} is a directory; give a file path")
    if not isinstance(response, dict) or response.get("type") != "file":
        raise ToolError(f"{path} is not a file")
    size = response.get("size")
    size = size if isinstance(size, int) else 0
    if size > MAX_GITHUB_FILE_BYTES:
        raise ToolError(f"{path} is {size} bytes; files over 200 KB are not read")
    if response.get("encoding") != "base64":
        raise ToolError(f"{path} has no readable content")
    try:
        data = base64.b64decode(str(response.get("content") or ""))
    except ValueError:
        raise ToolError(f"{path} has no readable content") from None
    if b"\x00" in data:
        raise ToolError(f"{path} is a binary file")
    return data.decode("utf-8", errors="replace"), size


def github_get_file(params: GitHubFileInput, ctx: ToolContext) -> dict[str, Any]:
    try:
        response = ctx.github.get_contents(repo=params.repo, path=params.path, ref=params.ref)
    except GitHubError as exc:
        raise ToolError(str(exc)) from None
    text, size = _file_text(response, params.path)
    lines = text.splitlines()
    if params.line is None:
        first, last = 1, min(len(lines), GITHUB_FIRST_LINES)
    elif params.line > len(lines):
        raise ToolError(f"{params.path} has {len(lines)} lines; line {params.line} is past the end")
    else:
        first = max(1, params.line - params.context)
        last = min(len(lines), params.line + params.context)
    return _compact(
        {
            "repo": params.repo,
            "path": params.path,
            "ref": params.ref,
            "size": size,
            "total_lines": len(lines),
            "from_line": first,
            "to_line": last,
            "lines": [
                f"{number}: {_github_text(lines[number - 1], MAX_GITHUB_LINE_CHARS)}"
                for number in range(first, last + 1)
            ],
        }
    )


def _github_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _first_line(message: Any) -> str:
    lines = str(message or "").splitlines()
    return _github_text(lines[0] if lines else "", MAX_GITHUB_TITLE_CHARS)


def _project_commit(commit: dict[str, Any]) -> dict[str, Any]:
    inner = commit.get("commit") or {}
    dates = [inner.get(role) or {} for role in ("committer", "author")]
    return _compact(
        {
            "sha7": str(commit.get("sha") or "")[:7] or None,
            "date": next((date.get("date") for date in dates if date.get("date")), None),
            "author": _login(commit.get("author")),
            "message": _first_line(inner.get("message")),
        }
    )


def _project_merged_pull(pull: dict[str, Any]) -> dict[str, Any]:
    return _compact(
        {
            "number": pull.get("number"),
            "title": _github_text(pull.get("title"), MAX_GITHUB_TITLE_CHARS),
            "merged_at": pull.get("merged_at"),
            "base": (pull.get("base") or {}).get("ref"),
            "author": _login(pull.get("user")),
        }
    )


def _project_run(run: dict[str, Any]) -> dict[str, Any]:
    return _compact(
        {
            "name": _github_text(run.get("name"), MAX_GITHUB_TITLE_CHARS),
            "event": run.get("event"),
            "head_branch": run.get("head_branch"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "created_at": run.get("created_at"),
            "run_number": run.get("run_number"),
        }
    )


def _rows(raw: Any) -> list[dict[str, Any]]:
    return [row for row in raw if isinstance(row, dict)] if isinstance(raw, list) else []


def github_recent_changes(params: GitHubChangesInput, ctx: ToolContext) -> dict[str, Any]:
    """Commits, merged pull requests and Actions runs in the window; a failed request is
    reported in ``errors`` and the others still return."""
    start, end = time_window(
        params.start,
        params.end,
        timedelta(hours=params.hours),
        timedelta(hours=MAX_GITHUB_HOURS),
        ctx.alarm_time,
    )
    since, until = _github_time(start), _github_time(end)
    commit_params = {"since": since, "until": until, "per_page": str(params.limit + 1)}
    if params.path is not None:
        commit_params["path"] = params.path
    pull_params = {
        "state": "closed",
        "sort": "updated",
        "direction": "desc",
        "per_page": str(GITHUB_PULLS_PAGE),
    }
    run_params = {"created": f"{since}..{until}", "per_page": str(GITHUB_RUNS_PAGE)}

    def merged_in_window(pull: dict[str, Any]) -> bool:
        merged = _parse_time(pull.get("merged_at")) if pull.get("merged_at") else None
        return merged is not None and start <= merged <= end

    sections: dict[str, tuple[Callable[[], list[dict[str, Any]]], Callable[..., Any]]] = {
        "commits": (
            lambda: _rows(ctx.github.list_commits(repo=params.repo, params=commit_params)),
            _project_commit,
        ),
        "merged_pulls": (
            lambda: [
                pull
                for pull in _rows(ctx.github.list_pulls(repo=params.repo, params=pull_params))
                if merged_in_window(pull)
            ],
            _project_merged_pull,
        ),
        "workflow_runs": (
            lambda: _rows(
                ctx.github.list_workflow_runs(repo=params.repo, params=run_params).get(
                    "workflow_runs"
                )
            ),
            _project_run,
        ),
    }
    result: dict[str, Any] = {
        "repo": params.repo,
        "path": params.path,
        "window": window_view(start, end),
    }
    errors: dict[str, str] = {}
    truncated: list[str] = []
    for name, (fetch, project) in sections.items():
        try:
            rows = fetch()
        except GitHubError as exc:
            errors[name] = str(exc)
            continue
        result[name] = [project(row) for row in rows[: params.limit]]
        if len(rows) > params.limit:
            truncated.append(name)
    if len(errors) == len(sections):
        raise ToolError("; ".join(errors.values()))
    result["truncated"] = truncated
    if errors:
        result["errors"] = errors
    return _compact(result)


def _project_changed_files(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Up to 30 files; patches stop once their total would pass the budget."""
    projected = []
    budget = MAX_GITHUB_PATCHES_CHARS
    for changed in files[:MAX_GITHUB_FILES]:
        patch = changed.get("patch")
        text = _github_text(patch, MAX_GITHUB_PATCH_CHARS) if patch else None
        if text is not None and len(text) > budget:
            text, omitted = None, True
        else:
            omitted = None
        budget -= len(text or "")
        projected.append(
            _compact(
                {
                    "filename": changed.get("filename"),
                    "status": changed.get("status"),
                    "additions": changed.get("additions"),
                    "deletions": changed.get("deletions"),
                    "patch": text,
                    "patch_omitted": omitted,
                }
            )
        )
    return projected


def _github_commit(params: GitHubChangeInput, ctx: ToolContext) -> dict[str, Any]:
    try:
        commit = ctx.github.get_commit(repo=params.repo, sha=params.sha)
    except GitHubError as exc:
        raise ToolError(str(exc)) from None
    files = _rows(commit.get("files"))
    summary = _project_commit(commit)
    message = (commit.get("commit") or {}).get("message")
    return _compact(
        {
            "repo": params.repo,
            **summary,
            "message": _github_text(message, MAX_GITHUB_COMMIT_MESSAGE_CHARS),
            "files": _project_changed_files(files),
            "truncated": len(files) > MAX_GITHUB_FILES,
        }
    )


def _github_pull_request(params: GitHubChangeInput, ctx: ToolContext) -> dict[str, Any]:
    try:
        pull = ctx.github.get_pull(repo=params.repo, number=params.number)
        files = _rows(
            ctx.github.list_pull_files(
                repo=params.repo,
                number=params.number,
                params={"per_page": str(MAX_GITHUB_FILES)},
            )
        )
    except GitHubError as exc:
        raise ToolError(str(exc)) from None
    changed_files = pull.get("changed_files")
    changed = changed_files if isinstance(changed_files, int) else len(files)
    return _compact(
        {
            "repo": params.repo,
            "number": pull.get("number", params.number),
            "title": _github_text(pull.get("title"), MAX_GITHUB_TITLE_CHARS),
            "body": _github_text(pull.get("body"), MAX_GITHUB_BODY_CHARS),
            "state": pull.get("state"),
            "merged_at": pull.get("merged_at"),
            "base": (pull.get("base") or {}).get("ref"),
            "head": (pull.get("head") or {}).get("ref"),
            "author": _login(pull.get("user")),
            "changed_files": changed,
            "files": _project_changed_files(files),
            "truncated": changed > MAX_GITHUB_FILES or len(files) > MAX_GITHUB_FILES,
        }
    )


def github_get_change(params: GitHubChangeInput, ctx: ToolContext) -> dict[str, Any]:
    if params.number is not None:
        return _github_pull_request(params, ctx)
    return _github_commit(params, ctx)


def _github_change_descriptor(values: dict[str, Any]) -> ToolCallDescriptor:
    repo = _subject_text(values.get("repo"))
    number = _subject_text(values.get("number"))
    if number is not None:
        return call_descriptor("github", "pulls", "get", f"{repo}#{number}" if repo else None)
    sha = _subject_text(values.get("sha"))
    return call_descriptor("github", "commits", "get", f"{repo}@{sha}" if repo and sha else None)


@lru_cache(maxsize=1)
def botocore_session() -> botocore.session.Session:
    """The one botocore session: the catalog, validation and every aws_call client share
    it."""
    return botocore.session.get_session()


@lru_cache(maxsize=1)
def aws_services() -> tuple[str, ...]:
    """Every service name botocore bundles a model for."""
    return tuple(botocore_session().get_available_services())


@lru_cache(maxsize=1)
def covered_services() -> tuple[str, ...]:
    """The bundled services aws_call covers, sorted."""
    return tuple(sorted(aws_guard.ALLOWED_SERVICES.intersection(aws_services())))


def _listed(label: str, names: list[str]) -> str:
    return f"; {label}: {', '.join(names)}" if names else ""


def _close_matches(name: str, choices: tuple[str, ...] | list[str]) -> str:
    return _listed(
        "close matches", difflib.get_close_matches(name, choices, n=MAX_AWS_CLOSE_MATCHES)
    )


def _covered_model(service: str, operation: str | None = None) -> ServiceModel:
    """The model of a covered service; an unknown or uncovered service is a ToolError,
    naming the closest covered services and, given the operation, the closest operations
    across them."""
    if service not in aws_services():
        closest = _closest_operations(operation) if operation else []
        raise ToolError(
            f"unknown service {service!r}{_close_matches(service, covered_services())}"
            f"{_listed('closest operations', closest)}"
        )
    if service not in aws_guard.ALLOWED_SERVICES:
        raise ToolError(f"blocked: {aws_guard.NOT_COVERED}")
    model: ServiceModel = botocore_session().get_service_model(service)
    return model


def _operation_name(model: ServiceModel, operation: str) -> str:
    """The model's PascalCase name for a snake_case or PascalCase operation."""
    if operation in model.operation_names:
        return operation
    by_snake: dict[str, str] = {xform_name(name): name for name in model.operation_names}
    if operation in by_snake:
        return by_snake[operation]
    closest = _closest_operations(operation, model.service_name)
    raise ToolError(
        f"unknown operation {operation!r} for {model.service_name}"
        f"{_listed('closest operations', closest)}"
    )


def _refusal(model: ServiceModel, operation: str) -> str | None:
    """The guard's reason for refusing one operation of a covered service, or None."""
    shape = model.operation_model(operation)
    returns_body = bool(shape.has_streaming_output or shape.has_event_stream_output)
    return aws_guard.check(model.service_name, operation, returns_body)


def _call_label(service: str, operation: str) -> str:
    return f"aws.{service}.{xform_name(operation)}"


@dataclass(frozen=True)
class _CatalogOperation:
    service: str
    operation: str
    words: frozenset[str]


def _doc_text(documentation: str) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", documentation)).split())


def _words(text: str) -> frozenset[str]:
    """Lowercase words, a plural s dropped, so 'versions' matches 'version'."""
    return frozenset(
        word[:-1] if len(word) > 3 and word.endswith("s") else word
        for word in re.findall(r"[a-z0-9]+", text.lower())
    )


@lru_cache(maxsize=1)
def _catalog() -> tuple[_CatalogOperation, ...]:
    """Every operation of the covered services with the words of its documentation, from
    botocore's model files.

    Each file is read and dropped in turn: the session caches every model it loads, and
    all of them together would weigh on the Lambda's memory.
    """
    loader = botocore_session().get_component("data_loader")
    files = JSONFileLoader()
    operations: list[_CatalogOperation] = []
    for service in covered_services():
        version = loader.determine_latest_version(service, "service-2")
        paths = (os.path.join(root, service, version, "service-2") for root in loader.search_paths)
        path = next((path for path in paths if files.exists(path)), None)
        spec = files.load_file(path) if path else None
        for operation, body in ((spec or {}).get("operations") or {}).items():
            text = _doc_text(body.get("documentation") or "")
            operations.append(
                _CatalogOperation(service, operation, _words(text[:AWS_DOC_WORD_CHARS]))
            )
    return tuple(operations)


def _score(entry: _CatalogOperation, query: frozenset[str]) -> int:
    service = _words(entry.service.replace("-", " ")) | {entry.service}
    operation = _words(xform_name(entry.operation).replace("_", " "))
    return 3 * len(query & service) + 2 * len(query & operation) + len(query & entry.words)


def _closest_operations(operation: str, service: str | None = None) -> list[str]:
    """Up to 5 operations aws_call allows named like ``operation``, in one service or, as
    service.operation, across the covered ones: the closest spellings alternating with
    the operations sharing the most words with it."""

    def label(entry: _CatalogOperation) -> str:
        name = xform_name(entry.operation)
        return name if service else f"{entry.service}.{name}"

    snake = xform_name(operation)
    entries = [
        entry
        for entry in _catalog()
        if service in (None, entry.service)
        and aws_guard.check(entry.service, entry.operation) is None
    ]
    by_name: dict[str, list[str]] = {}
    for entry in entries:
        by_name.setdefault(xform_name(entry.operation), []).append(label(entry))
    spelled = [
        name
        for match in difflib.get_close_matches(snake, list(by_name), n=MAX_AWS_CLOSE_MATCHES)
        for name in by_name[match]
    ]
    query = _words(snake.replace("_", " "))
    scored = [(score, entry) for entry in entries if (score := _score(entry, query)) > 0]
    scored.sort(key=itemgetter(0), reverse=True)
    worded = [label(entry) for _, entry in scored]
    ranked = [name for pair in zip_longest(spelled, worded) for name in pair if name]
    return list(dict.fromkeys(ranked))[:MAX_AWS_CLOSE_MATCHES]


def _check_page_tokens(request: dict[str, Any]) -> None:
    for key, value in request.items():
        if not re.search(r"(?i)token|marker|startkey", key):
            continue
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        if len(text.encode()) > MAX_AWS_PAGE_TOKEN_BYTES:
            raise ToolError(f"{key} is over {MAX_AWS_PAGE_TOKEN_BYTES} bytes")


def _page_tokens(service: str, operation: str) -> list[tuple[str, str]]:
    """(request parameter, response key) pairs that carry the next page, when known."""
    try:
        paginator = botocore_session().get_paginator_model(service).get_paginator(operation)
    except (DataNotFoundError, ValueError):
        return [("NextToken", "NextToken"), ("nextToken", "nextToken")]
    inputs = paginator["input_token"]
    outputs = paginator["output_token"]
    inputs = inputs if isinstance(inputs, list) else [inputs]
    outputs = outputs if isinstance(outputs, list) else [outputs]
    return [
        (request_key, response_key.split("||")[0].strip())
        for request_key, response_key in zip(inputs, outputs, strict=False)
    ]


def _sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in SENSITIVE_KEYS or any(part in lowered for part in SENSITIVE_KEY_PARTS)


def _embedded_document(key: str, value: Any) -> bool:
    """A long string holding a JSON object or array under a definition-like key."""
    if key.lower() not in EMBEDDED_DOCUMENT_KEYS:
        return False
    if not isinstance(value, str) or len(value) <= MIN_EMBEDDED_DOCUMENT_CHARS:
        return False
    try:
        return isinstance(json.loads(value), dict | list)
    except ValueError:
        return False


def _aws_entry(key: str, value: Any) -> Any:
    if _sensitive_key(key):
        return REMOVED
    if _embedded_document(key, value):
        return REMOVED_DOCUMENT
    return _aws_value(value)


def _aws_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _aws_entry(str(key), item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_aws_value(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes | bytearray):
        return f"<bytes {len(value)}>"
    if isinstance(value, str):
        return redact(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, StreamingBody):
        value.close()
        return "<stream>"
    return f"<{type(value).__name__}>"


_ValuePath = tuple[str | int, ...]


def _lists(value: Any, path: _ValuePath = ()) -> Iterator[tuple[_ValuePath, list[Any]]]:
    """Every non-empty list in a value, with its path."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _lists(item, (*path, key))
    elif isinstance(value, list):
        if value:
            yield path, value
        for index, item in enumerate(value):
            yield from _lists(item, (*path, index))


def _has_long_string(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_has_long_string(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_long_string(item) for item in value)
    return isinstance(value, str) and len(value) > MAX_AWS_STRING_CHARS


def _cut_strings(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _cut_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_cut_strings(item) for item in value]
    return value[:MAX_AWS_STRING_CHARS] if isinstance(value, str) else value


def _replaced(value: Any, path: _ValuePath, items: list[Any]) -> Any:
    if not path:
        return items
    head, rest = path[0], path[1:]
    if isinstance(value, dict):
        return {
            key: _replaced(item, rest, items) if key == head else item
            for key, item in value.items()
        }
    return [
        _replaced(item, rest, items) if index == head else item for index, item in enumerate(value)
    ]


def _size(content: dict[str, Any]) -> int:
    return len(json.dumps(content, default=str))


def _largest(lists: list[tuple[_ValuePath, list[Any]]]) -> tuple[_ValuePath, list[Any]]:
    return max(lists, key=lambda found: len(json.dumps(found[1], default=str)))


def _items_that_fit(content: dict[str, Any], path: _ValuePath, items: list[Any]) -> int:
    """How many leading items of the list at path fit the cap, at least one."""
    low, high = 1, len(items) - 1
    while low < high:
        middle = (low + high + 1) // 2
        trial = {**content, "result": _replaced(content["result"], path, items[:middle])}
        if _size(trial) <= MAX_AWS_RESULT_CHARS:
            low = middle
        else:
            high = middle - 1
    return low


def _fit_aws_result(content: dict[str, Any]) -> dict[str, Any]:
    """The content within MAX_AWS_RESULT_CHARS, ``truncated`` and ``items_total`` included.

    The largest list with more than one item is cut to the leading items that fit (at
    least one), then the next, descending into a lone item too large on its own; then
    long strings are cut to MAX_AWS_STRING_CHARS; then single-item lists are emptied,
    largest first. A result still too large becomes cut JSON text.
    """
    if _size(content) <= MAX_AWS_RESULT_CHARS:
        return content
    content = {**content, "truncated": True, "items_total": {}}
    while _size(content) > MAX_AWS_RESULT_CHARS:
        result = content["result"]
        lists = list(_lists(result))
        several = [found for found in lists if len(found[1]) > 1]
        if not several and _has_long_string(result):
            content = {**content, "result": _cut_strings(result)}
            continue
        if not lists:
            text = json.dumps(result, default=str)
            content = {**content, "result": text[: MAX_AWS_RESULT_CHARS // 2]}
            break
        path, items = _largest(several or lists)
        key = ".".join(str(part) for part in path)
        content = {**content, "items_total": {key: len(items), **content["items_total"]}}
        keep = _items_that_fit(content, path, items) if several else 0
        content = {**content, "result": _replaced(result, path, items[:keep])}
    if not content["items_total"]:
        return {key: value for key, value in content.items() if key != "items_total"}
    return content


def aws_call(params: AwsCallInput, ctx: ToolContext) -> dict[str, Any]:
    model = _covered_model(params.service, params.operation)
    operation = _operation_name(model, params.operation)
    if reason := _refusal(model, operation):
        raise ToolError(f"blocked: {reason}")
    if ctx.aws_client is None:
        raise ToolError("aws_call is not available")
    _check_page_tokens(params.params)
    method = getattr(ctx.aws_client(params.service), xform_name(operation))
    try:
        response = method(**params.params)
    except ParamValidationError as exc:
        raise ToolError(str(exc)[:MAX_REASON_CHARS]) from exc
    body = {key: value for key, value in response.items() if key != "ResponseMetadata"}
    page_tokens = _page_tokens(params.service, operation)
    next_token = {
        request_key: body[response_key]
        for request_key, response_key in page_tokens
        if body.get(response_key) not in (None, "")
    }
    tokens = {response_key for _, response_key in page_tokens}
    content: dict[str, Any] = {
        "call": _call_label(params.service, operation),
        "result": _aws_value({key: value for key, value in body.items() if key not in tokens}),
        **({"next_token": next_token} if next_token else {}),
    }
    return _fit_aws_result(content)


_AWS_NAMED_SUBJECTS = (
    "FunctionName",
    "JobName",
    "ClusterName",
    "TableName",
    "DBInstanceIdentifier",
    "DBClusterIdentifier",
    "DomainName",
)


def _last_segment(text: str) -> str:
    return re.split(r"[:/]", text.rstrip("/"))[-1]


def _load_balancer_name(arn: str) -> str:
    """The name in an ELB or target group ARN (``.../app/<name>/<id>``)."""
    parts = arn.split("/")
    return parts[-2] if len(parts) >= 3 else _last_segment(arn)


def aws_call_subject(request: dict[str, Any]) -> str | None:
    """The resource an aws_call request names, by the most telling parameter it has."""

    def text(key: str) -> str | None:
        value = request.get(key)
        return value if isinstance(value, str) and value else None

    def first(key: str) -> str | None:
        value = request.get(key)
        if isinstance(value, list) and value and isinstance(value[0], str) and value[0]:
            return value[0]
        return None

    if bucket := text("Bucket"):
        child = text("Prefix") or text("Key")
        return f"{bucket}/{child}" if child else bucket
    if url := text("QueueUrl"):
        return _last_segment(url)
    for key in _AWS_NAMED_SUBJECTS:
        if value := text(key):
            return value
    for key in ("LoadBalancerArns", "TargetGroupArns"):
        if arn := first(key):
            return _load_balancer_name(arn)
    if arn := text("StateMachineArn"):
        return _last_segment(arn)
    if instance_id := first("InstanceIds"):
        return instance_id
    for key in ("LogGroupName", "StreamName", "TopicArn", "RoleName"):
        if value := text(key):
            return _last_segment(value) if key == "TopicArn" else value
    strings = [(key, value) for key, value in request.items() if isinstance(value, str) and value]
    for key, value in strings:
        if key.endswith("Arn"):
            return _last_segment(value)
    for key, value in strings:
        if key.endswith(("Name", "Id")):
            return value
    return strings[0][1] if strings else None


def _aws_refusal(service: str, operation: str) -> str | None:
    """The guard's reason for refusing a call; None when it is allowed or the service or
    operation does not exist."""
    if service in aws_services() and service not in aws_guard.ALLOWED_SERVICES:
        return aws_guard.NOT_COVERED
    try:
        model = _covered_model(service)
        return _refusal(model, _operation_name(model, operation))
    except ToolError:
        return None


def _aws_call_descriptor(values: dict[str, Any]) -> ToolCallDescriptor:
    service = _subject_text(values.get("service"))
    operation = _subject_text(values.get("operation"))
    request = values.get("params")
    return call_descriptor(
        "aws",
        service or "unknown",
        xform_name(operation) if operation else "unknown",
        aws_call_subject(request) if isinstance(request, dict) else None,
        refused=_aws_refusal(service, operation) if service and operation else None,
    )


READ_ONLY_TOOLS: tuple[ReadTool, ...] = (
    ReadTool(
        name="get_metric",
        description=(
            "One CloudWatch metric series over the N minutes (default 60) ending when the "
            "alarm fired, or between start and end (ISO 8601 UTC, within the last 14 days); "
            "at most 6 hours. Up to 200 points; the period grows to 300 s or more when the "
            "window needs it. Returns the window read."
        ),
        input_model=MetricInput,
        run=get_metric,
        call=CallSpec("aws", "cloudwatch", subject_keys=("{namespace}/{metric_name}",)),
    ),
    ReadTool(
        name="query_logs",
        description=(
            "Run one CloudWatch Logs Insights query over one log group for the N minutes "
            "(default 60) ending when the alarm fired, or between start and end (ISO 8601 "
            "UTC, within the last 14 days); at most 3 hours. Returns the window read and up "
            "to 50 rows, each field cut to 500 chars and redacted."
        ),
        input_model=LogsQueryInput,
        run=query_logs,
        call=CallSpec("aws", "logs", subject_keys=("log_group",)),
    ),
    ReadTool(
        name="recent_changes",
        description=(
            "CloudTrail write events in this account over the N minutes (default 60) ending "
            "when the alarm fired, or between start and end (ISO 8601 UTC, within the last "
            "14 days); at most 3 hours. Returns the window read and up to 50 events: time, "
            "event name, source, user and resource names."
        ),
        input_model=ChangesInput,
        run=recent_changes,
        call=CallSpec("aws", "cloudtrail"),
    ),
    ReadTool(
        name="describe_s3_key",
        description=(
            "Whether one exact S3 object key exists and its version history, without "
            "reading the object: the bucket's versioning status, up to 10 versions and "
            "delete markers of the key (last modified, size, storage class, latest), and up "
            "to 10 other keys sharing the key's name without its extension, to spot an "
            "extension mismatch."
        ),
        input_model=S3KeyInput,
        run=describe_s3_key,
        call=CallSpec("aws", "s3", subject_keys=("{bucket}/{key}",)),
        describes_resource=True,
    ),
    ReadTool(
        name="describe_database",
        description=(
            "An RDS or DocumentDB cluster or instance: status, engine, class, members and "
            "writer; its events from the last 24 hours (up to 20); and, when Performance "
            "Insights is on, the top 5 SQL statements and top 5 wait events by load over "
            "the N minutes (at most 360) ending when the alarm fired."
        ),
        input_model=DatabaseInput,
        run=describe_database,
        call=CallSpec("aws", "rds", subject_keys=("identifier",)),
        describes_resource=True,
    ),
    ReadTool(
        name="describe_search_domain",
        description=(
            "An OpenSearch domain's processing state, engine version, cluster and storage "
            "config, log publishing, and cluster health (shards, nodes) when available."
        ),
        input_model=SearchDomainInput,
        run=describe_search_domain,
        call=CallSpec("aws", "opensearch", subject_keys=("domain_name",)),
        describes_resource=True,
    ),
    ReadTool(
        name="describe_targets",
        description=(
            "Target health for a load balancer's target groups, or for one target group: "
            "per target id, port, state, reason and description, unhealthy first. Up to "
            "50 targets. Give exactly one of load_balancer_name or target_group_name."
        ),
        input_model=TargetsInput,
        run=describe_targets,
        call=CallSpec("aws", "elbv2", subject_keys=("load_balancer_name", "target_group_name")),
    ),
    ReadTool(
        name="recent_executions",
        description=(
            "A Step Functions state machine's most recent executions with one status "
            "(default FAILED): name, status, start and stop. Up to 20. Never inputs or "
            "outputs."
        ),
        input_model=ExecutionsInput,
        run=recent_executions,
        call=CallSpec("aws", "stepfunctions", subject_keys=("state_machine_name",)),
    ),
    ReadTool(
        name="scheduled_jobs",
        description=(
            "Scheduled work around the alarm over the N hours (default 2) ending when the "
            "alarm fired, or between start and end (ISO 8601 UTC, within the last 14 days); "
            "at most 24 hours. Optional name_contains, a plain part of a name. Returns up to "
            "20 schedules that fire in the window, from EventBridge rules (UTC) and "
            "EventBridge Scheduler (in its own timezone): name, source, expression, "
            "timezone, state, fire_times (UTC) and target (rule target ARNs; a Scheduler "
            "target's ARN, and for an aws-sdk target its service, action and the job, "
            "function, state machine or task it names). A rate under an hour is marked "
            "frequent, a rule rate fire_times_unknown, and a cron with L, W or # "
            "unsupported. Never job arguments or target input."
        ),
        input_model=ScheduledJobsInput,
        run=scheduled_jobs,
        call=CallSpec("aws", "scheduler", subject_keys=("name_contains",)),
    ),
    ReadTool(
        name=SEARCH_DATADOG_LOGS,
        description=(
            "Search Datadog logs, where ECS and EKS application logs live, over the N minutes "
            "(default 30) ending when the alarm fired, or between start and end (ISO 8601 "
            "UTC, within the last 14 days); at most 3 hours. Optional env and free text of "
            "plain words and quoted phrases. With service (the exact service tag) and "
            "optional status (error, warn or info; default error or warn), returns up to 50 "
            "logs, newest first: timestamp, service, status, host (pod or task id when "
            "tagged) and message cut to 500 chars and redacted. Without service, returns "
            "the services with the most error and warn logs instead (up to 25 with their "
            "error and warn counts, most errors first), optionally only those whose name "
            "contains name, a plain part of a service name: use it to find the exact "
            "service name, or which services are failing."
        ),
        input_model=DatadogLogsInput,
        run=search_datadog_logs,
        call=CallSpec("datadog", "logs", "search", ("service", "name", "env")),
    ),
    ReadTool(
        name=DATADOG_EVENTS,
        description=(
            "Datadog events for one service or one kube_namespace over the N minutes "
            "(default 60) ending when the alarm fired, or between start and end (ISO 8601 "
            "UTC, within the last 14 days; at most 6 hours): pod restarts, BackOff, "
            "OOM kills, image pull failures and deploys. Optional env and source "
            "(change_tracking, alert or deployment_analysis; default change_tracking). "
            "Returns up to 50 events, newest first: timestamp, title, kube and service "
            "tags, and message cut to 400 chars and redacted."
        ),
        input_model=DatadogEventsInput,
        run=datadog_events,
        call=CallSpec("datadog", "events", "search", ("service", "kube_namespace")),
    ),
    ReadTool(
        name=DATADOG_TOP_PODS,
        description=(
            "The pods using the most CPU (cores) or memory (MiB) on one EKS node (host, the "
            "EC2 instance id) or in one cluster (cluster, the kube_cluster_name), optionally "
            "in one kube_namespace, over the N minutes (default 60) ending when the alarm "
            "fired, or between start and end (ISO 8601 UTC, within the last 14 days; at most "
            "3 hours). Returns up to 10 pods ranked by their max: kube_namespace, pod_name, "
            "max, max_at, avg, last, and before (the average over the first quarter of the "
            "window, to show a jump). Give exactly one of host or cluster."
        ),
        input_model=DatadogTopPodsInput,
        run=datadog_top_pods,
        call=CallSpec("datadog", "metrics", "top_pods", ("host", "cluster")),
    ),
    ReadTool(
        name=GITHUB_LIST_REPOS,
        description=(
            "List the GitHub repos in the org, optionally only those whose name contains "
            "name, sorted by last push (default) or name. Returns up to 50 (default 20): "
            "name, description, default branch, archived, last push and language."
        ),
        input_model=GitHubListReposInput,
        run=github_list_repos,
        call=CallSpec("github", "repos", "list", ("name",)),
    ),
    ReadTool(
        name=GITHUB_SEARCH_CODE,
        description=(
            "Search code in the org's GitHub repos for plain words or a quoted phrase, such "
            "as a log message, exception text or function name; optionally in one repo and "
            "under one path. No qualifiers: code adds them. Returns up to 20 (default 10): "
            "repo, path and up to 2 matching fragments cut to 300 chars and redacted. GitHub "
            "allows about 10 code searches a minute."
        ),
        input_model=GitHubSearchCodeInput,
        run=github_search_code,
        call=CallSpec("github", "code", "search", ("{repo}/{path}", "repo", "query")),
    ),
    ReadTool(
        name=GITHUB_GET_FILE,
        description=(
            "Read one file (at most 200 KB) from an org repo at the default branch or a ref "
            "(branch, tag or sha). With line, returns that line and context lines either "
            "side (default 30, at most 40); without, the first 80 lines. Each line is "
            "numbered, cut to 200 chars and redacted."
        ),
        input_model=GitHubFileInput,
        run=github_get_file,
        call=CallSpec("github", "contents", "get", ("{repo}/{path}",)),
    ),
    ReadTool(
        name=GITHUB_RECENT_CHANGES,
        description=(
            "What changed in one org repo over the N hours (default 24) ending when the "
            "alarm fired, or between start and end (ISO 8601 UTC, within the last 14 days; "
            "at most 168 hours), optionally only under a path: commits on the default "
            "branch (sha7, date, author, first message line), merged pull requests (number, "
            "title, merged_at, base, author) and GitHub Actions runs (name, event, branch "
            "or tag, status, conclusion, created_at, run number). Up to limit (default 15, "
            "at most 30) of each."
        ),
        input_model=GitHubChangesInput,
        run=github_recent_changes,
        call=CallSpec("github", "repos", "recent_changes", ("{repo}/{path}", "repo")),
    ),
    ReadTool(
        name=GITHUB_GET_CHANGE,
        description=(
            "One change in an org repo: a commit by sha (7 to 40 hex chars) or a pull "
            "request by number; give exactly one. A commit returns sha7, date, author and "
            "message cut to 1,000 chars; a pull request its title, body cut to 1,500 chars, "
            "state, merged_at, base, head and author. Both return up to 30 changed files "
            "with status, additions, deletions and patch cut to 1,500 chars and redacted."
        ),
        input_model=GitHubChangeInput,
        run=github_get_change,
        call=_github_change_descriptor,
    ),
    ReadTool(
        name=AWS_CALL,
        description=(
            "Call one read-only AWS operation (Describe, List or Get) by boto3 service name "
            "and snake_case operation, e.g. s3 list_object_versions, with its parameters in "
            "params. One page only: pass the next_token entries back in params for the "
            "next. An unknown service or operation is an error that lists the closest "
            "valid operation names. Operations that read data, secrets, environment "
            "variables or user data are refused. Secret-shaped fields are dropped and long "
            "lists cut."
        ),
        input_model=AwsCallInput,
        run=aws_call,
        call=_aws_call_descriptor,
    ),
)


def offered_tools(ctx: ToolContext) -> tuple[ReadTool, ...]:
    """The tools this run may call: the Datadog and GitHub tools and aws_call only when
    configured."""
    unavailable = (
        (DATADOG_TOOLS if ctx.datadog is None else frozenset())
        | (GITHUB_TOOLS if ctx.github is None else frozenset())
        | (AWS_TOOLS if ctx.aws_client is None else frozenset())
    )
    return tuple(tool for tool in READ_ONLY_TOOLS if tool.name not in unavailable)


def describe_call(name: str, raw_input: Any) -> ToolCallDescriptor | None:
    """The call descriptor of one call, or None when no tool has that name.

    It is read from the validated input. Invalid input is still described: a fixed
    descriptor as usual, an input-derived one with service and action ``unknown`` and the
    subject read from the raw input. Every name is redacted and cut.
    """
    tool = next((tool for tool in READ_ONLY_TOOLS if tool.name == name), None)
    if tool is None:
        return None
    values: dict[str, Any] = raw_input if isinstance(raw_input, dict) else {}
    try:
        values = tool.input_model.model_validate(values).model_dump(mode="json")
        valid = True
    except ValidationError:
        valid = False
    descriptor = tool.descriptor(values)
    if not valid and not isinstance(tool.call, CallSpec):
        descriptor = call_descriptor(descriptor.provider, "unknown", "unknown", descriptor.subject)
    service = redact(descriptor.service)[:MAX_DESCRIPTOR_NAME_CHARS]
    action = redact(descriptor.action)[:MAX_DESCRIPTOR_NAME_CHARS]
    subject = redact(descriptor.subject)[:MAX_SUBJECT_CHARS] if descriptor.subject else None
    refused = descriptor.refused[:MAX_REFUSED_CHARS] if descriptor.refused else None
    return descriptor.model_copy(
        update={
            "service": service,
            "action": action,
            "label": f"{descriptor.provider}.{service}.{action}"[:MAX_LABEL_CHARS],
            "subject": subject,
            "refused": refused,
        }
    )


def validation_summary(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(part) for part in error['loc']) or 'input'}: {error['msg']}"
        for error in exc.errors()[:5]
    )


def _execute(tool: ReadTool, params: BaseModel, ctx: ToolContext) -> ToolResult:
    try:
        return ToolResult("success", tool.run(params, ctx))
    except ToolError as exc:
        return ToolResult("error", {"error": str(exc)})
    except ClientError as exc:
        error = exc.response.get("Error", {})
        message = f"{error.get('Code', 'ClientError')}: {error.get('Message', '')}"
        return ToolResult("error", {"error": message[:MAX_REASON_CHARS]})
    except Exception as exc:
        return ToolResult("error", {"error": f"{type(exc).__name__}: {exc}"[:MAX_REASON_CHARS]})


def run_tool(name: str, raw_input: Any, ctx: ToolContext) -> ToolResult:
    """Validate the input and run one tool. Every failure becomes an error result.

    The whole result is redacted, so no tool's output reaches the model unredacted.
    """
    tool = next((tool for tool in offered_tools(ctx) if tool.name == name), None)
    if tool is None:
        return ToolResult("error", {"error": f"unknown tool {name!r}"})
    try:
        params = tool.input_model.model_validate(raw_input or {})
    except ValidationError as exc:
        return ToolResult("error", {"error": f"invalid input: {validation_summary(exc)}"})
    result = _execute(tool, params, ctx)
    found = tool.describes_resource and result.status == "success"
    return ToolResult(result.status, redact_value(result.content), found)
