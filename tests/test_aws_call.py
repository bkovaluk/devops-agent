"""The generic AWS tool: the guarded call, its suggestions, projection and descriptors."""

from __future__ import annotations

import dataclasses
import json
import math
from datetime import UTC, datetime
from typing import Any

import botocore.session
import pytest
from botocore import xform_name
from botocore.exceptions import ParamValidationError

from devops_agent import aws_guard, tools
from devops_agent.agent import MAX_TOOL_RESULT_CHARS, investigate
from devops_agent.config import Settings
from devops_agent.redact import REDACTED
from devops_agent.tools import (
    AWS_TOOLS,
    READ_ONLY_TOOLS,
    ToolContext,
    ToolResult,
    aws_call_subject,
    describe_call,
    offered_tools,
    run_tool,
)
from evals.replay import RecordedTools
from tests.conftest import FakeBedrock, FakeClients, converse_response, job, report, tool_use
from tests.test_tools import FORBIDDEN_OPERATIONS

WHEN = datetime(2026, 10, 13, 9, 30, tzinfo=UTC)
SESSION = botocore.session.get_session()


def _clients(ctx: ToolContext) -> FakeClients:
    assert isinstance(ctx.aws_client, FakeClients)
    return ctx.aws_client


def _call(ctx: ToolContext, service: str, operation: str, **params: Any) -> ToolResult:
    return run_tool("aws_call", {"service": service, "operation": operation, "params": params}, ctx)


# aws_call


def test_allowed_call_is_projected(tool_ctx: ToolContext) -> None:
    _clients(tool_ctx)("ec2").responses["describe_instances"] = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-0123456789abcdef0",
                        "LaunchTime": WHEN,
                        "UserData": "IyEvYmluL2Jhc2g=",
                        "Tags": [{"Key": "Name", "Value": "checkout"}],
                    }
                ]
            }
        ],
        "Environment": {"Variables": {"DB_PASSWORD": "hunter2"}},
        "Blob": b"abc",
        "ResponseMetadata": {"RequestId": "r"},
    }
    result = _call(tool_ctx, "ec2", "describe_instances", InstanceIds=["i-0123456789abcdef0"])
    assert result.status == "success"
    assert result.content["call"] == "aws.ec2.describe_instances"
    body = result.content["result"]
    assert "ResponseMetadata" not in body
    assert body["Environment"] == "<removed>"
    instance = body["Reservations"][0]["Instances"][0]
    assert instance["UserData"] == "<removed>"
    assert instance["LaunchTime"] == "2026-10-13T09:30:00+00:00"
    assert body["Blob"] == "<bytes 3>"
    assert "hunter2" not in json.dumps(result.content)
    assert _clients(tool_ctx).clients["ec2"].calls == [
        ("describe_instances", {"InstanceIds": ["i-0123456789abcdef0"]})
    ]


@pytest.mark.parametrize(
    ("service", "operation", "reason"),
    [
        ("s3", "get_object", "reads object contents"),
        ("s3", "select_object_content", "reads object contents"),
        ("ssm", "get_parameter", "returns secret values"),
        ("ssm", "get_parameters_by_path", "returns secret values"),
        ("lambda", "list_functions", "returns environment variables"),
        ("lambda", "get_function_configuration", "returns environment variables"),
        ("secretsmanager", "get_secret_value", "returns secret values"),
        ("secretsmanager", "get_random_password", "returns secret values"),
        ("iam", "get_role", "service not covered by aws_call"),
        ("sts", "get_caller_identity", "service not covered by aws_call"),
        ("amplify", "list_apps", "service not covered by aws_call"),
        ("cognito-idp", "list_users", "service not covered by aws_call"),
        ("config", "get_resource_config_history", "service not covered by aws_call"),
        ("sso-admin", "list_instances", "service not covered by aws_call"),
        ("textract", "get_document_analysis", "service not covered by aws_call"),
        ("apigateway", "get_usage_plan_keys", "returns secret values"),
        ("ssm", "list_command_invocations", "returns console output"),
        ("glue", "get_job_runs", "returns environment variables"),
        ("lambda", "list_versions_by_function", "returns environment variables"),
        ("ec2", "describe_vpn_connections", "returns secret values"),
        ("stepfunctions", "get_activity_task", "reads payload data"),
        ("apigateway", "get_sdk", "returns a file body"),
        ("logs", "get_log_object", "returns a file body"),
        ("dynamodb", "get_item", "reads payload data"),
        ("glue", "get_job", "returns environment variables"),
        ("glue", "get_connection", "returns secret values"),
        ("ec2", "get_password_data", "returns secret values"),
        ("ec2", "describe_instance_attribute", "returns instance user data"),
        ("ecs", "describe_task_definition", "returns environment variables"),
        ("stepfunctions", "get_execution_history", "reads payload data"),
        ("kinesis", "get_records", "reads payload data"),
        ("ecr", "get_authorization_token", "returns credentials"),
        ("kms", "get_public_key", "key material or cryptographic operation"),
        ("cloudformation", "get_stack_policy", "returns configuration contents"),
        ("sagemaker-runtime", "invoke_endpoint", "service not covered by aws_call"),
    ],
)
def test_blocked_operation_is_refused_without_calling_aws(
    tool_ctx: ToolContext, service: str, operation: str, reason: str
) -> None:
    result = _call(tool_ctx, service, operation)
    assert result.status == "error"
    assert result.content["error"] == f"blocked: {reason}"
    assert _clients(tool_ctx).calls == []


@pytest.mark.parametrize(
    ("service", "operation"),
    [
        ("s3", "put_object"),
        ("sqs", "delete_queue"),
        ("glue", "start_job_run"),
        ("lambda", "invoke"),
        ("dynamodb", "query"),
        ("s3", "head_object"),
        ("sqs", "receive_message"),
    ],
)
def test_non_read_operation_is_refused(tool_ctx: ToolContext, service: str, operation: str) -> None:
    result = _call(tool_ctx, service, operation)
    assert result.content["error"] == "blocked: not a read operation"
    assert _clients(tool_ctx).calls == []


def test_pascal_case_operation_is_accepted(tool_ctx: ToolContext) -> None:
    result = _call(tool_ctx, "s3", "ListObjectVersions", Bucket="drops")
    assert result.status == "success"
    assert result.content["call"] == "aws.s3.list_object_versions"
    assert _clients(tool_ctx).operations() == ["list_object_versions"]


def test_unknown_operation_lists_close_matches(tool_ctx: ToolContext) -> None:
    result = _call(tool_ctx, "s3", "list_object_version")
    assert result.status == "error"
    assert "unknown operation 'list_object_version' for s3" in result.content["error"]
    assert "; closest operations: list_object_versions" in result.content["error"]
    assert _clients(tool_ctx).calls == []


def test_unknown_operation_lists_operations_sharing_its_words(tool_ctx: ToolContext) -> None:
    error = _call(tool_ctx, "sqs", "describe_queue").content["error"]
    assert error.startswith("unknown operation 'describe_queue' for sqs; closest operations: ")
    closest = error.split("closest operations: ")[1].split(", ")
    assert "get_queue_attributes" in closest
    assert len(closest) <= 5
    assert _clients(tool_ctx).calls == []


def test_unknown_service_lists_close_services_and_operations(tool_ctx: ToolContext) -> None:
    error = _call(tool_ctx, "lamda", "list_event_source_mappings").content["error"]
    assert error.startswith("unknown service 'lamda'; close matches: lambda")
    closest = error.split("closest operations: ")[1].split(", ")
    assert closest[0] == "lambda.list_event_source_mappings"
    assert {name.split(".")[0] for name in closest} <= aws_guard.ALLOWED_SERVICES
    assert _clients(tool_ctx).calls == []


def test_uncovered_service_is_refused(tool_ctx: ToolContext) -> None:
    result = _call(tool_ctx, "cognito-idp", "list_users")
    assert result.content["error"] == "blocked: service not covered by aws_call"
    assert _clients(tool_ctx).calls == []


def test_param_validation_error_is_returned(tool_ctx: ToolContext) -> None:
    _clients(tool_ctx)("s3").responses["list_object_versions"] = ParamValidationError(
        report='Missing required parameter in input: "Bucket"'
    )
    result = _call(tool_ctx, "s3", "list_object_versions")
    assert result.status == "error"
    assert 'Missing required parameter in input: "Bucket"' in result.content["error"]


def test_oversized_page_token_is_rejected(tool_ctx: ToolContext) -> None:
    result = _call(tool_ctx, "logs", "describe_log_groups", nextToken="x" * 4097)
    assert result.content["error"] == "nextToken is over 4096 bytes"
    assert _clients(tool_ctx).calls == []


def test_long_lists_are_truncated_and_next_token_returned(tool_ctx: ToolContext) -> None:
    versions = [
        {"Key": f"drops/2026/10/{n:04}.xml", "VersionId": f"v{n}", "LastModified": WHEN}
        for n in range(500)
    ]
    _clients(tool_ctx)("s3").responses["list_object_versions"] = {
        "Versions": versions,
        "IsTruncated": True,
        "NextKeyMarker": "drops/2026/10/0500.xml",
        "NextVersionIdMarker": "v500",
    }
    content = _call(tool_ctx, "s3", "list_object_versions", Bucket="drops").content
    assert content["truncated"] is True
    assert content["items_total"] == {"Versions": 500}
    assert 0 < len(content["result"]["Versions"]) < 500
    assert content["next_token"] == {
        "KeyMarker": "drops/2026/10/0500.xml",
        "VersionIdMarker": "v500",
    }
    assert "NextKeyMarker" not in content["result"]
    text = json.dumps(content, default=str)
    assert len(text) < MAX_TOOL_RESULT_CHARS
    assert json.loads(text) == content


def test_small_result_is_not_marked_truncated(tool_ctx: ToolContext) -> None:
    _clients(tool_ctx)("logs").responses["describe_log_groups"] = {
        "logGroups": [{"logGroupName": "/aws/lambda/a"}],
        "nextToken": "page-2",
    }
    content = _call(tool_ctx, "logs", "describe_log_groups").content
    assert "truncated" not in content
    assert content["next_token"] == {"nextToken": "page-2"}
    assert "nextToken" not in content["result"]


def test_strings_are_redacted(tool_ctx: ToolContext) -> None:
    _clients(tool_ctx)("ecs").responses["describe_services"] = {
        "services": [{"serviceName": "checkout", "status": "url postgres://app:pw1234@db/x"}]
    }
    result = _call(tool_ctx, "ecs", "describe_services", cluster="c", services=["checkout"])
    status = result.content["result"]["services"][0]["status"]
    assert REDACTED in status
    assert "pw1234" not in status


def test_secret_shaped_keys_are_removed_at_any_depth(tool_ctx: ToolContext) -> None:
    _clients(tool_ctx)("ecs").responses["describe_services"] = {
        "services": [
            {
                "serviceName": "build",
                "env": [{"name": "API_URL", "value": "https://x"}],
                "source": {"basicAuthCredentials": {"username": "u", "password": "p"}},
                "MasterUserSecret": {"SecretArn": "arn:aws:secretsmanager:r:1:secret:db"},
                "DefaultArguments": {"--conf": "k=v"},
                "ApiKeyValue": "abc",
                "PreSharedKey": "psk",
                "AuthTokenEnabled": True,
                "EnvironmentVariables": [{"name": "A", "value": "b"}],
                "variables": {"db": "x"},
                "StageVariables": {"key": "y"},
                "Input": '{"secret": 1}',
                "Status": "ACTIVE",
            }
        ]
    }
    service = _call(tool_ctx, "ecs", "describe_services", cluster="c", services=["build"]).content[
        "result"
    ]["services"][0]
    removed = {key for key, value in service.items() if value == "<removed>"}
    assert removed == {
        "env",
        "MasterUserSecret",
        "DefaultArguments",
        "ApiKeyValue",
        "PreSharedKey",
        "AuthTokenEnabled",
        "EnvironmentVariables",
        "variables",
        "StageVariables",
        "Input",
    }
    assert service["source"] == {"basicAuthCredentials": "<removed>"}
    assert service["serviceName"] == "build"
    assert service["Status"] == "ACTIVE"


def test_embedded_documents_are_removed(tool_ctx: ToolContext) -> None:
    definition = json.dumps({"States": {f"S{n}": {"Type": "Task"} for n in range(20)}})
    _clients(tool_ctx)("stepfunctions").responses["describe_state_machine"] = {
        "name": "export",
        "definition": definition,
        "parameters": "short",
        "description": definition,
    }
    result = _call(
        tool_ctx, "stepfunctions", "describe_state_machine", stateMachineArn="arn:m"
    ).content["result"]
    assert result["definition"] == "<removed: embedded document>"
    assert result["parameters"] == "short"
    assert result["description"] == definition


def test_one_oversized_item_is_trimmed_not_emptied(tool_ctx: ToolContext) -> None:
    instance = {
        "DBInstanceIdentifier": "core-writer",
        "DBInstanceStatus": "available",
        "VpcSecurityGroups": [{"VpcSecurityGroupId": f"sg-{n:08x}"} for n in range(200)],
        "DBParameterGroups": [{"DBParameterGroupName": f"pg-{n}"} for n in range(100)],
        "Notes": "x" * 3000,
    }
    assert len(json.dumps(instance)) > 7000
    _clients(tool_ctx)("rds").responses["describe_db_instances"] = {"DBInstances": [instance]}
    content = _call(tool_ctx, "rds", "describe_db_instances").content
    trimmed = content["result"]["DBInstances"]
    assert len(trimmed) == 1
    assert trimmed[0]["DBInstanceIdentifier"] == "core-writer"
    assert trimmed[0]["DBInstanceStatus"] == "available"
    assert content["truncated"] is True
    assert "DBInstances" not in content["items_total"]
    assert len(json.dumps(content, default=str)) <= tools.MAX_AWS_RESULT_CHARS


def test_aws_tools_are_offered_only_with_a_client_factory(tool_ctx: ToolContext) -> None:
    assert {tool.name for tool in offered_tools(tool_ctx)} >= AWS_TOOLS
    bare = dataclasses.replace(tool_ctx, aws_client=None)
    assert not AWS_TOOLS & {tool.name for tool in offered_tools(bare)}
    assert run_tool("aws_call", {"service": "s3", "operation": "x"}, bare).status == "error"


# Guard table

# The botocore services in which each operation reads secrets or payloads.
_FORBIDDEN_OWNERS = {
    "get_function": ("lambda", "cloudfront"),
    "get_function_configuration": ("lambda",),
    "list_functions": ("lambda",),
    "describe_task_definition": ("ecs",),
    "receive_message": ("sqs",),
    "get_records": ("kinesis", "dynamodbstreams", "keyspacesstreams"),
    "get_shard_iterator": ("kinesis", "dynamodbstreams", "keyspacesstreams"),
    "describe_execution": ("stepfunctions",),
    "get_execution_history": ("stepfunctions",),
    "get_secret_value": ("secretsmanager",),
    "batch_get_secret_value": ("secretsmanager",),
    "get_parameter": ("ssm",),
    "get_parameters": ("ssm",),
    "get_parameters_by_path": ("ssm",),
    "get_parameter_history": ("ssm",),
    "get_object": ("s3", "mediastore-data"),
    "head_object": ("s3",),
    "select_object_content": ("s3",),
}


def _pascal(service: str, operation: str) -> str:
    model = SESSION.get_service_model(service)
    return next(name for name in model.operation_names if xform_name(name) == operation)


def test_every_forbidden_operation_has_its_owners_listed() -> None:
    assert set(_FORBIDDEN_OWNERS) == set(FORBIDDEN_OPERATIONS)


@pytest.mark.parametrize("operation", FORBIDDEN_OPERATIONS)
def test_guard_refuses_every_forbidden_operation(operation: str) -> None:
    for service in _FORBIDDEN_OWNERS[operation]:
        assert aws_guard.check(service, _pascal(service, operation)) is not None, service


def test_every_allowed_service_is_a_botocore_service() -> None:
    assert set(SESSION.get_available_services()) >= aws_guard.ALLOWED_SERVICES
    assert tools.covered_services() == tuple(sorted(aws_guard.ALLOWED_SERVICES))


def test_every_blocked_entry_names_a_real_covered_operation_and_is_refused() -> None:
    for key, reason in aws_guard.BLOCKED_OPERATIONS.items():
        service, operation = key.split(":")
        assert service in aws_guard.ALLOWED_SERVICES, key
        assert operation in SESSION.get_service_model(service).operation_names, key
        assert aws_guard.check(service, operation) == reason, key
    for service in (*aws_guard.SERVICE_READ_PREFIXES, *aws_guard.SERVICE_READ_OPERATIONS):
        assert service in aws_guard.ALLOWED_SERVICES, service


def test_every_uncovered_service_is_refused() -> None:
    for service in set(SESSION.get_available_services()) - aws_guard.ALLOWED_SERVICES:
        assert aws_guard.check(service, "DescribeAnything") == aws_guard.NOT_COVERED, service


def test_every_streaming_output_operation_is_refused() -> None:
    found = 0
    for service in tools.covered_services():
        model = SESSION.get_service_model(service)
        for operation in model.operation_names:
            shape = model.operation_model(operation)
            if shape.has_streaming_output or shape.has_event_stream_output:
                found += 1
                assert tools._refusal(model, operation) is not None, f"{service}:{operation}"
    assert found
    assert aws_guard.check("apigateway", "GetSdk", returns_body=True) == aws_guard.FILE_BODY


@pytest.mark.parametrize(
    ("service", "operation"),
    [
        ("s3", "ListObjectVersions"),
        ("logs", "GetLogEvents"),
        ("kms", "DescribeKey"),
        ("secretsmanager", "DescribeSecret"),
        ("ssm", "DescribeParameters"),
        ("cloudformation", "DescribeStacks"),
        ("elbv2", "DescribeTargetHealth"),
        ("cloudtrail", "LookupEvents"),
    ],
)
def test_guard_allows_metadata_reads(service: str, operation: str) -> None:
    assert aws_guard.check(service, operation) is None


@pytest.mark.parametrize(
    ("service", "operation", "reason"),
    [
        ("xray", "BatchGetTraces", aws_guard.TRACES),
        ("wafv2", "GetSampledRequests", aws_guard.SAMPLED_REQUESTS),
        ("waf", "GetSampledRequests", aws_guard.NOT_COVERED),
        ("waf-regional", "GetSampledRequests", aws_guard.NOT_COVERED),
        ("athena", "GetQueryResults", aws_guard.NOT_COVERED),
        ("codecommit", "GetBlob", aws_guard.NOT_COVERED),
    ],
)
def test_guard_refuses_traces_sampled_requests_and_uncovered_data_reads(
    service: str, operation: str, reason: str
) -> None:
    assert aws_guard.check(service, operation) == reason
    assert tools._aws_refusal(service, xform_name(operation)) == reason


def test_guard_still_allows_trace_and_firewall_metadata() -> None:
    assert aws_guard.check("xray", "GetServiceGraph") is None
    assert aws_guard.check("wafv2", "GetWebACL") is None


# Call descriptors


def test_every_registered_tool_has_a_descriptor() -> None:
    for tool in READ_ONLY_TOOLS:
        descriptor = describe_call(tool.name, {})
        assert descriptor is not None, tool.name
        assert descriptor.provider and descriptor.service and descriptor.action, tool.name
        assert descriptor.label == (
            f"{descriptor.provider}.{descriptor.service}.{descriptor.action}"
        )


@pytest.mark.parametrize(
    ("name", "tool_input", "label", "subject"),
    [
        (
            "describe_s3_key",
            {"bucket": "drops", "key": "a/b.xml"},
            "aws.s3.describe_s3_key",
            "drops/a/b.xml",
        ),
        ("recent_changes", {}, "aws.cloudtrail.recent_changes", None),
        ("scheduled_jobs", {"hours": 2}, "aws.scheduler.scheduled_jobs", None),
        ("datadog_top_pods", {"cluster": "checkout"}, "datadog.metrics.top_pods", "checkout"),
        (
            "github_get_file",
            {"repo": "chat-lambda", "path": "handler.py"},
            "github.contents.get",
            "chat-lambda/handler.py",
        ),
        (
            "github_recent_changes",
            {"repo": "chat-lambda"},
            "github.repos.recent_changes",
            "chat-lambda",
        ),
        (
            "github_get_change",
            {"repo": "chat-lambda", "number": 7},
            "github.pulls.get",
            "chat-lambda#7",
        ),
        (
            "github_get_change",
            {"repo": "chat-lambda", "sha": "abc1234"},
            "github.commits.get",
            "chat-lambda@abc1234",
        ),
        (
            "aws_call",
            {"service": "s3", "operation": "ListObjectVersions", "params": {"Bucket": "drops"}},
            "aws.s3.list_object_versions",
            "drops",
        ),
    ],
)
def test_curated_and_generic_descriptors(
    name: str, tool_input: dict[str, Any], label: str, subject: str | None
) -> None:
    descriptor = describe_call(name, tool_input)
    assert descriptor is not None
    assert (descriptor.label, descriptor.subject, descriptor.kind) == (label, subject, "evidence")
    assert descriptor.refused is None


@pytest.mark.parametrize(
    ("params", "subject"),
    [
        ({"Bucket": "drops", "Prefix": "2026/", "MaxKeys": 5}, "drops/2026/"),
        ({"Bucket": "drops", "Key": "a.xml"}, "drops/a.xml"),
        ({"QueueUrl": "https://sqs.us-east-1.amazonaws.com/1/jobs-dlq"}, "jobs-dlq"),
        ({"MaxItems": 5, "FunctionName": "chat-dev"}, "chat-dev"),
        (
            {"LoadBalancerArns": ["arn:aws:elasticloadbalancing:r:1:loadbalancer/app/front/50dc"]},
            "front",
        ),
        ({"TargetGroupArns": ["arn:aws:elasticloadbalancing:r:1:targetgroup/api/6d0e"]}, "api"),
        ({"StateMachineArn": "arn:aws:states:us-east-1:1:stateMachine:export"}, "export"),
        ({"InstanceIds": ["i-0123456789abcdef0"]}, "i-0123456789abcdef0"),
        ({"TopicArn": "arn:aws:sns:us-east-1:1:ops-alerts-prod"}, "ops-alerts-prod"),
        ({"Limit": 5, "ResourceArn": "arn:aws:ecs:us-east-1:1:cluster/checkout"}, "checkout"),
        ({"Mode": "all", "WidgetId": "w-1"}, "w-1"),
        ({"Mode": "all"}, "all"),
        ({"MaxResults": 5}, None),
    ],
)
def test_aws_call_subject_preference(params: dict[str, Any], subject: str | None) -> None:
    assert aws_call_subject(params) == subject


def test_unknown_tool_has_no_descriptor() -> None:
    assert describe_call("delete_alarm", {"alarm_name": "a"}) is None


def test_refused_call_is_described_with_its_reason() -> None:
    descriptor = describe_call(
        "aws_call",
        {"service": "s3", "operation": "GetObject", "params": {"Bucket": "drops", "Key": "a"}},
    )
    assert descriptor is not None
    assert descriptor.label == "aws.s3.get_object"
    assert descriptor.subject == "drops/a"
    assert descriptor.refused == "reads object contents"
    write = describe_call("aws_call", {"service": "sqs", "operation": "delete_queue"})
    assert write is not None
    assert write.refused == "not a read operation"


def test_invalid_input_is_described_as_unknown() -> None:
    descriptor = describe_call("aws_call", {"service": "s3", "params": {"Bucket": "drops"}})
    assert descriptor is not None
    assert (descriptor.label, descriptor.subject, descriptor.refused) == (
        "aws.unknown.unknown",
        "drops",
        None,
    )
    huge = describe_call("aws_call", {"service": "s" * 500, "operation": "o" * 500})
    assert huge is not None
    assert huge.label == "aws.unknown.unknown"


def test_descriptor_names_are_redacted_and_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    def describe(values: dict[str, Any]) -> tools.ToolCallDescriptor:
        return tools.call_descriptor("aws", "password=hunter2", "a" * 500)

    call_tool = next(tool for tool in READ_ONLY_TOOLS if tool.name == "aws_call")
    registry = tuple(
        dataclasses.replace(tool, call=describe) if tool is call_tool else tool
        for tool in READ_ONLY_TOOLS
    )
    monkeypatch.setattr(tools, "READ_ONLY_TOOLS", registry)
    descriptor = describe_call("aws_call", {"service": "s3", "operation": "list_buckets"})
    assert descriptor is not None
    assert "hunter2" not in descriptor.service
    assert descriptor.action == "a" * 64
    assert len(descriptor.label) <= 140
    assert descriptor.label == f"aws.{descriptor.service}.{descriptor.action}"[:140]


def test_subject_and_refusal_are_redacted_and_cut(monkeypatch: pytest.MonkeyPatch) -> None:
    long = describe_call(
        "aws_call", {"service": "s3", "operation": "x", "params": {"Name": "n" * 500}}
    )
    assert long is not None
    assert long.subject == "n" * 200
    secret = describe_call(
        "aws_call", {"service": "s3", "operation": "x", "params": {"Name": "password=hunter2"}}
    )
    assert secret is not None
    assert secret.subject is not None
    assert "hunter2" not in secret.subject
    assert REDACTED in secret.subject
    monkeypatch.setattr(aws_guard, "check", lambda service, operation, returns_body: "r" * 300)
    refused = describe_call("aws_call", {"service": "s3", "operation": "list_buckets"})
    assert refused is not None
    assert refused.refused == "r" * 120


def test_trail_step_carries_the_descriptor(tool_ctx: ToolContext, settings: Settings) -> None:
    bedrock = FakeBedrock(
        converse_response(
            tool_use(
                "aws_call",
                {"service": "ssm", "operation": "get_parameter", "params": {"Name": "/app/x"}},
            )
        ),
        converse_response(tool_use("describe_s3_key", {"bucket": "drops", "key": "a.xml"}, "t2")),
        converse_response(report()),
    )
    investigation = investigate(bedrock, tool_ctx, settings, job(), "ctx", [], lambda: math.inf)
    refused, key = investigation.trail
    assert refused.status == "error"
    assert refused.call is not None
    assert refused.call.label == "aws.ssm.get_parameter"
    assert refused.call.subject == "/app/x"
    assert refused.call.refused == "returns secret values"
    assert key.call is not None
    assert key.call.label == "aws.s3.describe_s3_key"
    assert key.call.refused is None


def test_replay_matches_aws_calls_on_the_same_resource() -> None:
    recorded = {
        "name": "aws_call",
        "input": {
            "service": "s3",
            "operation": "list_object_versions",
            "params": {"Bucket": "drops", "MaxKeys": 10},
        },
        "status": "success",
        "output": "recorded",
    }
    replayed = RecordedTools([recorded])

    def answer(params: dict[str, Any], operation: str = "ListObjectVersions") -> str:
        tool_input = {"service": "s3", "operation": operation, "params": params}
        return replayed("aws_call", tool_input, None).text  # type: ignore[arg-type]

    assert answer({"Bucket": "drops", "MaxKeys": 10}) == "recorded"
    assert answer({"Bucket": "drops", "MaxKeys": 50}) == "recorded"
    assert "no recorded data" in answer({"Bucket": "other"})
    assert "no recorded data" in answer({"Bucket": "drops"}, "list_objects_v2")
    assert (replayed.approximate, replayed.misses) == (1, 2)
