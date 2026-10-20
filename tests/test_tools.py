"""Read-only tool projections, bounds and error handling."""

from __future__ import annotations

import ast
import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from pytest_mock import MockerFixture

from devops_agent import tools
from devops_agent.redact import REDACTED
from devops_agent.tools import (
    READ_ONLY_OPERATIONS,
    READ_ONLY_TOOLS,
    AlarmInput,
    InstanceInput,
    ToolContext,
    ToolError,
    describe_instance,
    find_log_sources,
    get_alarm,
    run_tool,
)
from tests.conftest import ALARM_ARN, ALARM_FIELDS, ALARM_NAME, FakeClient, client_error

WHEN = datetime(2026, 9, 29, 14, 0, tzinfo=UTC)

METRIC_ALARM = {
    "AlarmName": ALARM_NAME,
    "AlarmArn": ALARM_ARN,
    "AlarmDescription": "Payment API error rate",
    "StateValue": "ALARM",
    "StateReason": "Threshold Crossed",
    "StateUpdatedTimestamp": WHEN,
    "Namespace": "AWS/Lambda",
    "MetricName": "Errors",
    "Dimensions": [{"Name": "FunctionName", "Value": "payment-api-prod"}],
    "Statistic": "Sum",
    "Period": 60,
    "Threshold": 5.0,
    "ComparisonOperator": "GreaterThanThreshold",
    "EvaluationPeriods": 3,
    "AlarmActions": ["arn:aws:sns:us-east-1:111122223333:ops"],
}


def test_every_tool_spec_is_a_converse_tool_spec() -> None:
    for tool in READ_ONLY_TOOLS:
        spec = tool.spec()["toolSpec"]
        assert spec["name"] == tool.name
        assert spec["inputSchema"]["json"]["type"] == "object"


def test_get_alarm_projects_config_tags_and_history(tool_ctx: ToolContext) -> None:
    tool_ctx.cloudwatch.responses.update(
        {
            "describe_alarms": {"MetricAlarms": [METRIC_ALARM], "CompositeAlarms": []},
            "list_tags_for_resource": {"Tags": [{"Key": "Severity", "Value": "high"}]},
            "describe_alarm_history": {
                "AlarmHistoryItems": [
                    {
                        "Timestamp": WHEN,
                        "HistoryItemType": "StateUpdate",
                        "HistorySummary": f"Alarm updated from OK to ALARM {i}",
                        "HistoryData": "{...large json...}",
                    }
                    for i in range(15)
                ]
            },
        }
    )
    body = get_alarm(AlarmInput(alarm_name=ALARM_NAME), tool_ctx)
    assert body["alarm"]["dimensions"] == {"FunctionName": "payment-api-prod"}
    assert body["alarm"]["state_updated"] == WHEN.isoformat()
    assert "AlarmActions" not in body["alarm"]
    assert body["tags"] == {"Severity": "high"}
    assert len(body["history"]) == 10
    assert "HistoryData" not in json.dumps(body)
    history_call = dict(tool_ctx.cloudwatch.calls)["describe_alarm_history"]
    assert history_call["MaxRecords"] == 10


def test_get_alarm_projects_metric_math_and_composite(tool_ctx: ToolContext) -> None:
    composite = {
        "AlarmName": "composite",
        "AlarmArn": "arn:composite",
        "StateValue": "ALARM",
        "AlarmRule": 'ALARM("a") OR ALARM("b")',
    }
    math_alarm = {
        "AlarmName": "math",
        "AlarmArn": "arn:math",
        "Metrics": [
            {"Id": "e1", "Expression": "m1 / 60"},
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {"Namespace": "AWS/SQS", "MetricName": "Age", "Dimensions": []},
                    "Period": 60,
                    "Stat": "Maximum",
                },
            },
        ],
    }
    tool_ctx.cloudwatch.responses["describe_alarms"] = {"CompositeAlarms": [composite]}
    assert (
        get_alarm(AlarmInput(alarm_name="composite"), tool_ctx)["alarm"]["alarm_rule"]
        == composite["AlarmRule"]
    )
    tool_ctx.cloudwatch.responses["describe_alarms"] = {"MetricAlarms": [math_alarm]}
    metrics = get_alarm(AlarmInput(alarm_name="math"), tool_ctx)["alarm"]["metrics"]
    assert metrics == [
        {"id": "e1", "expression": "m1 / 60"},
        {"id": "m1", "namespace": "AWS/SQS", "metric_name": "Age", "stat": "Maximum", "period": 60},
    ]


def test_get_alarm_not_found_is_a_tool_error(tool_ctx: ToolContext) -> None:
    tool_ctx.cloudwatch.responses["describe_alarms"] = {"MetricAlarms": []}
    with pytest.raises(ToolError, match="not found"):
        get_alarm(AlarmInput(alarm_name="missing"), tool_ctx)


def test_get_metric_returns_bounded_ascending_points(tool_ctx: ToolContext) -> None:
    stamps = [datetime(2026, 9, 29, 14, i % 60, tzinfo=UTC) for i in range(250)]
    tool_ctx.cloudwatch.responses["get_metric_data"] = {
        "MetricDataResults": [
            {
                "Id": "m1",
                "StatusCode": "Complete",
                "Timestamps": stamps[::-1],
                "Values": [float(i) for i in range(250)][::-1],
            }
        ]
    }
    body = run_tool(
        "get_metric",
        {
            "namespace": "AWS/Lambda",
            "metric_name": "Errors",
            "dimensions": {"FunctionName": "f"},
            "stat": "Sum",
            "period_seconds": 60,
            "minutes": 360,
        },
        tool_ctx,
    ).content
    assert len(body["points"]) == 200
    assert body["points"][-1]["v"] == 249.0
    call = dict(tool_ctx.cloudwatch.calls)["get_metric_data"]
    assert call["MaxDatapoints"] == 200
    query = call["MetricDataQueries"][0]["MetricStat"]
    assert query["Metric"]["Dimensions"] == [{"Name": "FunctionName", "Value": "f"}]
    assert (call["EndTime"] - call["StartTime"]).total_seconds() == 360 * 60


def test_get_metric_without_results(tool_ctx: ToolContext) -> None:
    tool_ctx.cloudwatch.responses["get_metric_data"] = {"MetricDataResults": []}
    body = run_tool("get_metric", {"namespace": "n", "metric_name": "m"}, tool_ctx).content
    assert body == {"status": "NoData", "window": body["window"], "points": []}


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("get_metric", {"namespace": "n", "metric_name": "m", "minutes": 361}),
        ("get_metric", {"namespace": "n", "metric_name": "m", "period_seconds": 90}),
        ("get_metric", {"namespace": "n", "metric_name": "m", "stat": "Median; drop"}),
        ("query_logs", {"log_group": "g", "query": "fields @message", "minutes": 181}),
        ("recent_changes", {"minutes": 0}),
        ("recent_changes", {"minutes": 181}),
        ("recent_changes", {"minutes": "lots"}),
        ("get_metric", {"namespace": "n", "metric_name": "m", "extra": 1}),
    ],
)
def test_out_of_bounds_input_is_rejected_without_calling_aws(
    tool_ctx: ToolContext, tool: str, tool_input: dict[str, Any]
) -> None:
    result = run_tool(tool, tool_input, tool_ctx)
    assert result.status == "error"
    assert result.content["error"].startswith("invalid input:")
    for name in ToolContext.__dataclass_fields__:
        if name not in ALARM_FIELDS:
            assert getattr(tool_ctx, name).calls == [], name


@pytest.mark.parametrize(
    "query",
    [
        "parse @message 'user=* ' as user",
        "fields @message | PARSE @message /key=(?<k>.*)/",
        "fields substr(@message, 0, 10)",
        "fields Replace(@message, 'a', 'b') as m",
        "fields concat(a, b)",
        "fields trim(@message)",
        "fields ltrim(@message)",
        "fields rtrim(@message)",
        "fields TOUPPER(@message)",
        "fields tolower(@message)",
        "stats count() by strlen (@message)",
        "pattern @message | parse @message 'user=* ' as user",
    ],
)
def test_query_logs_rejects_field_rewriting(tool_ctx: ToolContext, query: str) -> None:
    result = run_tool("query_logs", {"log_group": "g", "query": query}, tool_ctx)
    assert result.status == "error"
    assert result.content["error"].startswith("invalid input: query:")
    assert "not allowed" in result.content["error"]
    assert tool_ctx.logs.calls == []


@pytest.mark.parametrize(
    "query",
    [
        "fields @timestamp, @message | filter @message like /JSON parse error/",
        "stats count() by bin(5m)",
        "fields @message | filter @message like /replacement/",
        "filter @message like /error/ | pattern @message | sort @sampleCount desc | limit 10",
        "pattern @message",
    ],
)
def test_query_logs_accepts_plain_queries(query: str) -> None:
    assert tools.LogsQueryInput(log_group="g", query=query).query == query


def test_every_tool_result_is_redacted(tool_ctx: ToolContext) -> None:
    tool_ctx.cloudtrail.responses["lookup_events"] = {
        "Events": [
            {
                "EventTime": WHEN,
                "EventName": "PutParameter",
                "Username": "ci token=abc123",
                "Resources": [{"ResourceName": "AKIA" + "ABCDEFGHIJKLMNOP"}],
            }
        ]
    }
    body = run_tool("recent_changes", {}, tool_ctx).content
    event = body["events"][0]
    assert event["username"] == f"ci token={REDACTED}"
    assert event["resources"] == [REDACTED]


def test_error_results_are_redacted(tool_ctx: ToolContext) -> None:
    tool_ctx.cloudtrail.responses["lookup_events"] = client_error(
        "InvalidParameterValueException", "bad value password=hunter2"
    )
    result = run_tool("recent_changes", {}, tool_ctx)
    assert result.status == "error"
    assert "hunter2" not in result.content["error"]


def _log_row(i: int) -> list[dict[str, str]]:
    return [
        {"field": "@timestamp", "value": f"2026-09-29 14:0{i % 10}:00"},
        {"field": "@message", "value": f"ERROR password=hunter{i} " + "y" * 900},
        {"field": "@ptr", "value": "CmAKJwoj..."},
    ]


def test_query_logs_caps_rows_and_length_and_redacts(
    tool_ctx: ToolContext, mocker: MockerFixture
) -> None:
    mocker.patch.object(tools.time, "sleep")
    tool_ctx.logs.responses.update(
        {
            "start_query": {"queryId": "q-1"},
            "get_query_results": {
                "status": "Complete",
                "results": [_log_row(i) for i in range(80)],
            },
        }
    )
    body = run_tool(
        "query_logs",
        {"log_group": "/aws/lambda/f", "query": "fields @message", "minutes": 180},
        tool_ctx,
    ).content
    assert body["status"] == "Complete"
    assert body["row_count"] == 50
    row = body["rows"][0]
    assert "@ptr" not in row
    assert len(row["@message"]) == 500
    assert row["@message"].startswith(f"ERROR password={REDACTED} ")
    assert "hunter" not in json.dumps(body)
    start = dict(tool_ctx.logs.calls)["start_query"]
    assert start["limit"] == 50
    assert start["endTime"] - start["startTime"] == 180 * 60


def test_query_logs_stops_query_after_poll_budget(
    tool_ctx: ToolContext, mocker: MockerFixture
) -> None:
    mocker.patch.object(tools.time, "sleep")
    mocker.patch.object(tools.time, "monotonic", side_effect=[0.0, 5.0, 21.0])
    tool_ctx.logs.responses.update(
        {
            "start_query": {"queryId": "q-1"},
            "get_query_results": {"status": "Running", "results": [_log_row(1)]},
            "stop_query": client_error("InvalidParameterException"),
        }
    )
    body = run_tool(
        "query_logs", {"log_group": "/aws/lambda/f", "query": "fields @message"}, tool_ctx
    ).content
    assert body["status"] == "Stopped"
    assert body["row_count"] == 1
    assert tool_ctx.logs.operations() == [
        "start_query",
        "get_query_results",
        "get_query_results",
        "stop_query",
    ]


def test_recent_changes_projects_events_without_raw_json(tool_ctx: ToolContext) -> None:
    raw = json.dumps({"requestParameters": {"secret": "do-not-leak"}})
    tool_ctx.cloudtrail.responses["lookup_events"] = {
        "Events": [
            {
                "EventId": "e1",
                "EventName": "UpdateFunctionCode",
                "EventTime": WHEN,
                "EventSource": "lambda.amazonaws.com",
                "Username": "deployer",
                "Resources": [
                    {"ResourceType": "AWS::Lambda::Function", "ResourceName": "fn"},
                    {"ResourceType": "AWS::IAM::Role"},
                ],
                "CloudTrailEvent": raw,
            }
        ],
        "NextToken": "more",
    }
    body = run_tool("recent_changes", {"minutes": 120}, tool_ctx).content
    assert body["truncated"] is True
    assert body["events"] == [
        {
            "time": WHEN.isoformat(),
            "event_name": "UpdateFunctionCode",
            "event_source": "lambda.amazonaws.com",
            "username": "deployer",
            "resources": ["fn"],
        }
    ]
    assert "do-not-leak" not in json.dumps(body)
    call = dict(tool_ctx.cloudtrail.calls)["lookup_events"]
    assert call["LookupAttributes"] == [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}]
    assert call["MaxResults"] == 50


def test_client_error_becomes_error_result(tool_ctx: ToolContext) -> None:
    tool_ctx.cloudtrail.responses["lookup_events"] = client_error(
        "AccessDeniedException", "not authorized"
    )
    result = run_tool("recent_changes", {}, tool_ctx)
    assert result.status == "error"
    assert result.content == {"error": "AccessDeniedException: not authorized"}


def test_unexpected_exception_becomes_error_result(tool_ctx: ToolContext) -> None:
    tool_ctx.cloudtrail.responses["lookup_events"] = RuntimeError("socket closed")
    result = run_tool("recent_changes", {}, tool_ctx)
    assert result.status == "error"
    assert result.content == {"error": "RuntimeError: socket closed"}


def test_unknown_tool_is_an_error_result(tool_ctx: ToolContext) -> None:
    result = run_tool("delete_alarm", {"alarm_name": ALARM_NAME}, tool_ctx)
    assert result.status == "error"
    assert "unknown tool" in result.content["error"]


def _operations_called_in_source() -> set[str]:
    """Every method called on a client in tools.py: ctx.<client>.<operation>(...), or
    <client>.<operation>(...) in a helper that takes the client itself."""
    source = Path(tools.__file__).read_text()
    clients = {field.name for field in dataclasses.fields(ToolContext)} - ALARM_FIELDS
    operations = set()
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        client = node.func.value
        on_context = (
            isinstance(client, ast.Attribute)
            and isinstance(client.value, ast.Name)
            and client.value.id == "ctx"
        )
        on_client = isinstance(client, ast.Name) and client.id in clients
        if on_context or on_client:
            operations.add(node.func.attr)
    return operations


def test_tools_call_exactly_the_read_only_allowlist() -> None:
    assert _operations_called_in_source() == READ_ONLY_OPERATIONS
    assert {
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
    } == READ_ONLY_OPERATIONS


# Each of these returns secret material or payload data: function environment variables,
# container definitions, queue messages, stream records, execution inputs and outputs.
FORBIDDEN_OPERATIONS = (
    "get_function",
    "get_function_configuration",
    "list_functions",
    "describe_task_definition",
    "receive_message",
    "get_records",
    "get_shard_iterator",
    "describe_execution",
    "get_execution_history",
    "get_secret_value",
    "batch_get_secret_value",
    "get_parameter",
    "get_parameters",
    "get_parameters_by_path",
    "get_parameter_history",
    "get_object",
    "head_object",
    "select_object_content",
)


@pytest.mark.parametrize("operation", FORBIDDEN_OPERATIONS)
def test_tools_never_call_an_operation_that_reads_secrets_or_payloads(operation: str) -> None:
    source = Path(tools.__file__).read_text()
    assert operation not in READ_ONLY_OPERATIONS
    assert operation not in _operations_called_in_source()
    assert f".{operation}(" not in source


def test_tool_context_has_no_secret_store_clients() -> None:
    fields = set(ToolContext.__dataclass_fields__)
    assert not fields & {"secretsmanager", "ssm", "kms", "ecs"}
    assert "secretsmanager" not in Path(tools.__file__).read_text()


def test_registry_holds_only_read_tools() -> None:
    assert {tool.name for tool in READ_ONLY_TOOLS} == {
        "get_metric",
        "query_logs",
        "recent_changes",
        "describe_s3_key",
        "describe_database",
        "describe_search_domain",
        "describe_targets",
        "recent_executions",
        "scheduled_jobs",
        "search_datadog_logs",
        "datadog_events",
        "datadog_top_pods",
        "github_list_repos",
        "github_search_code",
        "github_get_file",
        "github_recent_changes",
        "github_get_change",
        "aws_call",
    }


def test_tools_build_no_clients_of_their_own() -> None:
    tree = ast.parse(Path(tools.__file__).read_text())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "boto3" not in imported


def test_recorded_calls_stay_inside_allowlist(tool_ctx: ToolContext, mocker: MockerFixture) -> None:
    mocker.patch.object(tools.time, "sleep")
    mocker.patch.object(tools.time, "monotonic", side_effect=[0.0, 100.0])
    tool_ctx.cloudwatch.responses.update(
        {"describe_alarms": {"MetricAlarms": [METRIC_ALARM]}, "get_metric_data": {}}
    )
    tool_ctx.logs.responses.update(
        {"start_query": {"queryId": "q"}, "get_query_results": {"status": "Running"}}
    )
    tool_ctx.sqs.responses.update(
        {
            "get_queue_url": {"QueueUrl": "u"},
            "get_queue_attributes": {"Attributes": {"QueueArn": "arn:q"}},
        }
    )
    tool_ctx.kinesis.responses["describe_stream_summary"] = {
        "StreamDescriptionSummary": {"StreamARN": "arn:stream"}
    }
    tool_ctx.rds.responses.update(
        {
            "describe_db_clusters": {
                "DBClusters": [
                    {"DBClusterMembers": [{"DBInstanceIdentifier": "w", "IsClusterWriter": True}]}
                ]
            },
            "describe_db_instances": {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "w",
                        "PerformanceInsightsEnabled": True,
                        "DbiResourceId": "db-W",
                    }
                ]
            },
        }
    )
    tool_ctx.opensearch.responses["describe_domain"] = {"DomainStatus": {}}
    tool_ctx.elbv2.responses.update(
        {
            "describe_load_balancers": {"LoadBalancers": [{"LoadBalancerArn": "arn:lb"}]},
            "describe_target_groups": {"TargetGroups": [{"TargetGroupArn": "arn:tg"}]},
        }
    )
    tool_ctx.elasticache.responses.update(
        {
            "describe_cache_clusters": {"CacheClusters": [{"ReplicationGroupId": "redis"}]},
            "describe_replication_groups": {"ReplicationGroups": [{}]},
        }
    )
    tool_ctx.ec2.responses["describe_instances"] = {
        "Reservations": [{"Instances": [{"InstanceId": "i-0123456789abcdef0"}]}]
    }
    tool_ctx.stepfunctions.responses["list_state_machines"] = {
        "stateMachines": [{"name": "m", "stateMachineArn": "arn:m"}]
    }
    tool_ctx.github.responses["get_contents"] = {
        "type": "file",
        "size": 4,
        "encoding": "base64",
        "content": "eD0xCg==",
    }
    tool_ctx.events.responses["list_rules"] = {
        "Rules": [{"Name": "nightly", "ScheduleExpression": "rate(5 minutes)", "State": "ENABLED"}]
    }
    tool_ctx.scheduler.responses["list_schedules"] = {"Schedules": [{"Name": "export"}]}
    source_alarms = {
        "AWS/Lambda": [],
        "AWS/SQS": [{"Name": "QueueName", "Value": "q"}],
        "AWS/Kinesis": [{"Name": "StreamName", "Value": "s"}],
        "AWS/States": [{"Name": "StateMachineArn", "Value": "arn:m"}],
        "AWS/ApiGateway": [{"Name": "ApiId", "Value": "a"}],
        "AWS/ES": [{"Name": "DomainName", "Value": "d"}],
        "AWS/ElastiCache": [{"Name": "CacheClusterId", "Value": "redis-0001"}],
    }
    get_alarm(AlarmInput(alarm_name=ALARM_NAME), tool_ctx)
    describe_instance(InstanceInput(instance_id="i-0123456789abcdef0"), tool_ctx)
    inputs: list[tuple[str, dict[str, Any]]] = [
        ("get_metric", {"namespace": "n", "metric_name": "m"}),
        ("query_logs", {"log_group": "g", "query": "fields @message"}),
        ("recent_changes", {}),
        ("describe_s3_key", {"bucket": "drops", "key": "a/b.xml"}),
        ("describe_database", {"identifier": "core"}),
        ("describe_search_domain", {"domain_name": "search"}),
        ("describe_targets", {"load_balancer_name": "front"}),
        ("recent_executions", {"state_machine_name": "m"}),
        ("scheduled_jobs", {"hours": 24}),
        ("search_datadog_logs", {"service": "checkout-api-prod"}),
        ("datadog_events", {"kube_namespace": "checkout"}),
        ("datadog_top_pods", {"host": "i-0123456789abcdef0"}),
        ("github_list_repos", {}),
        ("github_search_code", {"query": "proxy error"}),
        ("github_get_file", {"repo": "chat-lambda", "path": "handler.py"}),
        ("github_recent_changes", {"repo": "chat-lambda"}),
        ("github_get_change", {"repo": "chat-lambda", "sha": "abc1234"}),
        ("github_get_change", {"repo": "chat-lambda", "number": 7}),
        ("search_datadog_logs", {}),
    ]
    for name, tool_input in inputs:
        assert run_tool(name, tool_input, tool_ctx).status == "success", name
    for namespace, dimensions in source_alarms.items():
        alarm = {**METRIC_ALARM, "Namespace": namespace, "Dimensions": dimensions}
        tool_ctx.cloudwatch.responses["describe_alarms"] = {"MetricAlarms": [alarm]}
        find_log_sources(AlarmInput(alarm_name=ALARM_NAME), tool_ctx)
    called = {
        operation
        for name in ToolContext.__dataclass_fields__
        if name not in ALARM_FIELDS
        for operation in getattr(tool_ctx, name).operations()
    }
    assert called == READ_ONLY_OPERATIONS
    assert isinstance(tool_ctx.cloudwatch, FakeClient)


# EKS


def _eks_alarm(**dimensions: str) -> dict[str, Any]:
    return {
        **METRIC_ALARM,
        "Namespace": "AWS/EKS",
        "MetricName": "apiserver_request_total_5XX",
        "Dimensions": [{"Name": name, "Value": value} for name, value in dimensions.items()],
    }


def test_eks_alarm_is_keyed_by_cluster() -> None:
    alarm = _eks_alarm(ClusterName="checkout", Verb="GET")
    assert tools.primary_key(alarm) == (
        "AWS/EKS:ClusterName=checkout",
        "AWS/EKS",
        {"ClusterName": "checkout", "Verb": "GET"},
    )


def test_container_insights_alarm_is_keyed_by_cluster() -> None:
    alarm = {
        **METRIC_ALARM,
        "Namespace": "ContainerInsights",
        "Dimensions": [
            {"Name": "Namespace", "Value": "checkout"},
            {"Name": "ClusterName", "Value": "checkout"},
        ],
    }
    key = tools.primary_key(alarm)
    assert key is not None
    assert key[0] == "ContainerInsights:ClusterName=checkout"


def test_eks_alarm_maps_to_control_plane_logs(tool_ctx: ToolContext) -> None:
    tool_ctx.cloudwatch.responses["describe_alarms"] = {
        "MetricAlarms": [_eks_alarm(ClusterName="checkout")]
    }
    tool_ctx.logs.responses["describe_log_groups"] = {
        "logGroups": [
            {"logGroupName": "/aws/eks/checkout/cluster"},
            {"logGroupName": "/aws/eks/checkout/cluster-old"},
        ]
    }
    body = find_log_sources(AlarmInput(alarm_name=ALARM_NAME), tool_ctx)
    assert body["sources"] == [
        {"log_group": "/aws/eks/checkout/cluster", "why": "EKS cluster checkout control plane"}
    ]
    assert tool_ctx.logs.calls[0][1]["logGroupNamePrefix"] == "/aws/eks/checkout/cluster"


# EC2

NODE_ID = "i-0123456789abcdef0"


def _instances(tags: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": NODE_ID,
                        "InstanceType": "t3.medium",
                        "State": {"Code": 16, "Name": "running"},
                        "LaunchTime": WHEN,
                        "PrivateIpAddress": "10.0.1.2",
                        "IamInstanceProfile": {"Arn": "arn:aws:iam::1:instance-profile/node"},
                        "Tags": tags,
                    }
                ]
            }
        ]
    }


EKS_NODE_TAGS = [
    {"Key": "Name", "Value": "main-br-node"},
    {"Key": "aws:autoscaling:groupName", "Value": "eks-main-br-1234"},
    {"Key": "eks:cluster-name", "Value": "acme-prod"},
    {"Key": "eks:nodegroup-name", "Value": "main-br"},
    {"Key": "kubernetes.io/cluster/acme-prod", "Value": "owned"},
    {"Key": "team", "Value": "platform"},
]


def test_ec2_alarm_is_keyed_by_instance() -> None:
    alarm = {
        **METRIC_ALARM,
        "Namespace": "AWS/EC2",
        "Dimensions": [
            {"Name": "AutoScalingGroupName", "Value": "eks-main-br-1234"},
            {"Name": "InstanceId", "Value": NODE_ID},
        ],
    }
    key = tools.primary_key(alarm)
    assert key is not None
    assert key[0] == f"AWS/EC2:InstanceId={NODE_ID}"


def test_describe_instance_projects_an_eks_node(tool_ctx: ToolContext) -> None:
    tool_ctx.ec2.responses["describe_instances"] = _instances(EKS_NODE_TAGS)
    assert describe_instance(InstanceInput(instance_id=NODE_ID), tool_ctx) == {
        "instance_id": NODE_ID,
        "instance_type": "t3.medium",
        "state": "running",
        "launch_time": WHEN.isoformat(),
        "name": "main-br-node",
        "asg": "eks-main-br-1234",
        "eks_cluster": "acme-prod",
        "eks_nodegroup": "main-br",
    }
    assert tool_ctx.ec2.calls == [("describe_instances", {"InstanceIds": [NODE_ID]})]


def test_describe_instance_reads_the_aws_eks_cluster_tag(tool_ctx: ToolContext) -> None:
    tags = [
        {"Key": "aws:eks:cluster-name", "Value": "checkout"},
        {"Key": "eks:nodegroup-name", "Value": "general"},
    ]
    tool_ctx.ec2.responses["describe_instances"] = _instances(tags)
    instance = describe_instance(InstanceInput(instance_id=NODE_ID), tool_ctx)
    assert instance["eks_cluster"] == "checkout"
    assert instance["eks_nodegroup"] == "general"


def test_describe_instance_of_a_plain_instance_has_no_eks_fields(tool_ctx: ToolContext) -> None:
    tags = [
        {"Key": "Name", "Value": "bastion"},
        {"Key": "eks:nodegroup-name", "Value": "stray"},
    ]
    tool_ctx.ec2.responses["describe_instances"] = _instances(tags)
    instance = describe_instance(InstanceInput(instance_id=NODE_ID), tool_ctx)
    assert instance["name"] == "bastion"
    assert "eks_cluster" not in instance
    assert "eks_nodegroup" not in instance
    assert "asg" not in instance


def test_describe_instance_not_found(tool_ctx: ToolContext) -> None:
    tool_ctx.ec2.responses["describe_instances"] = client_error("InvalidInstanceID.NotFound")
    with pytest.raises(ToolError, match=f"^instance {NODE_ID!r} not found$"):
        describe_instance(InstanceInput(instance_id=NODE_ID), tool_ctx)


def test_describe_instance_with_no_reservations_is_not_found(tool_ctx: ToolContext) -> None:
    tool_ctx.ec2.responses["describe_instances"] = {"Reservations": []}
    with pytest.raises(ToolError, match=f"^instance {NODE_ID!r} not found$"):
        describe_instance(InstanceInput(instance_id=NODE_ID), tool_ctx)


@pytest.mark.parametrize(
    "instance_id",
    [
        "",
        "i-123",
        "i-07AC21C137D6B4AB9",
        "i-0123456789abcdef0a",
        "07ac21c137d6b4ab9",
        "i-*",
        "i-01234567 ",
    ],
)
def test_instance_input_rejects_a_malformed_id(instance_id: str) -> None:
    with pytest.raises(ValidationError):
        InstanceInput(instance_id=instance_id)
