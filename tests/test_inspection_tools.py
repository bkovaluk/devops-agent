"""Log-source mapping and resource inspection tools: projections, bounds and errors."""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from devops_agent.redact import REDACTED
from devops_agent.tools import (
    AlarmInput,
    ToolContext,
    ToolError,
    find_log_sources,
    parse_cron,
    run_tool,
    schedule_firing,
)
from tests.conftest import ALARM_FIELDS, ALARM_NAME, client_error

WHEN = datetime(2026, 9, 29, 14, 0, tzinfo=UTC)
QUEUE_ARN = "arn:aws:sqs:us-east-1:111122223333:orders"
STREAM_ARN = "arn:aws:kinesis:us-east-1:111122223333:stream/events"
STATE_MACHINE_ARN = "arn:aws:states:us-east-1:111122223333:stateMachine:ingest"


def _log_group_arn(name: str) -> str:
    return f"arn:aws:logs:us-east-1:111122223333:log-group:{name}:*"


def _metric_alarm(namespace: str, **dimensions: str) -> dict[str, Any]:
    return {
        "AlarmName": ALARM_NAME,
        "AlarmArn": "arn:alarm",
        "Namespace": namespace,
        "MetricName": "Errors",
        "Dimensions": [{"Name": name, "Value": value} for name, value in dimensions.items()],
    }


def _existing_groups(*names: str) -> Any:
    def describe_log_groups(**kwargs: Any) -> dict[str, Any]:
        prefix = kwargs["logGroupNamePrefix"]
        matches = sorted(name for name in names if name.startswith(prefix))
        return {"logGroups": [{"logGroupName": name} for name in matches[: kwargs["limit"]]]}

    return describe_log_groups


def _find(tool_ctx: ToolContext, alarm: dict[str, Any], *groups: str) -> dict[str, Any]:
    tool_ctx.cloudwatch.responses["describe_alarms"] = {"MetricAlarms": [alarm]}
    tool_ctx.logs.responses["describe_log_groups"] = _existing_groups(*groups)
    return find_log_sources(AlarmInput(alarm_name=ALARM_NAME), tool_ctx)


def _mapping(function: str, **extra: Any) -> dict[str, Any]:
    return {
        "UUID": "u-1",
        "FunctionArn": f"arn:aws:lambda:us-east-1:111122223333:function:{function}",
        "State": "Enabled",
        "BatchSize": 10,
        "LastProcessingResult": "OK",
        "SourceAccessConfigurations": [{"Type": "BASIC_AUTH", "URI": "arn:secret"}],
        **extra,
    }


# find_log_sources


def test_lambda_alarm_maps_to_its_log_group(tool_ctx: ToolContext) -> None:
    body = _find(
        tool_ctx,
        _metric_alarm("AWS/Lambda", FunctionName="pay"),
        "/aws/lambda/pay",
        "/aws/lambda/pay-worker",
    )
    assert body == {"sources": [{"log_group": "/aws/lambda/pay", "why": "Lambda function pay"}]}
    call = dict(tool_ctx.logs.calls)["describe_log_groups"]
    assert call == {"logGroupNamePrefix": "/aws/lambda/pay", "limit": 10}


@pytest.mark.parametrize(
    ("dimension", "prefix", "why"),
    [
        ("DBClusterIdentifier", "/aws/rds/cluster/core/", "RDS cluster core"),
        ("DBInstanceIdentifier", "/aws/rds/instance/core/", "RDS instance core"),
    ],
)
def test_rds_alarm_maps_to_every_log_under_the_database(
    tool_ctx: ToolContext, dimension: str, prefix: str, why: str
) -> None:
    body = _find(
        tool_ctx,
        _metric_alarm("AWS/RDS", **{dimension: "core"}),
        f"{prefix}error",
        f"{prefix}slowquery",
        "/aws/rds/cluster/core-replica/error",
    )
    assert body["sources"] == [
        {"log_group": f"{prefix}error", "why": why},
        {"log_group": f"{prefix}slowquery", "why": why},
    ]


def test_docdb_alarm_maps_to_cluster_logs(tool_ctx: ToolContext) -> None:
    body = _find(
        tool_ctx,
        _metric_alarm("AWS/DocDB", DBClusterIdentifier="docs"),
        "/aws/docdb/docs/audit",
        "/aws/docdb/docs/profiler",
    )
    assert [source["log_group"] for source in body["sources"]] == [
        "/aws/docdb/docs/audit",
        "/aws/docdb/docs/profiler",
    ]


def test_search_domain_alarm_maps_to_published_logs(tool_ctx: ToolContext) -> None:
    tool_ctx.opensearch.responses["describe_domain"] = {
        "DomainStatus": {
            "DomainName": "search",
            "LogPublishingOptions": {
                "ES_APPLICATION_LOGS": {
                    "Enabled": True,
                    "CloudWatchLogsLogGroupArn": _log_group_arn("/aws/opensearch/search/app"),
                },
                "SEARCH_SLOW_LOGS": {
                    "Enabled": False,
                    "CloudWatchLogsLogGroupArn": _log_group_arn("/aws/opensearch/search/slow"),
                },
            },
        }
    }
    body = _find(
        tool_ctx,
        _metric_alarm("AWS/ES", DomainName="search", ClientId="111122223333"),
        "/aws/opensearch/search/app",
        "/aws/opensearch/search/slow",
    )
    assert body["sources"] == [
        {
            "log_group": "/aws/opensearch/search/app",
            "why": "OpenSearch domain search ES_APPLICATION_LOGS",
        }
    ]


def _cache_log_delivery(group: str) -> list[dict[str, Any]]:
    return [
        {
            "LogType": "slow-log",
            "DestinationType": "cloudwatch-logs",
            "DestinationDetails": {"CloudWatchLogsDetails": {"LogGroup": group}},
            "Status": "active",
        },
        {
            "LogType": "engine-log",
            "DestinationType": "kinesis-firehose",
            "DestinationDetails": {"KinesisFirehoseDetails": {"DeliveryStream": "fh"}},
        },
    ]


def test_cache_cluster_alarm_maps_through_its_replication_group(tool_ctx: ToolContext) -> None:
    tool_ctx.elasticache.responses.update(
        {
            "describe_cache_clusters": {
                "CacheClusters": [
                    {"CacheClusterId": "redis-0001-001", "ReplicationGroupId": "redis"}
                ]
            },
            "describe_replication_groups": {
                "ReplicationGroups": [
                    {"LogDeliveryConfigurations": _cache_log_delivery("/redis/slow")}
                ]
            },
        }
    )
    body = _find(
        tool_ctx, _metric_alarm("AWS/ElastiCache", CacheClusterId="redis-0001-001"), "/redis/slow"
    )
    assert body["sources"] == [
        {"log_group": "/redis/slow", "why": "ElastiCache replication group redis slow-log"}
    ]
    assert dict(tool_ctx.elasticache.calls)["describe_replication_groups"] == {
        "ReplicationGroupId": "redis"
    }


def test_standalone_cache_cluster_uses_its_own_log_delivery(tool_ctx: ToolContext) -> None:
    tool_ctx.elasticache.responses["describe_cache_clusters"] = {
        "CacheClusters": [{"LogDeliveryConfigurations": _cache_log_delivery("/memcached/slow")}]
    }
    body = _find(tool_ctx, _metric_alarm("AWS/ElastiCache", CacheClusterId="mc"), "/memcached/slow")
    assert body["sources"] == [
        {"log_group": "/memcached/slow", "why": "ElastiCache cluster mc slow-log"}
    ]
    assert "describe_replication_groups" not in tool_ctx.elasticache.operations()


def test_replication_group_alarm_maps_to_log_delivery(tool_ctx: ToolContext) -> None:
    tool_ctx.elasticache.responses["describe_replication_groups"] = {
        "ReplicationGroups": [{"LogDeliveryConfigurations": _cache_log_delivery("/redis/slow")}]
    }
    body = _find(
        tool_ctx, _metric_alarm("AWS/ElastiCache", ReplicationGroupId="redis"), "/redis/slow"
    )
    assert [source["log_group"] for source in body["sources"]] == ["/redis/slow"]
    assert "describe_cache_clusters" not in tool_ctx.elasticache.operations()


def test_state_machine_alarm_maps_to_logging_destination(tool_ctx: ToolContext) -> None:
    tool_ctx.stepfunctions.responses["describe_state_machine"] = {
        "definition": '{"secret": "never returned"}',
        "loggingConfiguration": {
            "level": "ERROR",
            "destinations": [
                {"cloudWatchLogsLogGroup": {"logGroupArn": _log_group_arn("/sfn/ingest")}}
            ],
        },
    }
    body = _find(
        tool_ctx, _metric_alarm("AWS/States", StateMachineArn=STATE_MACHINE_ARN), "/sfn/ingest"
    )
    assert body["sources"] == [
        {"log_group": "/sfn/ingest", "why": "Step Functions state machine ingest (level ERROR)"}
    ]
    assert "never returned" not in json.dumps(body)


def test_api_alarm_maps_to_api_groups_and_stage_access_logs(tool_ctx: ToolContext) -> None:
    tool_ctx.apigatewayv2.responses["get_stages"] = {
        "Items": [
            {
                "StageName": "prod",
                "AccessLogSettings": {"DestinationArn": _log_group_arn("/access/api1")},
            },
            {"StageName": "$default"},
        ]
    }
    body = _find(
        tool_ctx,
        _metric_alarm("AWS/ApiGateway", ApiId="api1", Stage="prod"),
        "/aws/apigateway/api1/prod",
        "/access/api1",
    )
    assert body["sources"] == [
        {"log_group": "/aws/apigateway/api1/prod", "why": "API api1"},
        {"log_group": "/access/api1", "why": "API api1 stage prod access log"},
    ]
    assert dict(tool_ctx.apigatewayv2.calls)["get_stages"] == {"ApiId": "api1", "MaxResults": "10"}


def test_queue_alarm_maps_to_consumer_lambdas(tool_ctx: ToolContext) -> None:
    tool_ctx.sqs.responses.update(
        {
            "get_queue_url": {"QueueUrl": "https://sqs/orders"},
            "get_queue_attributes": {"Attributes": {"QueueArn": QUEUE_ARN}},
        }
    )
    tool_ctx.lambda_.responses["list_event_source_mappings"] = {
        "EventSourceMappings": [_mapping("order-worker")]
    }
    body = _find(tool_ctx, _metric_alarm("AWS/SQS", QueueName="orders"), "/aws/lambda/order-worker")
    assert body["sources"] == [
        {
            "log_group": "/aws/lambda/order-worker",
            "why": "Lambda function order-worker consumes queue orders",
        }
    ]
    assert dict(tool_ctx.sqs.calls)["get_queue_attributes"]["AttributeNames"] == ["QueueArn"]
    assert dict(tool_ctx.lambda_.calls)["list_event_source_mappings"] == {
        "EventSourceArn": QUEUE_ARN,
        "MaxItems": 10,
    }


def test_stream_alarm_maps_to_consumer_lambdas(tool_ctx: ToolContext) -> None:
    tool_ctx.kinesis.responses["describe_stream_summary"] = {
        "StreamDescriptionSummary": {"StreamName": "events", "StreamARN": STREAM_ARN}
    }
    tool_ctx.lambda_.responses["list_event_source_mappings"] = {
        "EventSourceMappings": [_mapping("ingest:live")]
    }
    body = _find(tool_ctx, _metric_alarm("AWS/Kinesis", StreamName="events"), "/aws/lambda/ingest")
    assert body["sources"] == [
        {"log_group": "/aws/lambda/ingest", "why": "Lambda function ingest consumes stream events"}
    ]


def test_sagemaker_alarm_maps_to_endpoint_logs(tool_ctx: ToolContext) -> None:
    body = _find(
        tool_ctx,
        _metric_alarm("AWS/SageMaker", EndpointName="embed", VariantName="AllTraffic"),
        "/aws/sagemaker/Endpoints/embed",
    )
    assert body["sources"] == [
        {"log_group": "/aws/sagemaker/Endpoints/embed", "why": "SageMaker endpoint embed"}
    ]


def test_metric_math_alarm_maps_each_metric(tool_ctx: ToolContext) -> None:
    alarm = {
        "AlarmName": ALARM_NAME,
        "AlarmArn": "arn:alarm",
        "Metrics": [
            {"Id": "e1", "Expression": "m1 + m2"},
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/Lambda",
                        "MetricName": "Errors",
                        "Dimensions": [{"Name": "FunctionName", "Value": "a"}],
                    }
                },
            },
            {
                "Id": "m2",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/Lambda",
                        "MetricName": "Errors",
                        "Dimensions": [{"Name": "FunctionName", "Value": "b"}],
                    }
                },
            },
        ],
    }
    body = _find(tool_ctx, alarm, "/aws/lambda/a", "/aws/lambda/b")
    assert [source["log_group"] for source in body["sources"]] == ["/aws/lambda/a", "/aws/lambda/b"]


def test_sources_are_capped_at_ten(tool_ctx: ToolContext) -> None:
    groups = [f"/aws/rds/cluster/core/log{i:02}" for i in range(15)]
    body = _find(tool_ctx, _metric_alarm("AWS/RDS", DBClusterIdentifier="core"), *groups)
    assert len(body["sources"]) == 10


@pytest.mark.parametrize(
    ("alarm", "reason"),
    [
        (_metric_alarm("Custom/Payments", Service="pay"), "Custom/Payments has no log-source"),
        (_metric_alarm("AWS/Lambda"), "no AWS/Lambda dimension names a resource"),
        (_metric_alarm("AWS/Lambda", FunctionName="gone"), "no log group /aws/lambda/gone"),
        (
            _metric_alarm("AWS/RDS", DBClusterIdentifier="gone"),
            "no log group /aws/rds/cluster/gone/*",
        ),
        (
            {"AlarmName": ALARM_NAME, "AlarmArn": "a", "Metrics": [{"Id": "q", "Expression": "x"}]},
            "the alarm watches no metric",
        ),
    ],
)
def test_unmapped_alarm_returns_empty_sources_with_reason(
    tool_ctx: ToolContext, alarm: dict[str, Any], reason: str
) -> None:
    body = _find(tool_ctx, alarm)
    assert body["sources"] == []
    assert reason in body["unmapped_reason"]


def test_composite_alarm_is_unmapped(tool_ctx: ToolContext) -> None:
    tool_ctx.cloudwatch.responses["describe_alarms"] = {
        "CompositeAlarms": [{"AlarmName": ALARM_NAME, "AlarmRule": 'ALARM("a")'}]
    }
    body = find_log_sources(AlarmInput(alarm_name=ALARM_NAME), tool_ctx)
    assert body["sources"] == []
    assert "composite alarm" in body["unmapped_reason"]
    assert tool_ctx.logs.calls == []


def test_find_log_sources_for_missing_alarm_is_an_error(tool_ctx: ToolContext) -> None:
    tool_ctx.cloudwatch.responses["describe_alarms"] = {"MetricAlarms": []}
    with pytest.raises(ToolError, match=r"^alarm 'missing' not found$"):
        find_log_sources(AlarmInput(alarm_name="missing"), tool_ctx)


def test_find_log_sources_for_missing_queue_is_an_error(tool_ctx: ToolContext) -> None:
    tool_ctx.cloudwatch.responses["describe_alarms"] = {
        "MetricAlarms": [_metric_alarm("AWS/SQS", QueueName="gone")]
    }
    tool_ctx.sqs.responses["get_queue_url"] = client_error(
        "AWS.SimpleQueueService.NonExistentQueue"
    )
    with pytest.raises(ToolError, match=r"^queue 'gone' not found$"):
        find_log_sources(AlarmInput(alarm_name=ALARM_NAME), tool_ctx)


# describe_s3_key

DROP_KEY = "drops/2026/09/29/report.XHTML"


def _s3_responses(
    tool_ctx: ToolContext,
    *,
    status: str | None = "Enabled",
    versions: list[dict[str, Any]] | None = None,
    markers: list[dict[str, Any]] | None = None,
    siblings: list[str] | None = None,
) -> None:
    tool_ctx.s3.responses.update(
        {
            "get_bucket_versioning": {"Status": status} if status else {},
            "list_object_versions": {
                "Versions": versions or [],
                "DeleteMarkers": markers or [],
                "IsTruncated": False,
            },
            "list_objects_v2": {"Contents": [{"Key": key} for key in siblings or []]},
        }
    )


def _version(key: str, minute: int, latest: bool = False, **extra: Any) -> dict[str, Any]:
    return {
        "Key": key,
        "VersionId": f"v{minute}",
        "IsLatest": latest,
        "LastModified": WHEN.replace(minute=minute),
        **extra,
    }


def test_a_key_that_never_existed_still_returned_data(tool_ctx: ToolContext) -> None:
    from devops_agent.agent import run_read_tool

    _s3_responses(tool_ctx)
    reply = run_read_tool("describe_s3_key", {"bucket": "drops", "key": DROP_KEY}, tool_ctx)
    assert reply.status == "success"
    assert reply.returned_data


def test_describe_s3_key_exists_with_history(tool_ctx: ToolContext) -> None:
    _s3_responses(
        tool_ctx,
        versions=[
            _version(DROP_KEY, 30, latest=True, Size=2048, StorageClass="STANDARD"),
            _version(DROP_KEY, 10, Size=1024, StorageClass="STANDARD"),
        ],
        siblings=[DROP_KEY],
    )
    body = run_tool("describe_s3_key", {"bucket": "drops", "key": DROP_KEY}, tool_ctx).content
    assert body == {
        "bucket": "drops",
        "key": DROP_KEY,
        "versioning": "Enabled",
        "exists": True,
        "versions": [
            {
                "last_modified": WHEN.replace(minute=30).isoformat(),
                "size": 2048,
                "is_latest": True,
                "storage_class": "STANDARD",
            },
            {
                "last_modified": WHEN.replace(minute=10).isoformat(),
                "size": 1024,
                "is_latest": False,
                "storage_class": "STANDARD",
            },
        ],
        "similar_keys": [],
    }
    assert tool_ctx.s3.calls == [
        ("get_bucket_versioning", {"Bucket": "drops"}),
        ("list_object_versions", {"Bucket": "drops", "Prefix": DROP_KEY, "MaxKeys": 20}),
        (
            "list_objects_v2",
            {"Bucket": "drops", "Prefix": "drops/2026/09/29/report", "MaxKeys": 11},
        ),
    ]


def test_describe_s3_key_never_existed_surfaces_similar_key(tool_ctx: ToolContext) -> None:
    _s3_responses(tool_ctx, siblings=["drops/2026/09/29/report.XML"])
    body = run_tool("describe_s3_key", {"bucket": "drops", "key": DROP_KEY}, tool_ctx).content
    assert body == {
        "bucket": "drops",
        "key": DROP_KEY,
        "versioning": "Enabled",
        "exists": False,
        "versions": [],
        "similar_keys": ["drops/2026/09/29/report.XML"],
        "note": (
            "No versions or delete markers: the key most likely never existed "
            "(a lifecycle rule can expire both)"
        ),
    }


def test_describe_s3_key_latest_delete_marker_does_not_exist(tool_ctx: ToolContext) -> None:
    _s3_responses(
        tool_ctx,
        versions=[_version(DROP_KEY, 10, Size=1024, StorageClass="STANDARD")],
        markers=[_version(DROP_KEY, 40, latest=True)],
    )
    body = run_tool("describe_s3_key", {"bucket": "drops", "key": DROP_KEY}, tool_ctx).content
    assert body["exists"] is False
    assert body["versions"] == [
        {
            "last_modified": WHEN.replace(minute=40).isoformat(),
            "is_latest": True,
            "delete_marker": True,
        },
        {
            "last_modified": WHEN.replace(minute=10).isoformat(),
            "size": 1024,
            "is_latest": False,
            "storage_class": "STANDARD",
        },
    ]
    assert "note" not in body


def test_describe_s3_key_unversioned_bucket_cannot_tell_deleted(tool_ctx: ToolContext) -> None:
    _s3_responses(tool_ctx, status=None)
    body = run_tool("describe_s3_key", {"bucket": "drops", "key": DROP_KEY}, tool_ctx).content
    assert body["versioning"] == "Disabled"
    assert body["exists"] is False
    assert body["note"] == (
        "Bucket versioning is not enabled: absence cannot tell a key that never existed "
        "from one that was deleted"
    )


def test_describe_s3_key_excludes_other_keys_sharing_the_prefix(tool_ctx: ToolContext) -> None:
    _s3_responses(
        tool_ctx,
        versions=[
            _version(DROP_KEY, 30, latest=True, Size=10),
            _version(f"{DROP_KEY}.bak", 50, latest=True, Size=20),
        ],
        markers=[_version(f"{DROP_KEY}.old", 45, latest=True)],
        siblings=[DROP_KEY, f"{DROP_KEY}.bak"],
    )
    body = run_tool("describe_s3_key", {"bucket": "drops", "key": DROP_KEY}, tool_ctx).content
    assert body["exists"] is True
    assert body["versions"] == [
        {"last_modified": WHEN.replace(minute=30).isoformat(), "size": 10, "is_latest": True}
    ]
    assert body["similar_keys"] == [f"{DROP_KEY}.bak"]


def test_describe_s3_key_caps_versions_and_flags_truncation(tool_ctx: ToolContext) -> None:
    _s3_responses(
        tool_ctx,
        versions=[_version(DROP_KEY, minute, latest=minute == 59) for minute in range(40, 60)],
    )
    tool_ctx.s3.responses["list_object_versions"].update(
        {"IsTruncated": True, "NextKeyMarker": DROP_KEY}
    )
    body = run_tool("describe_s3_key", {"bucket": "drops", "key": DROP_KEY}, tool_ctx).content
    assert len(body["versions"]) == 10
    assert body["versions"][0]["is_latest"] is True
    assert body["versions_truncated"] is True


def test_describe_s3_key_bucket_not_found(tool_ctx: ToolContext) -> None:
    tool_ctx.s3.responses["get_bucket_versioning"] = client_error("NoSuchBucket")
    result = run_tool("describe_s3_key", {"bucket": "drops", "key": DROP_KEY}, tool_ctx)
    assert result.status == "error"
    assert result.content == {"error": "bucket 'drops' not found"}


def test_describe_s3_key_access_denied_keeps_the_code(tool_ctx: ToolContext) -> None:
    _s3_responses(tool_ctx)
    tool_ctx.s3.responses["list_object_versions"] = client_error("AccessDenied", "no")
    result = run_tool("describe_s3_key", {"bucket": "drops", "key": DROP_KEY}, tool_ctx)
    assert result.content == {"error": "AccessDenied: no"}


# describe_database

CLUSTER = {
    "DBClusterIdentifier": "core",
    "Status": "available",
    "Engine": "aurora-mysql",
    "EngineVersion": "8.0.mysql_aurora.3.08.0",
    "MultiAZ": True,
    "Endpoint": "core.cluster-abc.us-east-1.rds.amazonaws.com",
    "ReaderEndpoint": "core.cluster-ro-abc.us-east-1.rds.amazonaws.com",
    "MasterUsername": "admin",
    "MasterUserSecret": {"SecretArn": "arn:aws:secretsmanager:us-east-1:1:secret:rds"},
    "ServerlessV2ScalingConfiguration": {"MinCapacity": 0.5, "MaxCapacity": 16.0},
    "DBClusterMembers": [
        {"DBInstanceIdentifier": "main-1", "IsClusterWriter": True},
        {"DBInstanceIdentifier": "main-2", "IsClusterWriter": False},
    ],
}


def _instance(identifier: str, *, insights: bool = True) -> dict[str, Any]:
    return {
        "DBInstanceIdentifier": identifier,
        "DBInstanceStatus": "available",
        "DBInstanceClass": "db.r8g.2xlarge",
        "Engine": "aurora-mysql",
        "AvailabilityZone": "us-east-1a",
        "PerformanceInsightsEnabled": insights,
        "DbiResourceId": f"db-{identifier.upper()}",
        "Endpoint": {"Address": f"{identifier}.abc.rds.amazonaws.com", "Port": 3306},
        "MasterUsername": "admin",
    }


def _pi_series(dimensions: dict[str, str] | None, *values: float) -> dict[str, Any]:
    key: dict[str, Any] = {"Metric": "db.load.avg"}
    if dimensions:
        key["Dimensions"] = dimensions
    return {"Key": key, "DataPoints": [{"Timestamp": WHEN, "Value": value} for value in values]}


def _pi_response() -> dict[str, Any]:
    statements = [
        _pi_series({"db.sql_tokenized.statement": f"SELECT {i} password='hunter2' " + "x" * 600}, i)
        for i in range(7)
    ]
    waits = [
        _pi_series({"db.wait_event.name": f"io/wait-{i}", "db.wait_event.type": "io"}, i, i + 2)
        for i in range(7)
    ]
    return {"MetricList": [_pi_series(None, 9.0), *statements, *waits, _pi_series({"x": "y"})]}


def test_describe_cluster_projects_members_events_and_insights(tool_ctx: ToolContext) -> None:
    tool_ctx.rds.responses.update(
        {
            "describe_db_clusters": {"DBClusters": [CLUSTER]},
            "describe_db_instances": {
                "DBInstances": [_instance("main-2", insights=False), _instance("main-1")]
            },
            "describe_events": {
                "Events": [
                    {"Date": WHEN, "Message": f"event {i}", "EventCategories": ["failover"]}
                    for i in range(30)
                ],
                "Marker": "more",
            },
        }
    )
    tool_ctx.pi.responses["get_resource_metrics"] = _pi_response()
    result = run_tool("describe_database", {"identifier": "core", "minutes": 360}, tool_ctx)
    assert result.status == "success"
    body = result.content
    assert body["kind"] == "cluster"
    database = body["database"]
    assert database["serverless_v2_capacity"] == {"min": 0.5, "max": 16.0}
    assert database["members"][0] == {
        "id": "main-1",
        "writer": True,
        "status": "available",
        "class": "db.r8g.2xlarge",
        "az": "us-east-1a",
        "performance_insights": True,
    }
    text = json.dumps(body)
    for leaked in ("admin", "Endpoint", "rds.amazonaws.com", "secretsmanager", "hunter2"):
        assert leaked not in text
    events = body["events"]
    assert events["truncated"] is True
    assert len(events["items"]) == 20
    assert events["items"][-1]["message"] == "event 29"
    event_call = dict(tool_ctx.rds.calls)["describe_events"]
    assert event_call["SourceType"] == "db-cluster"
    assert (event_call["EndTime"] - event_call["StartTime"]).total_seconds() == 24 * 3600
    insights = body["performance_insights"]
    assert insights["instance"] == "main-1"
    assert insights["window_minutes"] == 360
    assert len(insights["top_sql"]) == 5
    assert insights["top_sql"][0]["load_avg"] == 6.0
    assert len(insights["top_sql"][0]["statement"]) == 300
    assert insights["top_sql"][0]["statement"].startswith(f"SELECT 6 password='{REDACTED}' ")
    assert insights["top_waits"][0] == {"load_avg": 7.0, "wait_event": "io/wait-6", "type": "io"}
    assert len(insights["top_waits"]) == 5
    pi_call = dict(tool_ctx.pi.calls)["get_resource_metrics"]
    assert pi_call["Identifier"] == "db-MAIN-1"
    assert pi_call["PeriodInSeconds"] == 300
    assert [query["GroupBy"]["Limit"] for query in pi_call["MetricQueries"]] == [5, 5]
    assert (pi_call["EndTime"] - pi_call["StartTime"]).total_seconds() == 360 * 60


def test_describe_instance_after_cluster_not_found(tool_ctx: ToolContext) -> None:
    tool_ctx.rds.responses.update(
        {
            "describe_db_clusters": client_error("DBClusterNotFoundFault"),
            "describe_db_instances": {"DBInstances": [_instance("solo")]},
            "describe_events": {"Events": []},
        }
    )
    tool_ctx.pi.responses["get_resource_metrics"] = {
        "MetricList": [_pi_series({"db.sql_tokenized.statement": "SELECT 1"})]
    }
    body = run_tool("describe_database", {"identifier": "solo"}, tool_ctx).content
    assert body["kind"] == "instance"
    assert body["database"]["id"] == "solo"
    assert "Endpoint" not in json.dumps(body)
    assert body["events"] == {"truncated": False, "items": []}
    assert dict(tool_ctx.rds.calls)["describe_events"]["SourceType"] == "db-instance"
    assert body["performance_insights"]["top_sql"] == [{"load_avg": 0.0, "statement": "SELECT 1"}]
    assert dict(tool_ctx.pi.calls)["get_resource_metrics"]["PeriodInSeconds"] == 60


def test_describe_database_without_insights_skips_pi(tool_ctx: ToolContext) -> None:
    tool_ctx.rds.responses.update(
        {
            "describe_db_clusters": client_error("DBClusterNotFoundFault"),
            "describe_db_instances": {"DBInstances": [_instance("solo", insights=False)]},
        }
    )
    body = run_tool("describe_database", {"identifier": "solo"}, tool_ctx).content
    assert "performance_insights" not in body
    assert tool_ctx.pi.calls == []


def test_performance_insights_error_keeps_the_rest(tool_ctx: ToolContext) -> None:
    tool_ctx.rds.responses.update(
        {
            "describe_db_clusters": client_error("DBClusterNotFoundFault"),
            "describe_db_instances": {"DBInstances": [_instance("solo")]},
        }
    )
    tool_ctx.pi.responses["get_resource_metrics"] = client_error("NotAuthorizedException")
    result = run_tool("describe_database", {"identifier": "solo"}, tool_ctx)
    assert result.status == "success"
    assert result.content["performance_insights"] == {
        "instance": "solo",
        "error": "NotAuthorizedException",
    }


def test_describe_database_not_found(tool_ctx: ToolContext) -> None:
    tool_ctx.rds.responses.update(
        {
            "describe_db_clusters": client_error("DBClusterNotFoundFault"),
            "describe_db_instances": client_error("DBInstanceNotFound"),
        }
    )
    result = run_tool("describe_database", {"identifier": "gone"}, tool_ctx)
    assert result.content == {"error": "database 'gone' not found"}


def test_describe_database_other_errors_keep_the_code(tool_ctx: ToolContext) -> None:
    tool_ctx.rds.responses["describe_db_clusters"] = client_error("Throttling", "slow down")
    result = run_tool("describe_database", {"identifier": "core"}, tool_ctx)
    assert result.content == {"error": "Throttling: slow down"}


# describe_search_domain


def test_describe_search_domain_projects_config_and_health(tool_ctx: ToolContext) -> None:
    tool_ctx.opensearch.responses.update(
        {
            "describe_domain": {
                "DomainStatus": {
                    "DomainName": "search",
                    "Endpoint": "search-abc.us-east-1.es.amazonaws.com",
                    "Endpoints": {"vpc": "vpc-search-abc.es.amazonaws.com"},
                    "AccessPolicies": '{"Statement": "do-not-leak"}',
                    "AdvancedSecurityOptions": {
                        "Enabled": True,
                        "InternalUserDatabaseEnabled": True,
                    },
                    "EngineVersion": "OpenSearch_3.7",
                    "Processing": False,
                    "UpgradeProcessing": True,
                    "DomainProcessingStatus": "UpgradingEngineVersion",
                    "ClusterConfig": {
                        "InstanceType": "r8g.2xlarge.search",
                        "InstanceCount": 3,
                        "DedicatedMasterEnabled": True,
                        "DedicatedMasterType": "m7g.large.search",
                        "DedicatedMasterCount": 3,
                        "WarmEnabled": False,
                        "WarmType": "ultrawarm1.medium.search",
                        "ZoneAwarenessEnabled": True,
                    },
                    "EBSOptions": {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 500},
                    "LogPublishingOptions": {
                        "ES_APPLICATION_LOGS": {
                            "Enabled": True,
                            "CloudWatchLogsLogGroupArn": _log_group_arn("/os/search/app"),
                        },
                        "AUDIT_LOGS": {"Enabled": False},
                    },
                }
            },
            "describe_domain_health": {
                "ClusterHealth": "Yellow",
                "DomainState": "Processing",
                "DataNodeCount": "3",
                "TotalShards": "120",
                "TotalUnAssignedShards": "4",
            },
        }
    )
    body = run_tool("describe_search_domain", {"domain_name": "search"}, tool_ctx).content
    assert body["upgrade_processing"] is True
    assert body["cluster"] == {
        "instance_type": "r8g.2xlarge.search",
        "instance_count": 3,
        "dedicated_master_type": "m7g.large.search",
        "dedicated_master_count": 3,
        "zone_awareness": True,
    }
    assert body["storage"] == {"volume_type": "gp3", "volume_size_gb": 500}
    assert body["log_publishing"] == {
        "AUDIT_LOGS": {"enabled": False},
        "ES_APPLICATION_LOGS": {"enabled": True, "log_group": "/os/search/app"},
    }
    assert body["health"] == {
        "state": "Processing",
        "cluster_health": "Yellow",
        "data_nodes": "3",
        "total_shards": "120",
        "unassigned_shards": "4",
    }
    text = json.dumps(body)
    for leaked in ("es.amazonaws.com", "do-not-leak", "InternalUserDatabase"):
        assert leaked not in text


def test_describe_search_domain_health_unavailable(tool_ctx: ToolContext) -> None:
    tool_ctx.opensearch.responses.update(
        {
            "describe_domain": {"DomainStatus": {"DomainName": "search"}},
            "describe_domain_health": client_error("DisabledOperationException"),
        }
    )
    body = run_tool("describe_search_domain", {"domain_name": "search"}, tool_ctx).content
    assert body["health"] == {"error": "DisabledOperationException"}
    assert "storage" not in body


def test_describe_search_domain_not_found(tool_ctx: ToolContext) -> None:
    tool_ctx.opensearch.responses["describe_domain"] = client_error("ResourceNotFoundException")
    result = run_tool("describe_search_domain", {"domain_name": "search"}, tool_ctx)
    assert result.content == {"error": "search domain 'search' not found"}


# describe_targets


def _health(i: int, state: str) -> dict[str, Any]:
    description: dict[str, Any] = {
        "Target": {"Id": f"10.0.0.{i}", "Port": 8080},
        "HealthCheckPort": "8080",
        "TargetHealth": {"State": state},
    }
    if state != "healthy":
        description["TargetHealth"].update(
            {"Reason": "Target.ResponseCodeMismatch", "Description": "codes: [502] " + "z" * 400}
        )
    return description


def _target_group(name: str) -> dict[str, Any]:
    return {
        "TargetGroupName": name,
        "TargetGroupArn": f"arn:tg/{name}",
        "Protocol": "HTTP",
        "Port": 8080,
        "TargetType": "ip",
        "HealthCheckPath": "/health",
    }


def test_describe_targets_for_load_balancer_caps_targets(tool_ctx: ToolContext) -> None:
    health_by_group = {
        "arn:tg/web": [_health(i, "healthy") for i in range(30)] + [_health(99, "unhealthy")],
        "arn:tg/api": [_health(i, "healthy") for i in range(30)],
    }
    tool_ctx.elbv2.responses.update(
        {
            "describe_load_balancers": {
                "LoadBalancers": [
                    {
                        "LoadBalancerName": "front",
                        "LoadBalancerArn": "arn:lb/front",
                        "DNSName": "front-123.us-east-1.elb.amazonaws.com",
                        "Type": "application",
                        "Scheme": "internet-facing",
                        "State": {"Code": "active"},
                    }
                ]
            },
            "describe_target_groups": {
                "TargetGroups": [_target_group("web"), _target_group("api")]
            },
            "describe_target_health": lambda **kwargs: {
                "TargetHealthDescriptions": health_by_group[kwargs["TargetGroupArn"]]
            },
        }
    )
    body = run_tool("describe_targets", {"load_balancer_name": "front"}, tool_ctx).content
    assert body["load_balancer"] == {
        "name": "front",
        "type": "application",
        "scheme": "internet-facing",
        "state": "active",
    }
    web, api = body["target_groups"]
    assert web["state_counts"] == {"healthy": 30, "unhealthy": 1}
    assert web["targets"][0]["state"] == "unhealthy"
    assert len(web["targets"][0]["description"]) == 300
    assert web["health_check"] == {"path": "/health"}
    assert len(web["targets"]) + len(api["targets"]) == 50
    assert api["state_counts"] == {"healthy": 30}
    assert body["truncated"] is True
    assert "elb.amazonaws.com" not in json.dumps(body)
    assert dict(tool_ctx.elbv2.calls)["describe_target_groups"] == {
        "LoadBalancerArn": "arn:lb/front",
        "PageSize": 10,
    }


def test_describe_targets_for_one_target_group(tool_ctx: ToolContext) -> None:
    tool_ctx.elbv2.responses.update(
        {
            "describe_target_groups": {"TargetGroups": [_target_group("web")]},
            "describe_target_health": {"TargetHealthDescriptions": [_health(1, "healthy")]},
        }
    )
    body = run_tool("describe_targets", {"target_group_name": "web"}, tool_ctx).content
    assert "load_balancer" not in body
    assert body["truncated"] is False
    assert body["target_groups"][0]["targets"] == [
        {"id": "10.0.0.1", "port": 8080, "state": "healthy"}
    ]
    assert "describe_load_balancers" not in tool_ctx.elbv2.operations()


@pytest.mark.parametrize(
    ("tool_input", "code", "error"),
    [
        ({"load_balancer_name": "gone"}, "LoadBalancerNotFound", "load balancer 'gone' not found"),
        ({"target_group_name": "gone"}, "TargetGroupNotFound", "target group 'gone' not found"),
    ],
)
def test_describe_targets_not_found(
    tool_ctx: ToolContext, tool_input: dict[str, str], code: str, error: str
) -> None:
    tool_ctx.elbv2.responses.update(
        {
            "describe_load_balancers": client_error(code),
            "describe_target_groups": client_error(code),
        }
    )
    assert run_tool("describe_targets", tool_input, tool_ctx).content == {"error": error}


# recent_executions


def test_recent_executions_finds_machine_and_caps_executions(tool_ctx: ToolContext) -> None:
    pages = {
        None: {
            "stateMachines": [{"name": "other", "stateMachineArn": "arn:other"}],
            "nextToken": "p2",
        },
        "p2": {"stateMachines": [{"name": "ingest", "stateMachineArn": STATE_MACHINE_ARN}]},
    }
    tool_ctx.stepfunctions.responses.update(
        {
            "list_state_machines": lambda **kwargs: pages[kwargs.get("nextToken")],
            "list_executions": {
                "executions": [
                    {
                        "executionArn": f"arn:exec:{i}",
                        "name": f"run-{i}",
                        "status": "FAILED",
                        "startDate": WHEN,
                        "stopDate": WHEN,
                    }
                    for i in range(25)
                ],
                "nextToken": "more",
            },
        }
    )
    body = run_tool("recent_executions", {"state_machine_name": "ingest"}, tool_ctx).content
    assert body["status"] == "FAILED"
    assert body["count"] == 20
    assert body["truncated"] is True
    assert body["executions"][0] == {
        "name": "run-0",
        "status": "FAILED",
        "start": WHEN.isoformat(),
        "stop": WHEN.isoformat(),
    }
    call = dict(tool_ctx.stepfunctions.calls)["list_executions"]
    assert call == {
        "stateMachineArn": STATE_MACHINE_ARN,
        "statusFilter": "FAILED",
        "maxResults": 20,
    }


def test_recent_executions_with_status(tool_ctx: ToolContext) -> None:
    tool_ctx.stepfunctions.responses.update(
        {
            "list_state_machines": {
                "stateMachines": [{"name": "ingest", "stateMachineArn": STATE_MACHINE_ARN}]
            },
            "list_executions": {"executions": []},
        }
    )
    body = run_tool(
        "recent_executions", {"state_machine_name": "ingest", "status": "TIMED_OUT"}, tool_ctx
    ).content
    assert body == {
        "state_machine": "ingest",
        "status": "TIMED_OUT",
        "count": 0,
        "truncated": False,
        "executions": [],
    }


def test_recent_executions_state_machine_not_found(tool_ctx: ToolContext) -> None:
    tool_ctx.stepfunctions.responses["list_state_machines"] = {
        "stateMachines": [{"name": "other", "stateMachineArn": "arn:other"}],
        "nextToken": "again",
    }
    result = run_tool("recent_executions", {"state_machine_name": "ingest"}, tool_ctx)
    assert result.content == {"error": "state machine 'ingest' not found"}
    assert tool_ctx.stepfunctions.operations() == ["list_state_machines"] * 5


# scheduled_jobs


def _utc_text(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


DAY = (datetime.now(UTC) - timedelta(days=3)).replace(hour=0, minute=0, second=0, microsecond=0)
SEVEN = DAY.replace(hour=7)
MORNING = {"start": _utc_text(DAY.replace(hour=6)), "end": _utc_text(DAY.replace(hour=8))}
GLUE_TARGET = "arn:aws:scheduler:::aws-sdk:glue:startJobRun"


def _rule(name: str, expression: str, state: str = "ENABLED") -> dict[str, Any]:
    return {
        "Name": name,
        "Arn": f"arn:aws:events:us-east-1:111122223333:rule/{name}",
        "ScheduleExpression": expression,
        "State": state,
        "EventBusName": "default",
    }


def _schedules(tool_ctx: ToolContext, *details: dict[str, Any]) -> None:
    by_name = {detail["Name"]: detail for detail in details}
    tool_ctx.scheduler.responses.update(
        {
            "list_schedules": {
                "Schedules": [{"Name": name, "GroupName": "default"} for name in by_name]
            },
            "get_schedule": lambda **kwargs: by_name[kwargs["Name"]],
        }
    )


def _scheduled(tool_ctx: ToolContext, tool_input: dict[str, Any]) -> dict[str, Any]:
    result = run_tool("scheduled_jobs", tool_input, tool_ctx)
    assert result.status == "success", result.content
    return result.content


def test_scheduled_jobs_scheduler_cron_honours_its_timezone(tool_ctx: ToolContext) -> None:
    _schedules(
        tool_ctx,
        {
            "Name": "os-export-to-parquet",
            "ScheduleExpression": "cron(30 12 * * ? *)",
            "ScheduleExpressionTimezone": "Asia/Kolkata",
            "State": "ENABLED",
            "Target": {
                "Arn": GLUE_TARGET,
                "RoleArn": "arn:aws:iam::111122223333:role/scheduler",
                "Input": json.dumps(
                    {
                        "JobName": "acme-export-to-parquet-prod",
                        "Arguments": {"--password": "hunter2"},
                    }
                ),
            },
        },
        {
            "Name": "noon-in-utc",
            "ScheduleExpression": "cron(30 12 * * ? *)",
            "State": "ENABLED",
            "Target": {"Arn": GLUE_TARGET, "Input": "{}"},
        },
    )
    body = _scheduled(tool_ctx, MORNING)
    assert body["schedules"] == [
        {
            "name": "os-export-to-parquet",
            "source": "scheduler",
            "expression": "cron(30 12 * * ? *)",
            "timezone": "Asia/Kolkata",
            "state": "ENABLED",
            "target": {
                "arn": GLUE_TARGET,
                "service": "glue",
                "action": "startJobRun",
                "input": {"JobName": "acme-export-to-parquet-prod"},
            },
            "fire_times": [_utc_text(SEVEN)],
        }
    ]
    assert body["window"] == MORNING
    assert body["truncated"] == []
    assert "errors" not in body
    assert "Arguments" not in json.dumps(body)
    assert "hunter2" not in json.dumps(body)
    assert ("get_schedule", {"Name": "noon-in-utc", "GroupName": "default"}) in (
        tool_ctx.scheduler.calls
    )


def test_scheduled_jobs_universal_target_keeps_only_whitelisted_input(
    tool_ctx: ToolContext,
) -> None:
    payload = {
        "StateMachineArn": "arn:aws:states:us-east-1:111122223333:stateMachine:ingest",
        "Input": '{"token": "abc"}',
        "Arguments": ["--secret", "x"],
        "Name": {"nested": "dropped"},
    }
    _schedules(
        tool_ctx,
        {
            "Name": "ingest",
            "ScheduleExpression": "cron(0 7 * * ? *)",
            "State": "ENABLED",
            "Target": {
                "Arn": "arn:aws:scheduler:::aws-sdk:sfn:startExecution",
                "Input": json.dumps(payload),
            },
        },
        {
            "Name": "lambda",
            "ScheduleExpression": "cron(0 7 * * ? *)",
            "State": "ENABLED",
            "Target": {
                "Arn": "arn:aws:lambda:us-east-1:111122223333:function:f",
                "Input": json.dumps({"FunctionName": "f", "Arguments": "x"}),
            },
        },
    )
    by_name = {view["name"]: view for view in _scheduled(tool_ctx, MORNING)["schedules"]}
    assert by_name["ingest"]["target"]["input"] == {"StateMachineArn": payload["StateMachineArn"]}
    assert by_name["lambda"]["target"] == {
        "arn": "arn:aws:lambda:us-east-1:111122223333:function:f"
    }
    assert "Arguments" not in json.dumps(by_name)
    assert "token" not in json.dumps(by_name)


def test_scheduled_jobs_rules_fire_in_utc_and_return_target_arns_only(
    tool_ctx: ToolContext,
) -> None:
    tool_ctx.events.responses.update(
        {
            "list_rules": {
                "Rules": [
                    _rule("daily", "rate(1 day)"),
                    _rule("export", "cron(0 7 * * ? *)"),
                    _rule("noon", "cron(0 12 * * ? *)"),
                    _rule("paused-export", "cron(15 7 * * ? *)", "DISABLED"),
                    _rule("paused-daily", "rate(1 day)", "DISABLED"),
                    {"Name": "on-change", "EventPattern": "{}", "State": "ENABLED"},
                ]
            },
            "list_targets_by_rule": {
                "Targets": [
                    {
                        "Id": "1",
                        "Arn": "arn:aws:glue:us-east-1:111122223333:job/export",
                        "Input": '{"password": "hunter2"}',
                        "InputTransformer": {"InputTemplate": "<secret>"},
                    }
                ]
            },
        }
    )
    body = _scheduled(tool_ctx, MORNING)
    assert [view["name"] for view in body["schedules"]] == ["export", "paused-export", "daily"]
    export, paused, daily = body["schedules"]
    assert export == {
        "name": "export",
        "source": "rule",
        "expression": "cron(0 7 * * ? *)",
        "timezone": "UTC",
        "state": "ENABLED",
        "fire_times": [_utc_text(SEVEN)],
        "target_arns": ["arn:aws:glue:us-east-1:111122223333:job/export"],
    }
    assert paused["state"] == "DISABLED"
    assert paused["fire_times"] == [_utc_text(SEVEN.replace(minute=15))]
    assert daily["fire_times_unknown"] is True
    assert "fire_times" not in daily
    assert "hunter2" not in json.dumps(body)
    assert "secret" not in json.dumps(body)
    assert ("list_targets_by_rule", {"Rule": "export", "EventBusName": "default"}) in (
        tool_ctx.events.calls
    )


def test_scheduled_jobs_rates_under_an_hour_are_frequent_and_longer_ones_timed(
    tool_ctx: ToolContext,
) -> None:
    tool_ctx.events.responses["list_rules"] = {"Rules": [_rule("poll", "rate(5 minutes)")]}
    _schedules(
        tool_ctx,
        {
            "Name": "every-six-hours",
            "ScheduleExpression": "rate(6 hours)",
            "State": "ENABLED",
            "CreationDate": DAY.replace(hour=1) - timedelta(days=2),
            "Target": {"Arn": "arn:aws:lambda:us-east-1:111122223333:function:f"},
        },
        {
            "Name": "ended",
            "ScheduleExpression": "cron(0 7 * * ? *)",
            "State": "ENABLED",
            "EndDate": DAY.replace(hour=6, minute=30),
            "Target": {"Arn": "arn:aws:lambda:us-east-1:111122223333:function:f"},
        },
    )
    by_name = {view["name"]: view for view in _scheduled(tool_ctx, MORNING)["schedules"]}
    assert set(by_name) == {"poll", "every-six-hours"}
    assert by_name["poll"]["frequent"] is True
    assert "fire_times" not in by_name["poll"]
    assert by_name["every-six-hours"]["fire_times"] == [_utc_text(SEVEN)]


def test_scheduled_jobs_name_contains_filters_every_source(tool_ctx: ToolContext) -> None:
    tool_ctx.events.responses["list_rules"] = {
        "Rules": [_rule("OS-Export", "cron(0 7 * * ? *)"), _rule("ingest", "cron(0 7 * * ? *)")]
    }
    _schedules(
        tool_ctx,
        {"Name": "ingest-nightly", "ScheduleExpression": "cron(0 7 * * ? *)", "State": "ENABLED"},
    )
    body = _scheduled(tool_ctx, {**MORNING, "name_contains": "export"})
    assert [view["name"] for view in body["schedules"]] == ["OS-Export"]
    assert body["name_contains"] == "export"
    assert tool_ctx.scheduler.operations() == ["list_schedules"]


def test_scheduled_jobs_scheduler_access_denied_keeps_the_rules(
    tool_ctx: ToolContext,
) -> None:
    tool_ctx.scheduler.responses["list_schedules"] = client_error("AccessDeniedException")
    tool_ctx.events.responses["list_rules"] = {"Rules": [_rule("export", "cron(0 7 * * ? *)")]}
    body = _scheduled(tool_ctx, MORNING)
    assert body["errors"] == {"scheduler": "AccessDeniedException"}
    assert [view["name"] for view in body["schedules"]] == ["export"]


def test_scheduled_jobs_target_errors_are_reported_inline(
    tool_ctx: ToolContext,
) -> None:
    tool_ctx.events.responses.update(
        {
            "list_rules": {"Rules": [_rule("a", "cron(0 7 * * ? *)"), _rule("b", "rate(1 hour)")]},
            "list_targets_by_rule": client_error("AccessDeniedException"),
        }
    )
    body = _scheduled(tool_ctx, MORNING)
    assert body["errors"] == {"rule_targets": "AccessDeniedException"}
    assert [view["name"] for view in body["schedules"]] == ["a", "b"]
    assert tool_ctx.events.operations().count("list_targets_by_rule") == 1


def test_scheduled_jobs_every_source_failing_is_an_error(tool_ctx: ToolContext) -> None:
    denied = client_error("AccessDeniedException")
    tool_ctx.events.responses["list_rules"] = denied
    tool_ctx.scheduler.responses["list_schedules"] = denied
    result = run_tool("scheduled_jobs", MORNING, tool_ctx)
    assert result.status == "error"
    assert result.content == {
        "error": "rules: AccessDeniedException; scheduler: AccessDeniedException"
    }


def test_scheduled_jobs_caps_schedules(tool_ctx: ToolContext) -> None:
    tool_ctx.events.responses["list_rules"] = {
        "Rules": [_rule(f"rule-{i:02}", f"cron({i} 7 * * ? *)") for i in range(25)],
        "NextToken": "more",
    }
    body = _scheduled(tool_ctx, MORNING)
    assert len(body["schedules"]) == 20
    assert body["schedules"][0]["name"] == "rule-00"
    assert body["truncated"] == ["rules", "schedules"]
    assert tool_ctx.events.operations().count("list_rules") == 5
    assert tool_ctx.events.operations().count("list_targets_by_rule") == 20


def test_scheduled_jobs_caps_fire_times(tool_ctx: ToolContext) -> None:
    tool_ctx.events.responses["list_rules"] = {"Rules": [_rule("hourly", "cron(0 * * * ? *)")]}
    tool_input = {"start": _utc_text(DAY), "end": _utc_text(DAY + timedelta(hours=24))}
    [view] = _scheduled(tool_ctx, tool_input)["schedules"]
    assert view["fire_times"] == [_utc_text(DAY.replace(hour=hour)) for hour in range(5)]
    assert view["fire_count"] == 25


def test_scheduled_jobs_window_defaults_to_the_alarm_and_is_at_most_a_day(
    tool_ctx: ToolContext,
) -> None:
    alarm_ctx = dataclasses.replace(tool_ctx, alarm_time=SEVEN)
    body = _scheduled(alarm_ctx, {})
    assert body["window"] == {
        "start": _utc_text(SEVEN - timedelta(hours=2)),
        "end": _utc_text(SEVEN),
    }
    too_long = {"start": _utc_text(DAY), "end": _utc_text(DAY + timedelta(hours=25))}
    result = run_tool("scheduled_jobs", too_long, tool_ctx)
    assert result.content == {"error": "the window is at most 24 hours"}


# cron and rate expressions


@pytest.mark.parametrize(
    ("body", "field", "values"),
    [
        ("*/15 * * * ? *", "minutes", {0, 15, 30, 45}),
        ("5/20 * * * ? *", "minutes", {5, 25, 45}),
        ("0 9-11 * * ? *", "hours", {9, 10, 11}),
        ("0 8-17/4 * * ? *", "hours", {8, 12, 16}),
        ("0 0 1,15 * ? *", "days", {1, 15}),
        ("0 0 ? JAN,JUL-SEP * *", "months", {1, 7, 8, 9}),
        ("0 0 ? * MON-FRI *", "weekdays", {2, 3, 4, 5, 6}),
        ("0 0 ? * sun,7 *", "weekdays", {1, 7}),
        ("0 0 ? * * 2026-2027", "years", {2026, 2027}),
        ("0 0 * * ? *", "days", set(range(1, 32))),
    ],
)
def test_parse_cron_fields(body: str, field: str, values: set[int]) -> None:
    assert getattr(parse_cron(body), field) == values


@pytest.mark.parametrize(
    "body",
    [
        "0 0 L * ? *",
        "0 0 15W * ? *",
        "0 0 ? * 6#3 *",
        "0 0 ? * 6L *",
        "0 0 * * ?",
        "60 0 * * ? *",
        "0 0 ? * FRI-MON *",
        "0 0 */0 * ? *",
    ],
)
def test_parse_cron_rejects_unsupported_and_malformed(body: str) -> None:
    with pytest.raises(ValueError):
        parse_cron(body)


def test_cron_matches_the_aws_day_of_week() -> None:
    monday = datetime(2026, 10, 12, 7, 0, tzinfo=UTC)
    weekdays = parse_cron("0 7 ? * MON *")
    assert weekdays.matches(monday)
    assert not weekdays.matches(monday + timedelta(days=1))
    assert parse_cron("0 7 ? * 1 *").matches(monday - timedelta(days=1))


def test_schedule_firing_by_expression() -> None:
    start, end = SEVEN - timedelta(hours=1), SEVEN + timedelta(hours=1)
    assert schedule_firing("cron(0 7 * * ? *)", "UTC", start, end) == {"fire_times": [SEVEN]}
    assert schedule_firing("cron(0 7 * * ? *)", "Asia/Kolkata", start, end) == {"fire_times": []}
    at = f"at({SEVEN.strftime('%Y-%m-%dT%H:%M:%S')})"
    assert schedule_firing(at, "UTC", start, end) == {"fire_times": [SEVEN]}
    assert schedule_firing("rate(1 minute)", "UTC", start, end) == {"frequent": True}
    assert schedule_firing("rate(2 hours)", "UTC", start, end) == {"fire_times_unknown": True}
    anchored = schedule_firing("rate(1 hour)", "UTC", start, end, SEVEN - timedelta(days=1))
    assert anchored == {"fire_times": [start, SEVEN, end]}
    for unsupported in ("cron(0 7 L * ? *)", "rate(0 hours)", "weekly", "cron(0 7 * * ? *"):
        assert schedule_firing(unsupported, "UTC", start, end) == {"unsupported": True}
    assert schedule_firing("cron(0 7 * * ? *)", "Mars/Olympus", start, end) == {"unsupported": True}


# inputs


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("describe_s3_key", {"bucket": "Drops", "key": "a.xml"}),
        ("describe_s3_key", {"bucket": "drops", "key": ""}),
        ("describe_s3_key", {"bucket": "drops", "key": "a\nb"}),
        ("describe_s3_key", {"bucket": "drops", "key": "k" * 1025}),
        ("describe_database", {"identifier": "core", "minutes": 361}),
        ("describe_database", {"identifier": "1core"}),
        ("describe_search_domain", {"domain_name": "UPPER"}),
        ("describe_targets", {}),
        ("describe_targets", {"load_balancer_name": "a", "target_group_name": "b"}),
        ("recent_executions", {"state_machine_name": "ingest", "status": "BROKEN"}),
        ("scheduled_jobs", {"name_contains": "a b"}),
        ("scheduled_jobs", {"name_contains": "*export"}),
        ("scheduled_jobs", {"hours": 25}),
    ],
)
def test_out_of_bounds_input_is_rejected_without_calling_aws(
    tool_ctx: ToolContext, tool: str, tool_input: dict[str, Any]
) -> None:
    result = run_tool(tool, tool_input, tool_ctx)
    assert result.status == "error"
    assert result.content["error"].startswith("invalid input:")
    for name in ToolContext.__dataclass_fields__:
        client = getattr(tool_ctx, name)
        if name not in ALARM_FIELDS:
            assert client.calls == [], name
