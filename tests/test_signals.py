"""Signal registry: parsers, the Datadog payload read defensively, and the key scheme."""

from __future__ import annotations

from typing import Any

import pytest

from devops_agent import tools
from devops_agent.models import InvestigationJob
from devops_agent.signals import (
    SIMPLE_GROUP,
    datadog_keys,
    group_keys,
    parse_signal,
)
from tests.conftest import (
    ALARM_NAME,
    DATADOG_MONITOR_ID,
    ECS_SERVICE_KEY,
    alarm_event,
    datadog_event,
)


def test_cloudwatch_alarm_parses_to_a_cloudwatch_signal() -> None:
    signal = parse_signal(alarm_event())
    assert signal is not None
    assert signal.source == "cloudwatch"
    assert signal.name == ALARM_NAME
    assert signal.identity == ALARM_NAME
    assert signal.arn == alarm_event()["resources"][0]
    assert signal.observed_at == "2026-09-29T14:05:00+00:00"
    assert signal.reason.startswith("Threshold Crossed")
    assert signal.fired == "entered ALARM"


def test_datadog_fixture_parses_to_a_datadog_signal() -> None:
    signal = parse_signal(datadog_event())
    assert signal is not None
    assert signal.source == "datadog"
    assert signal.subject == "checkout-api 5xx rate"
    assert signal.name == "checkout-api 5xx rate (service:checkout-api-prod)"
    assert signal.env == "prod"
    assert signal.priority == 2
    assert signal.observed_at == "2026-10-14T13:12:05+00:00"
    assert signal.resource_keys == [ECS_SERVICE_KEY]
    assert signal.identity == f"datadog:monitor/{DATADOG_MONITOR_ID}/service:checkout-api-prod"
    assert signal.ref["group"] == "service:checkout-api-prod"
    assert signal.ref["group_tags"] == ["service:checkout-api-prod"]
    assert signal.ref["dest_state"] == "Alert"
    assert signal.fired == "went to Alert"
    assert "devops_agent_retry" not in signal.raw


@pytest.mark.parametrize(
    "event",
    [
        alarm_event(detail_type="EC2 Instance State-change Notification"),
        {"detail-type": 7},
        "not an object",
        datadog_event(meta="not an object"),
        datadog_event(meta={"monitor": {"id": "abc"}}),
    ],
    ids=["unknown-type", "type-not-text", "not-object", "meta-not-object", "no-monitor-id"],
)
def test_events_that_are_not_signals_are_ignored(event: Any) -> None:
    assert parse_signal(event) is None


@pytest.mark.parametrize(
    ("states", "alert_type", "parsed"),
    [
        ({"source_state": "Alert", "dest_state": "OK"}, "success", False),
        ({"dest_state": "No Data"}, "error", False),
        ({"dest_state": "Warn"}, "warning", True),
        ({}, "error", True),
        ({}, "success", False),
    ],
)
def test_only_alert_and_warn_transitions_are_signals(
    states: dict[str, str], alert_type: str, parsed: bool
) -> None:
    event = datadog_event(alert_type=alert_type)
    event["detail"]["meta"]["states"] = states
    assert (parse_signal(event) is not None) is parsed


def test_datadog_payload_is_read_defensively() -> None:
    event = datadog_event(tags="env:prod, service:checkout-api-prod", unexpected={"x": 1})
    meta = event["detail"]["meta"]
    meta["monitor"].update(id=str(DATADOG_MONITOR_ID), tags=None, priority="high")
    meta["result"] = {"result_ts": "soon", "evaluation_ts": True, "metadata": ["x"]}
    meta["transition"] = None
    signal = parse_signal(event)
    assert signal is not None
    assert signal.ref["monitor_id"] == DATADOG_MONITOR_ID
    assert signal.priority == 4
    assert signal.observed_at == "2026-10-14T13:12:11+00:00"
    assert signal.ref["group"] == "service:checkout-api-prod"
    assert signal.ref["transition"] == ""


def test_group_falls_back_to_result_metadata() -> None:
    event = datadog_event(tags=["env:prod"])
    event["detail"]["meta"]["result"]["metadata"] = {"service": "checkout-api-prod"}
    signal = parse_signal(event)
    assert signal is not None
    assert signal.ref["group"] == "service:checkout-api-prod"


def test_unresolved_group_is_kept_empty_for_verification_to_drop() -> None:
    signal = parse_signal(datadog_event(tags=["env:prod"]))
    assert signal is not None
    assert signal.ref["group"] == ""
    assert signal.name == "checkout-api 5xx rate (unknown group)"


def test_simple_monitor_has_the_simple_group() -> None:
    event = datadog_event()
    event["detail"]["meta"]["monitor"]["query"] = "avg(last_5m):avg:system.load.1{env:prod} > 4"
    signal = parse_signal(event)
    assert signal is not None
    assert signal.ref["group"] == SIMPLE_GROUP
    assert signal.name == "checkout-api 5xx rate"


def test_millisecond_evaluation_time_is_read() -> None:
    event = datadog_event()
    event["detail"]["meta"]["result"] = {"evaluation_ts": 1791983525000}
    signal = parse_signal(event)
    assert signal is not None
    assert signal.observed_at == "2026-10-14T13:12:05+00:00"


@pytest.mark.parametrize(
    ("query", "keys"),
    [
        ("avg(last_5m):avg:x{*} by {service,env} > 1", ["service", "env"]),
        (
            'logs("status:error").index("*").rollup("count").by("service").last("5m") > 5',
            ["service"],
        ),
        ("avg(last_5m):avg:x{*} > 1", []),
    ],
)
def test_group_keys_read_both_query_forms(query: str, keys: list[str]) -> None:
    assert group_keys(query) == keys


# Resource keys: one scheme for both sources


def _task_deficit_alarm(service: str) -> dict[str, Any]:
    """A Fargate task-deficit alarm: desired - running, Container Insights."""

    def metric(name: str, metric_id: str) -> dict[str, Any]:
        return {
            "Id": metric_id,
            "ReturnData": False,
            "MetricStat": {
                "Metric": {
                    "Namespace": "ECS/ContainerInsights",
                    "MetricName": name,
                    "Dimensions": [
                        {"Name": "ClusterName", "Value": "acme-prod"},
                        {"Name": "ServiceName", "Value": service},
                    ],
                },
                "Period": 60,
                "Stat": "Average",
            },
        }

    return {
        "AlarmName": f"{service}-task-deficit",
        "AlarmArn": f"arn:aws:cloudwatch:us-east-1:111122223333:alarm:{service}-task-deficit",
        "Metrics": [
            {"Id": "deficit", "Expression": "desired - running", "ReturnData": True},
            metric("DesiredTaskCount", "desired"),
            metric("RunningTaskCount", "running"),
        ],
    }


def test_ecs_alarm_and_datadog_ecs_signal_share_a_key() -> None:
    primary = tools.primary_key(_task_deficit_alarm("checkout-api-prod"))
    signal = parse_signal(datadog_event())
    assert primary is not None
    assert signal is not None
    assert primary[0] == ECS_SERVICE_KEY == signal.resource_keys[0]
    assert primary[1] == "ECS/ContainerInsights"


def test_ecs_metric_alarm_is_keyed_by_service() -> None:
    alarm = {
        "AlarmName": "cpu",
        "Namespace": "AWS/ECS",
        "MetricName": "CPUUtilization",
        "Dimensions": [
            {"Name": "ClusterName", "Value": "acme-prod"},
            {"Name": "ServiceName", "Value": "checkout-api-prod"},
        ],
    }
    key = tools.primary_key(alarm)
    assert key is not None
    assert key[0] == ECS_SERVICE_KEY


def test_metric_math_alarm_is_keyed_by_its_first_metric_with_dimensions() -> None:
    alarm = {
        "AlarmName": "errors-ratio",
        "Metrics": [
            {"Id": "e1", "Expression": "m1 / m2"},
            {"Id": "m0", "MetricStat": {"Metric": {"Namespace": "AWS/Lambda", "MetricName": "X"}}},
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/Lambda",
                        "MetricName": "Errors",
                        "Dimensions": [{"Name": "FunctionName", "Value": "orders"}],
                    }
                },
            },
        ],
    }
    assert tools.primary_key(alarm) == (
        "AWS/Lambda:FunctionName=orders",
        "AWS/Lambda",
        {"FunctionName": "orders"},
    )


def test_metric_math_alarm_without_dimensions_has_no_key() -> None:
    alarm = {"AlarmName": "x", "Metrics": [{"Id": "e1", "Expression": "m1 / m2"}]}
    assert tools.primary_key(alarm) is None


def test_ecs_key_needs_source_ecs_in_tags_or_query() -> None:
    assert datadog_keys(1, "service:a", ["service:a"], [], "avg:x{source:ecs} by {service}") == [
        "AWS/ECS:ServiceName=a"
    ]
    assert datadog_keys(1, "service:a", ["service:a"], ["source:ecs"], "q") == [
        "AWS/ECS:ServiceName=a"
    ]
    assert datadog_keys(1, "service:a", ["service:a"], [], "q") == ["datadog:monitor=1/service:a"]


def test_group_service_wins_over_the_monitor_tag() -> None:
    keys = datadog_keys(1, "service:b", ["service:b"], ["service:a", "source:ecs"], "q")
    assert keys == ["AWS/ECS:ServiceName=b"]


def test_kubernetes_groups_fall_back_to_the_monitor_key() -> None:
    group = "kube_deployment:api,kube_namespace:checkout"
    keys = datadog_keys(7, group, group.split(","), ["kube_cluster_name:main"], "q")
    assert keys == [f"datadog:monitor=7/{group}"]


def test_simple_monitor_key_uses_the_simple_group() -> None:
    assert datadog_keys(7, "", [], [], "q") == ["datadog:monitor=7/*"]


# Jobs


def test_job_written_without_signals_takes_them_from_its_alarms() -> None:
    body = {
        "finding_id": "f-1",
        "kind": "alarm",
        "alarms": [alarm_event()],
        "alarm_count": 1,
        "keys": ["k"],
        "floor": "medium",
    }
    work = InvestigationJob.model_validate(body)
    assert work.signal.source == "cloudwatch"
    assert work.signal.name == ALARM_NAME
    assert work.signal.priority == 3
    assert work.alarm is not None


def test_job_needs_a_signal() -> None:
    with pytest.raises(ValueError, match="at least one signal"):
        InvestigationJob.model_validate(
            {"finding_id": "f", "kind": "alarm", "alarm_count": 1, "keys": ["k"], "floor": "low"}
        )


def test_datadog_job_has_no_alarm() -> None:
    signal = parse_signal(datadog_event())
    assert signal is not None
    work = InvestigationJob(
        finding_id="f",
        kind="alarm",
        signals=[signal.as_ref()],
        alarm_count=1,
        keys=signal.resource_keys,
        floor="high",
    )
    assert work.alarm is None
    assert "raw" not in work.model_dump()["signals"][0]
