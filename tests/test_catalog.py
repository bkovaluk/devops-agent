"""The catalog: the bundled document, the SSM override, and the rules read from it."""

from __future__ import annotations

import json
from typing import Any

import pytest

from devops_agent import catalog as catalog_module
from devops_agent import tools
from devops_agent.catalog import BUNDLED_CATALOG, bundled_catalog, load_catalog
from devops_agent.config import get_settings
from devops_agent.models import Severity
from devops_agent.severity import env_floor, notifies
from devops_agent.signals import parse_signal
from devops_agent.triage import opted_out
from devops_agent.verify import clear_monitor_cache, verify_monitor
from tests.conftest import (
    ALARM_NAME,
    FakeClient,
    alarm_event,
    client_error,
    datadog_event,
    datadog_monitor,
    set_environment,
)

PARAMETER = "/devops-agent/catalog"
KNOWN_FLOORS = {
    "prod": Severity.HIGH,
    "staging": Severity.MEDIUM,
    "qa": Severity.LOW,
    "dev": Severity.LOW,
}


def _document(**changes: Any) -> dict[str, Any]:
    """The bundled document with top-level fields, or ``section__field``, replaced."""
    document: dict[str, Any] = json.loads(BUNDLED_CATALOG.read_text())
    for path, value in changes.items():
        section, _, field = path.partition("__")
        if field:
            document[section][field] = value
        else:
            document[section] = value
    return document


@pytest.fixture()
def ssm(monkeypatch: pytest.MonkeyPatch) -> FakeClient:
    """CATALOG_PARAMETER set, against a fake SSM client serving an edited catalog."""
    document = _document(agent__notify=["critical"])
    client = FakeClient({"get_parameter": {"Parameter": {"Value": json.dumps(document)}}})
    monkeypatch.setenv("CATALOG_PARAMETER", PARAMETER)
    monkeypatch.setattr(catalog_module.boto3, "client", lambda service, region_name: client)
    get_settings.cache_clear()
    load_catalog.cache_clear()
    return client


def _override(monkeypatch: pytest.MonkeyPatch, **changes: Any) -> None:
    document = json.dumps(_document(**changes))
    monkeypatch.setenv("CATALOG_PARAMETER", PARAMETER)
    monkeypatch.setattr(catalog_module, "_read_parameter", lambda name, region: document)
    get_settings.cache_clear()
    load_catalog.cache_clear()


def _metric_alarm(namespace: str, **dimensions: str) -> dict[str, Any]:
    return {
        "AlarmName": "a",
        "Namespace": namespace,
        "MetricName": "m",
        "Dimensions": [{"Name": name, "Value": value} for name, value in dimensions.items()],
    }


# Loading


def test_without_a_parameter_the_bundled_catalog_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(catalog_module.boto3, "client", pytest.fail)
    assert load_catalog() is bundled_catalog()
    assert bundled_catalog().env is None


def test_loads_the_parameter_once_per_process(ssm: FakeClient) -> None:
    catalog = load_catalog()
    assert load_catalog() is catalog
    assert ssm.calls == [("get_parameter", {"Name": PARAMETER})]
    assert catalog.agent.notify == [Severity.CRITICAL]
    assert catalog != bundled_catalog()


@pytest.mark.parametrize("code", ["ParameterNotFound", "AccessDeniedException"])
def test_missing_or_denied_parameter_falls_back(ssm: FakeClient, code: str) -> None:
    ssm.responses["get_parameter"] = client_error(code)
    assert load_catalog() is bundled_catalog()


@pytest.mark.parametrize("value", ["not json", "{}", json.dumps(_document(resources="x"))])
def test_malformed_parameter_falls_back(ssm: FakeClient, value: str) -> None:
    ssm.responses["get_parameter"] = {"Parameter": {"Value": value}}
    assert load_catalog() is bundled_catalog()


def test_response_without_a_value_falls_back(ssm: FakeClient) -> None:
    ssm.responses["get_parameter"] = {}
    assert load_catalog() is bundled_catalog()


def test_catalog_for_another_env_falls_back(ssm: FakeClient) -> None:
    document = _document(env="dev", agent__notify=["critical"])
    ssm.responses["get_parameter"] = {"Parameter": {"Value": json.dumps(document)}}
    assert load_catalog() is bundled_catalog()


def test_catalog_for_this_env_is_used(ssm: FakeClient) -> None:
    document = _document(env="prod", agent__notify=["critical"])
    ssm.responses["get_parameter"] = {"Parameter": {"Value": json.dumps(document)}}
    assert load_catalog().agent.notify == [Severity.CRITICAL]


# What the catalog sets


def test_bundled_resources_name_each_namespace_once() -> None:
    resources = bundled_catalog().resources
    namespaces = [namespace for resource in resources for namespace in resource.namespaces]
    assert len(namespaces) == len(set(namespaces))
    assert all(resource.dimensions for resource in resources)


def test_key_namespaces_fold_only_container_insights_into_ecs() -> None:
    assert load_catalog().key_namespaces() == {"ECS/ContainerInsights": "AWS/ECS"}


def test_docdb_alarm_keeps_its_own_namespace() -> None:
    key = tools.primary_key(_metric_alarm("AWS/DocDB", DBClusterIdentifier="docs"))
    assert key is not None
    assert key[0] == "AWS/DocDB:DBClusterIdentifier=docs"


def test_inference_component_alarm_keys_by_component() -> None:
    alarm = _metric_alarm("AWS/SageMaker", EndpointName="ranker", InferenceComponentName="ic")
    key = tools.primary_key(alarm)
    assert key is not None
    assert key[0] == "AWS/SageMaker:InferenceComponentName=ic"


def test_resource_dimensions_come_from_the_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    alarm = _metric_alarm("AWS/Lambda", FunctionName="f", Resource="f:live")
    key = tools.primary_key(alarm)
    assert key is not None
    assert key[0] == "AWS/Lambda:FunctionName=f"
    resources = [{"id": "lambda", "namespaces": ["AWS/Lambda"], "dimensions": ["Resource"]}]
    _override(monkeypatch, resources=resources)
    key = tools.primary_key(alarm)
    assert key is not None
    assert key[0] == "AWS/Lambda:Resource=f:live"


@pytest.mark.parametrize("env", ["dev", "qa", "staging", "prod"])
def test_env_floor_is_the_catalog_default(monkeypatch: pytest.MonkeyPatch, env: str) -> None:
    set_environment(monkeypatch, env)
    assert env_floor() is KNOWN_FLOORS[env]


def test_env_floor_follows_the_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    _override(monkeypatch, severity={"default": {"prod": "critical"}})
    assert env_floor() is Severity.CRITICAL


def test_env_left_out_of_the_catalog_is_low(monkeypatch: pytest.MonkeyPatch) -> None:
    _override(monkeypatch, severity={"default": {"dev": "high"}})
    assert env_floor() is Severity.LOW


def test_notify_levels_come_from_the_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    assert [level for level in Severity if notifies(level)] == [Severity.CRITICAL, Severity.HIGH]
    _override(monkeypatch, agent__notify=["critical"])
    assert [level for level in Severity if notifies(level)] == [Severity.CRITICAL]


@pytest.mark.parametrize("name", ["devops-agent-errors-prod", "TargetTracking-table/x-AlarmHigh-1"])
def test_excluded_alarm_prefixes_are_not_signals(name: str) -> None:
    assert parse_signal(alarm_event(name=name)) is None


def test_excluded_alarm_prefixes_come_from_the_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    assert parse_signal(alarm_event()) is not None
    _override(monkeypatch, agent__exclude_alarm_prefixes=[ALARM_NAME[:10]])
    assert parse_signal(alarm_event()) is None
    assert parse_signal(alarm_event(name="devops-agent-errors-prod")) is not None


def test_opt_out_tag_is_case_insensitive() -> None:
    assert opted_out({"devopsagent": " OFF "})
    assert opted_out({"DevOpsAgent": "off"})
    assert not opted_out({"DevOpsAgent": "on"})


def test_opt_out_tag_comes_from_the_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    _override(monkeypatch, agent__opt_out_tag={"key": "Investigate", "value": "Skip"})
    assert opted_out({"investigate": "SKIP"})
    assert not opted_out({"DevOpsAgent": "off"})


def test_datadog_monitor_tags_come_from_the_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    signal = parse_signal(datadog_event())
    assert signal is not None
    client = FakeClient({"get_monitor": datadog_monitor(tags=["env:prod", "team:ops"])})
    verdict = verify_monitor(client, signal, "prod", 2)  # type: ignore[arg-type]
    assert verdict.reason == "the monitor lacks the devops_agent:true tag"
    _override(monkeypatch, agent__datadog_monitor_tags=["Team:Ops"])
    clear_monitor_cache()
    assert verify_monitor(client, signal, "prod", 2).verified  # type: ignore[arg-type]
