"""The catalog: resource types, the default severity per env and the agent's rules.

``catalog.json`` next to this module is the catalog every deployment starts from. A
deployment replaces it with its own document by storing one in an SSM parameter and naming
that parameter in CATALOG_PARAMETER. ``load_catalog`` reads it once per process with boto3;
this is agent code, not a model tool, so it does not go through ``aws_call``. A missing,
unreadable or malformed parameter, or one whose ``env`` names another env, logs a warning
and yields the bundled catalog instead.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import boto3
from aws_lambda_powertools import Logger
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel, ValidationError

from devops_agent.config import Environment, get_settings
from devops_agent.models import Severity

logger = Logger(service="devops-agent", child=True)

BUNDLED_CATALOG = Path(__file__).with_name("catalog.json")


class CatalogResource(BaseModel):
    """One kind of AWS resource: the namespaces whose alarms judge it and the dimensions
    that name it, most specific first."""

    id: str
    namespaces: list[str]
    dimensions: list[str]
    # The namespace a resource key uses when it differs from the alarm's own.
    key_namespace: str | None = None


class CatalogSeverity(BaseModel):
    # Per env, the floor of an alarm whose Severity tag names no level; an env left out
    # is low.
    default: dict[Environment, Severity]


class OptOutTag(BaseModel):
    key: str
    value: str


class AgentRules(BaseModel):
    exclude_alarm_prefixes: list[str]
    opt_out_tag: OptOutTag
    # Finding severities that notify a person.
    notify: list[Severity]
    # Tags a Datadog monitor must carry before triage acts on its notifications.
    datadog_monitor_tags: list[str]


class Catalog(BaseModel):
    """The catalog document the agent reads."""

    version: int
    # When set, the env the document was written for; another env's document is refused.
    env: Environment | None = None
    severity: CatalogSeverity
    resources: list[CatalogResource]
    agent: AgentRules

    def default_severity(self, env: Environment) -> Severity:
        return self.severity.default.get(env, Severity.LOW)

    def primary_dimensions(self) -> dict[str, tuple[str, ...]]:
        """Namespace to the dimensions that name its resource, most specific first."""
        return {
            namespace: tuple(resource.dimensions)
            for resource in self.resources
            for namespace in resource.namespaces
        }

    def key_namespaces(self) -> dict[str, str]:
        """Namespace to the namespace its resource keys use, where the two differ."""
        return {
            namespace: resource.key_namespace
            for resource in self.resources
            if resource.key_namespace
            for namespace in resource.namespaces
            if namespace != resource.key_namespace
        }


@lru_cache(maxsize=1)
def bundled_catalog() -> Catalog:
    """The catalog shipped with the package."""
    return Catalog.model_validate_json(BUNDLED_CATALOG.read_text(encoding="utf-8"))


def _read_parameter(name: str, region: str) -> str:
    response = boto3.client("ssm", region_name=region).get_parameter(Name=name)
    return str(response["Parameter"]["Value"])


@lru_cache(maxsize=1)
def load_catalog() -> Catalog:
    """The catalog CATALOG_PARAMETER names, read once per process; else the bundled one."""
    settings = get_settings()
    if not settings.catalog_parameter:
        return bundled_catalog()
    try:
        catalog = Catalog.model_validate_json(
            _read_parameter(settings.catalog_parameter, settings.aws_region)
        )
    except ClientError as exc:
        logger.warning(
            "catalog unavailable, using the bundled catalog",
            extra={"error_code": exc.response.get("Error", {}).get("Code")},
        )
        return bundled_catalog()
    except (BotoCoreError, KeyError, ValidationError) as exc:
        logger.warning(
            "catalog unreadable, using the bundled catalog",
            extra={"error_type": type(exc).__name__},
        )
        return bundled_catalog()
    if catalog.env is not None and catalog.env != settings.environment:
        logger.warning(
            "catalog is for another env, using the bundled catalog",
            extra={"catalog_env": catalog.env, "env": settings.environment},
        )
        return bundled_catalog()
    return catalog
