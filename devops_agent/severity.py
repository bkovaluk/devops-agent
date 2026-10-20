"""Severity floor and final severity. The model can raise severity, never lower it."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from devops_agent.catalog import load_catalog
from devops_agent.config import get_settings
from devops_agent.models import SEVERITY_PRIORITY, Severity

_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def alarm_tags(cloudwatch: Any, alarm_arn: str) -> dict[str, str]:
    """Tags on the alarm, as a plain dict."""
    response = cloudwatch.list_tags_for_resource(ResourceARN=alarm_arn)
    return {tag["Key"]: tag["Value"] for tag in response.get("Tags", [])}


def severity_floor(tags: Mapping[str, str]) -> Severity:
    """The alarm's Severity tag when it names a level, else the env default."""
    for key, value in tags.items():
        if key.lower() == "severity":
            try:
                return Severity(value.strip().lower())
            except ValueError:
                break
    return env_floor()


def rank(severity: Severity) -> int:
    """0 for low up to 3 for critical."""
    return _RANK[severity]


def priority(severity: Severity) -> int:
    """1 for critical down to 4 for low."""
    return SEVERITY_PRIORITY[severity]


def floor_for_priority(value: int) -> Severity:
    """The severity floor of a priority; past 4 (Datadog's P5) is low."""
    return next(
        (severity for severity, level in SEVERITY_PRIORITY.items() if level == value),
        Severity.LOW if value > 1 else Severity.CRITICAL,
    )


def env_floor() -> Severity:
    """The catalog's default severity for this env."""
    return load_catalog().default_severity(get_settings().environment)


def final_severity(floor: Severity, proposed: Severity | None) -> Severity:
    if proposed is None or _RANK[proposed] < _RANK[floor]:
        return floor
    return proposed


def notifies(severity: Severity) -> bool:
    return severity in load_catalog().agent.notify
