"""Datadog signal verification: the monitor as Datadog reports it, not as the payload says.

A Datadog notification reaches the alarms queue through a partner event bus, so its
payload is untrusted. Triage reads the monitor back (``GET /api/v1/monitor/{id}`` with
``group_states=alert,warn``) and keeps the signal only when the monitor exists, carries
every tag in the catalog's ``datadog_monitor_tags``, its ``env`` tag names this env, and
the signal's group is still in Alert (or Warn, for priority 1). Reads are cached per
monitor in the process, 60 s for an answer and 30 s for a failed read, so a flood costs
one call per monitor a minute and an outage one failing call per monitor every 30 s.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from devops_agent.catalog import load_catalog
from devops_agent.datadog import DatadogClient, DatadogError
from devops_agent.signals import SIMPLE_GROUP, Signal, datadog_priority, tag_list

MONITOR_CACHE_SECONDS = 60.0
FAILED_READ_CACHE_SECONDS = 30.0
NOT_FOUND = 404

# monitor id -> (expiry on the monotonic clock, the monitor, None when it does not exist,
# or the error a failed read raised)
_monitors: dict[int, tuple[float, dict[str, Any] | DatadogError | None]] = {}


def clear_monitor_cache() -> None:
    _monitors.clear()


def read_monitor(
    client: DatadogClient, monitor_id: int, clock: Callable[[], float] = time.monotonic
) -> dict[str, Any] | None:
    """The monitor with its alerting and warning groups; None when Datadog has no such
    monitor. Any other failure raises DatadogError, again from the cache until it expires."""
    now = clock()
    cached = _monitors.get(monitor_id)
    if cached is not None and cached[0] > now:
        if isinstance(cached[1], DatadogError):
            raise DatadogError(str(cached[1]), cached[1].status)
        return cached[1]
    monitor: dict[str, Any] | None
    try:
        monitor = client.get_monitor(monitor_id=monitor_id, params={"group_states": "alert,warn"})
    except DatadogError as exc:
        if exc.status != NOT_FOUND:
            _monitors[monitor_id] = (now + FAILED_READ_CACHE_SECONDS, exc)
            raise
        monitor = None
    _monitors[monitor_id] = (now + MONITOR_CACHE_SECONDS, monitor)
    return monitor


@dataclass(frozen=True)
class Verdict:
    """The verified monitor, or why the signal is dropped.

    ``priority`` is the monitor's own priority, or the fallback when it has none.
    ``misrouted`` marks a monitor of another env.
    """

    monitor: dict[str, Any] | None
    priority: int
    reason: str | None = None
    misrouted: bool = False

    @property
    def verified(self) -> bool:
        return self.reason is None


def _group_status(monitor: dict[str, Any], group: str) -> str | None:
    state = monitor.get("state")
    groups = state.get("groups") if isinstance(state, dict) else None
    groups = groups if isinstance(groups, dict) else {}
    wanted = frozenset(group.split(","))
    for name, entry in groups.items():
        if frozenset(str(name).split(",")) == wanted and isinstance(entry, dict):
            status = entry.get("status")
            return status if isinstance(status, str) else None
    if group == SIMPLE_GROUP:
        overall = monitor.get("overall_state")
        return overall if isinstance(overall, str) else None
    return None


def verify_monitor(
    client: DatadogClient | None,
    signal: Signal,
    env: str,
    fallback_priority: int,
    clock: Callable[[], float] = time.monotonic,
) -> Verdict:
    """Whether a Datadog signal stands, read from the monitor itself."""
    if client is None:
        return Verdict(None, signal.priority, "the Datadog keys are not configured")
    monitor = read_monitor(client, int(signal.ref["monitor_id"]), clock)
    if monitor is None:
        return Verdict(None, signal.priority, "the monitor does not exist")
    priority = datadog_priority(monitor.get("priority")) or fallback_priority
    tags = [tag.lower() for tag in tag_list(monitor.get("tags"))]
    required = [tag.lower() for tag in load_catalog().agent.datadog_monitor_tags]
    missing = [tag for tag in required if tag not in tags]
    if missing:
        return Verdict(monitor, priority, f"the monitor lacks the {', '.join(missing)} tag")
    envs = [tag.partition(":")[2] for tag in tags if tag.startswith("env:")]
    if env not in envs:
        named = ", ".join(envs) or "none"
        return Verdict(monitor, priority, f"the monitor's env is {named}, not {env}", True)
    group = str(signal.ref.get("group") or "")
    if not group:
        return Verdict(monitor, priority, "the notification names no group")
    allowed = {"Alert", "Warn"} if priority == 1 else {"Alert"}
    status = _group_status(monitor, group)
    if status not in allowed:
        return Verdict(monitor, priority, f"the group is {status or 'not alerting'}")
    return Verdict(monitor, priority)
