"""The five Datadog read APIs the agent calls: logs search, logs aggregate, events search,
one monitor and the metrics query.

Only ``POST /api/v2/logs/events/search``, ``POST /api/v2/logs/analytics/aggregate``,
``POST /api/v2/events/search``, ``GET /api/v1/monitor/{id}`` and ``GET /api/v1/query`` are
ever sent. Triage reads one monitor to verify a Datadog signal;
the tools read the rest. The API and application keys go in the request headers and
nowhere else: never into a log line, an error message or a tool result.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from devops_agent.config import Settings

LOGS_SEARCH_PATH = "/api/v2/logs/events/search"
LOGS_AGGREGATE_PATH = "/api/v2/logs/analytics/aggregate"
EVENTS_SEARCH_PATH = "/api/v2/events/search"
MONITOR_PATH = "/api/v1/monitor/{monitor_id}"
METRICS_QUERY_PATH = "/api/v1/query"
REQUEST_TIMEOUT_SECONDS = 10.0


class DatadogError(Exception):
    """A failed request, described by its HTTP status or error class only."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class DatadogClient:
    site: str
    api_key: str = field(repr=False)
    app_key: str = field(repr=False)

    @property
    def logs_search_url(self) -> str:
        return f"https://api.{self.site}{LOGS_SEARCH_PATH}"

    @property
    def logs_aggregate_url(self) -> str:
        return f"https://api.{self.site}{LOGS_AGGREGATE_PATH}"

    @property
    def events_search_url(self) -> str:
        return f"https://api.{self.site}{EVENTS_SEARCH_PATH}"

    def monitor_url(self, monitor_id: int) -> str:
        return f"https://api.{self.site}{MONITOR_PATH.format(monitor_id=int(monitor_id))}"

    @property
    def metrics_query_url(self) -> str:
        return f"https://api.{self.site}{METRICS_QUERY_PATH}"

    def search_logs(self, *, body: dict[str, Any]) -> dict[str, Any]:
        return _object(self._send(self.logs_search_url, "Datadog logs search", body))

    def aggregate_logs(self, *, body: dict[str, Any]) -> dict[str, Any]:
        return _object(self._send(self.logs_aggregate_url, "Datadog logs aggregate", body))

    def search_events(self, *, body: dict[str, Any]) -> dict[str, Any]:
        return _object(self._send(self.events_search_url, "Datadog events search", body))

    def get_monitor(self, *, monitor_id: int, params: dict[str, str]) -> dict[str, Any]:
        url = f"{self.monitor_url(monitor_id)}?{urllib.parse.urlencode(params)}"
        return _object(self._send(url, "Datadog monitor read", None))

    def query_metrics(self, *, params: dict[str, str]) -> dict[str, Any]:
        url = f"{self.metrics_query_url}?{urllib.parse.urlencode(params)}"
        return _object(self._send(url, "Datadog metrics query", None))

    def _send(self, url: str, label: str, body: dict[str, Any] | None) -> Any:
        """POST the body as JSON, or GET when there is none."""
        request = urllib.request.Request(
            url,
            data=None if body is None else json.dumps(body).encode(),
            method="GET" if body is None else "POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "DD-API-KEY": self.api_key,
                "DD-APPLICATION-KEY": self.app_key,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            hint = " (rate limited, try again later)" if exc.code == 429 else ""
            raise DatadogError(f"{label} failed: HTTP {exc.code}{hint}", exc.code) from None
        except (OSError, ValueError) as exc:
            raise DatadogError(f"{label} failed: {type(exc).__name__}") from None
        return payload


def _object(payload: Any) -> dict[str, Any]:
    return payload if isinstance(payload, dict) else {}


def datadog_client(settings: Settings) -> DatadogClient | None:
    """The client, or None when either key is missing and the Datadog tools are not offered."""
    api_key = settings.dd_api_key.get_secret_value() if settings.dd_api_key else ""
    app_key = settings.datadog_app_key.get_secret_value() if settings.datadog_app_key else ""
    if not api_key or not app_key:
        return None
    return DatadogClient(site=settings.datadog_site, api_key=api_key, app_key=app_key)
