"""Investigation budgets, the daily token counter and the signal rate, atomic counters
in the findings table.

A job is counted before it is sent and refunded when it is refused or not sent, so the
budget counters only keep the jobs that reached the work queue: the hourly and daily
budgets, the Datadog share of the hourly budget, and the priority 1 overflow past the
hourly budget. With member accounts, each account's jobs are also counted against its
own share of the hourly and daily budgets, so one noisy account cannot spend the others'.
The investigator adds each run's cost-weighted tokens to the day's token counter once the
run ends. Triage adds the signals it accepts to a 5-minute rate bucket, one per member
account (``scope``) and one for the agent's own account.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

BUDGET_TTL = timedelta(days=3)
RATE_BUCKET = timedelta(minutes=5)


def _hour_key(now: datetime) -> str:
    return f"budget#{now.strftime('%Y-%m-%dT%H')}"


def _day_key(now: datetime) -> str:
    return f"budget#{now.strftime('%Y-%m-%d')}"


def _day_tokens_key(now: datetime) -> str:
    return f"budget#tokens#day#{now.strftime('%Y-%m-%d')}"


def _datadog_hour_key(now: datetime) -> str:
    return f"budget#datadog#{now.strftime('%Y-%m-%dT%H')}"


def _p1_overflow_key(now: datetime) -> str:
    return f"budget#p1#day#{now.strftime('%Y-%m-%d')}"


def _account_hour_key(account_id: str, now: datetime) -> str:
    return f"budget#account#{account_id}#{now.strftime('%Y-%m-%dT%H')}"


def _account_day_key(account_id: str, now: datetime) -> str:
    return f"budget#account#{account_id}#{now.strftime('%Y-%m-%d')}"


def _rate_key(at: datetime, scope: str) -> str:
    minute = at.minute - at.minute % (RATE_BUCKET.seconds // 60)
    prefix = f"rate#{scope}#" if scope else "rate#"
    return f"{prefix}{at.strftime('%Y-%m-%dT%H')}:{minute:02d}"


def _count(table: Any, pk: str) -> int:
    item = table.get_item(Key={"pk": pk}).get("Item") or {}
    return int(item.get("count", 0))


def _add(table: Any, pk: str, delta: int, now: datetime) -> int:
    response = table.update_item(
        Key={"pk": pk},
        UpdateExpression="ADD #count :delta SET #ttl = if_not_exists(#ttl, :ttl)",
        ExpressionAttributeNames={"#count": "count", "#ttl": "ttl"},
        ExpressionAttributeValues={":delta": delta, ":ttl": int((now + BUDGET_TTL).timestamp())},
        ReturnValues="UPDATED_NEW",
    )
    return int(response["Attributes"]["count"])


def hourly_count(table: Any, now: datetime) -> int:
    """Investigations counted so far in this (UTC) hour."""
    return _count(table, _hour_key(now))


def daily_tokens(table: Any, now: datetime) -> int:
    """Cost-weighted model tokens investigations spent so far this (UTC) day."""
    return _count(table, _day_tokens_key(now))


def add_daily_tokens(table: Any, tokens: int, now: datetime) -> None:
    """Add one investigation's cost-weighted tokens to today's (UTC) token counter."""
    _add(table, _day_tokens_key(now), tokens, now)


def consume_hourly_budget(table: Any, limit: int, now: datetime) -> bool:
    """Count one investigation against this (UTC) hour's budget. False once past the cap."""
    return _add(table, _hour_key(now), 1, now) <= limit


def consume_daily_budget(table: Any, limit: int, now: datetime) -> bool:
    """Count one investigation against today's (UTC) budget. False once past the cap."""
    return _add(table, _day_key(now), 1, now) <= limit


def refund_hourly_budget(table: Any, now: datetime) -> None:
    """Take back one investigation counted against this hour's budget."""
    _add(table, _hour_key(now), -1, now)


def refund_daily_budget(table: Any, now: datetime) -> None:
    """Take back one investigation counted against today's budget."""
    _add(table, _day_key(now), -1, now)


def consume_datadog_share(table: Any, limit: int, now: datetime) -> bool:
    """Count one Datadog job against its share of this hour's budget. False past the cap."""
    return _add(table, _datadog_hour_key(now), 1, now) <= limit


def refund_datadog_share(table: Any, now: datetime) -> None:
    _add(table, _datadog_hour_key(now), -1, now)


def consume_p1_overflow(table: Any, limit: int, now: datetime) -> bool:
    """Count one priority 1 job past the hourly budget against today's overflow."""
    return _add(table, _p1_overflow_key(now), 1, now) <= limit


def refund_p1_overflow(table: Any, now: datetime) -> None:
    _add(table, _p1_overflow_key(now), -1, now)


def consume_account_hourly_budget(table: Any, limit: int, now: datetime, account_id: str) -> bool:
    """Count one job against its account's share of this hour. False once past the cap."""
    return _add(table, _account_hour_key(account_id, now), 1, now) <= limit


def refund_account_hourly_budget(table: Any, now: datetime, account_id: str) -> None:
    _add(table, _account_hour_key(account_id, now), -1, now)


def consume_account_daily_budget(table: Any, limit: int, now: datetime, account_id: str) -> bool:
    """Count one job against its account's share of today. False once past the cap."""
    return _add(table, _account_day_key(account_id, now), 1, now) <= limit


def refund_account_daily_budget(table: Any, now: datetime, account_id: str) -> None:
    _add(table, _account_day_key(account_id, now), -1, now)


def add_signals(table: Any, count: int, now: datetime, scope: str = "") -> int:
    """Add accepted signals to the current 5-minute bucket of a member account (``scope``)
    or of the agent's own account; its count after the add."""
    return _add(table, _rate_key(now, scope), count, now)


def signal_rate(table: Any, at: datetime, scope: str = "") -> int:
    """Signals counted in the 5-minute bucket holding ``at``."""
    return _count(table, _rate_key(at, scope))
