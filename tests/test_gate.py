"""Hourly and daily investigation budgets and the daily token counter."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from devops_agent.gate import (
    add_daily_tokens,
    consume_daily_budget,
    consume_hourly_budget,
    daily_tokens,
    hourly_count,
    refund_daily_budget,
    refund_hourly_budget,
)
from tests.conftest import FakeTable

NOW = datetime(2026, 9, 29, 14, 5, tzinfo=UTC)


def test_daily_budget_counts_per_utc_day() -> None:
    table = FakeTable()
    assert consume_daily_budget(table, 2, NOW)
    update = table.updates[0]
    assert update["Key"] == {"pk": "budget#2026-09-29"}
    assert update["ReturnValues"] == "UPDATED_NEW"
    assert "ADD #count :delta" in update["UpdateExpression"]
    assert update["ExpressionAttributeValues"][":delta"] == 1
    assert update["ExpressionAttributeValues"][":ttl"] == int(NOW.timestamp()) + 3 * 86400


def test_daily_budget_over_cap_is_refused() -> None:
    table = FakeTable()
    assert consume_daily_budget(table, 2, NOW)
    assert consume_daily_budget(table, 2, NOW)
    assert not consume_daily_budget(table, 2, NOW)
    assert consume_daily_budget(table, 2, NOW + timedelta(days=1))


def test_hourly_budget_counts_per_utc_hour() -> None:
    table = FakeTable()
    assert consume_hourly_budget(table, 1, NOW)
    assert table.updates[0]["Key"] == {"pk": "budget#2026-09-29T14"}
    assert not consume_hourly_budget(table, 1, NOW + timedelta(minutes=30))
    assert consume_hourly_budget(table, 1, NOW + timedelta(hours=1))


def test_hourly_count_reads_the_counter() -> None:
    table = FakeTable()
    assert hourly_count(table, NOW) == 0
    consume_hourly_budget(table, 10, NOW)
    consume_hourly_budget(table, 10, NOW)
    assert hourly_count(table, NOW) == 2
    assert hourly_count(table, NOW + timedelta(hours=1)) == 0


def test_refunds_take_back_one_count() -> None:
    table = FakeTable()
    consume_hourly_budget(table, 10, NOW)
    consume_daily_budget(table, 10, NOW)
    refund_hourly_budget(table, NOW)
    refund_daily_budget(table, NOW)
    assert hourly_count(table, NOW) == 0
    assert table.items["budget#2026-09-29"]["count"] == 0
    assert table.updates[-1]["ExpressionAttributeValues"][":delta"] == -1


def test_daily_tokens_are_added_atomically_per_utc_day() -> None:
    table = FakeTable()
    assert daily_tokens(table, NOW) == 0
    add_daily_tokens(table, 12_000, NOW)
    add_daily_tokens(table, 3_500, NOW)
    update = table.updates[0]
    assert update["Key"] == {"pk": "budget#tokens#day#2026-09-29"}
    assert update["UpdateExpression"].startswith("ADD #count :delta")
    assert update["ExpressionAttributeValues"][":delta"] == 12_000
    assert update["ExpressionAttributeValues"][":ttl"] == int(NOW.timestamp()) + 3 * 86400
    assert daily_tokens(table, NOW) == 15_500
    assert daily_tokens(table, NOW + timedelta(days=1)) == 0


def test_daily_tokens_are_apart_from_the_investigation_counters() -> None:
    table = FakeTable()
    add_daily_tokens(table, 9_000, NOW)
    assert consume_daily_budget(table, 1, NOW)
    assert hourly_count(table, NOW) == 0
    assert daily_tokens(table, NOW) == 9_000
