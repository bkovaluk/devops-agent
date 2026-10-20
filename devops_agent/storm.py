"""Storm mode across batches: one investigation while the signal rate stays high.

Triage adds every first firing it accepts to a 5-minute bucket (gate.py); a deferred
signal sent back for retry is not counted again, and a redelivered SQS record is (the
rate is a flood detector, so the rare double count is accepted). When the previous
and the current bucket both hold more than ``storm_rate`` signals, triage opens a storm:
``storm#active`` names the storm finding and the highest-priority signal it was opened
with (its head, by the id its deferral would be recorded under, so a deferred head that
comes back is still the head). Priority 1 and 2 signals keep going through the budgets as
usual; every priority 3 or 4 signal is grouped onto the storm finding, which counts them by
source and by primary resource key, until a full bucket stays at or below the rate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

from devops_agent.gate import RATE_BUCKET, add_signals, signal_rate

STORM_PK = "storm#active"
STORM_TTL = timedelta(hours=24)


@dataclass(frozen=True)
class Storm:
    """The open storm: its finding and its head's deferral id."""

    storm_id: str
    head_id: str


def _condition_failed(exc: ClientError) -> bool:
    code: str = exc.response.get("Error", {}).get("Code", "")
    return code == "ConditionalCheckFailedException"


def _storm(item: dict[str, Any] | None, now: datetime) -> Storm | None:
    if not item or int(item["ttl"]) <= int(now.timestamp()):
        return None
    return Storm(str(item["finding_id"]), str(item["head_id"]))


def active_storm(table: Any, now: datetime) -> Storm | None:
    """The open storm; an item past its ttl counts as gone."""
    return _storm(table.get_item(Key={"pk": STORM_PK}).get("Item"), now)


def claim_storm(table: Any, storm: Storm, now: datetime) -> Storm:
    """Open the storm. When another invocation opened one first, that storm."""
    try:
        table.put_item(
            Item={
                "pk": STORM_PK,
                "finding_id": storm.storm_id,
                "head_id": storm.head_id,
                "created_at": now.isoformat(),
                "ttl": int((now + STORM_TTL).timestamp()),
            },
            ConditionExpression="attribute_not_exists(pk) OR #ttl < :now",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={":now": int(now.timestamp())},
        )
    except ClientError as exc:
        if not _condition_failed(exc):
            raise
        owner = _storm(table.get_item(Key={"pk": STORM_PK}, ConsistentRead=True).get("Item"), now)
        if owner is None:
            raise RuntimeError("storm item vanished after a failed claim") from None
        return owner
    return storm


def end_storm(table: Any, storm: Storm, now: datetime) -> None:
    """Expire the storm, leaving one another invocation has since opened."""
    try:
        table.update_item(
            Key={"pk": STORM_PK},
            UpdateExpression="SET #ttl = :now",
            ConditionExpression="finding_id = :id",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={":now": int(now.timestamp()) - 1, ":id": storm.storm_id},
        )
    except ClientError as exc:
        if not _condition_failed(exc):
            raise


def set_storm_head(table: Any, storm_id: str, head_record: str, summary: str) -> None:
    """Point the storm finding at the head's newest record: its job, or its deferral."""
    table.update_item(
        Key={"pk": f"finding#{storm_id}"},
        UpdateExpression="SET linked_to = :head, summary = :summary",
        ConditionExpression="attribute_exists(pk)",
        ExpressionAttributeValues={":head": head_record, ":summary": summary},
    )


def count_on_storm(
    table: Any, storm_id: str, source: str, resource_key: str, now: datetime
) -> bool:
    """Count one grouped signal on the storm finding. False when it is not stored yet."""
    try:
        table.update_item(
            Key={"pk": f"finding#{storm_id}"},
            UpdateExpression=(
                "ADD alarm_count :one, source_counts.#source :one, "
                "resource_counts.#resource :one SET last_seen_at = :now"
            ),
            ConditionExpression="attribute_exists(pk)",
            ExpressionAttributeNames={"#source": source, "#resource": resource_key},
            ExpressionAttributeValues={":one": 1, ":now": now.isoformat()},
        )
    except ClientError as exc:
        if _condition_failed(exc):
            return False
        raise
    return True


@dataclass(frozen=True)
class Rate:
    previous: int
    current: int


def record_rate(table: Any, accepted: int, now: datetime) -> Rate:
    """Add this batch's accepted signals; the previous and current bucket counts."""
    current = add_signals(table, accepted, now) if accepted else signal_rate(table, now)
    return Rate(signal_rate(table, now - RATE_BUCKET), current)
