"""Active-job items: the resource keys an emitted investigation covers, for 20 minutes.

``active#<resource_key>`` holds the job's finding_id and the alarms triage linked to it
while it runs. Triage writes them on emit; the investigator reads linked_alarms back when
it stores the finding.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

ACTIVE_TTL = timedelta(minutes=20)


def _pk(resource_key: str) -> str:
    return f"active#{resource_key}"


def _condition_failed(exc: ClientError) -> bool:
    code: str = exc.response.get("Error", {}).get("Code", "")
    return code == "ConditionalCheckFailedException"


def claim_keys(
    table: Any, keys: Sequence[str], finding_id: str, now: datetime
) -> tuple[str, str] | None:
    """Mark every key as covered by the job. None when all are claimed.

    A key a running job already holds is not taken: the keys claimed so far are released
    and (key, owner finding_id) is returned.
    """
    expires = int((now + ACTIVE_TTL).timestamp())
    claimed: list[str] = []
    for key in keys:
        try:
            table.put_item(
                Item={
                    "pk": _pk(key),
                    "finding_id": finding_id,
                    "linked_alarms": [],
                    "created_at": now.isoformat(),
                    "ttl": expires,
                },
                ConditionExpression="attribute_not_exists(pk) OR #ttl < :now",
                ExpressionAttributeNames={"#ttl": "ttl"},
                ExpressionAttributeValues={":now": int(now.timestamp())},
            )
        except ClientError as exc:
            if not _condition_failed(exc):
                release_keys(table, claimed, finding_id, now)
                raise
            release_keys(table, claimed, finding_id, now)
            owner = table.get_item(Key={"pk": _pk(key)}, ConsistentRead=True).get("Item")
            if owner is None:
                raise RuntimeError("active item vanished after a failed claim") from None
            return key, str(owner["finding_id"])
        claimed.append(key)
    return None


def release_keys(table: Any, keys: Sequence[str], finding_id: str, now: datetime) -> None:
    """Expire the job's items, leaving any key another job has since claimed.

    The ttl goes one second into the past, so a claim in the same second can take the key.
    """
    for key in keys:
        try:
            table.update_item(
                Key={"pk": _pk(key)},
                UpdateExpression="SET #ttl = :now",
                ConditionExpression="finding_id = :id",
                ExpressionAttributeNames={"#ttl": "ttl"},
                ExpressionAttributeValues={
                    ":now": int(now.timestamp()) - 1,
                    ":id": finding_id,
                },
            )
        except ClientError as exc:
            if not _condition_failed(exc):
                raise


def active_job(table: Any, keys: Sequence[str], now: datetime) -> tuple[str, str] | None:
    """The (key, finding_id) of the first key a running job covers, if any.

    DynamoDB deletes expired items late, so an item past its ttl counts as gone.
    """
    for key in keys:
        item = table.get_item(Key={"pk": _pk(key)}).get("Item")
        if item and int(item["ttl"]) > int(now.timestamp()):
            return key, str(item["finding_id"])
    return None


def link_alarm(table: Any, key: str, alarm_name: str, now: datetime) -> bool:
    """Append the alarm to the key's running job. False when the job's item has expired."""
    try:
        table.update_item(
            Key={"pk": _pk(key)},
            UpdateExpression=(
                "SET linked_alarms = list_append(if_not_exists(linked_alarms, :empty), :alarm)"
            ),
            ConditionExpression="attribute_exists(pk) AND #ttl > :now",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={
                ":empty": [],
                ":alarm": [alarm_name],
                ":now": int(now.timestamp()),
            },
        )
    except ClientError as exc:
        if _condition_failed(exc):
            return False
        raise
    return True


def linked_alarms(table: Any, keys: Sequence[str], finding_id: str) -> list[str]:
    """The alarms linked to the job across its keys, in link order, once each."""
    names: dict[str, None] = {}
    for key in keys:
        item = table.get_item(Key={"pk": _pk(key)}).get("Item")
        if item and item.get("finding_id") == finding_id:
            names.update(dict.fromkeys(str(name) for name in item.get("linked_alarms", [])))
    return list(names)
