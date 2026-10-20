"""Investigation snapshots: what the model read, kept so an eval can replay the run.

A snapshot holds the job, the context bundle, the reviewed prior findings the model was
given, the tools it was offered and every tool call with the result text it read. Tool
results and the bundle are already redacted and capped; call inputs are redacted here.
"""

from __future__ import annotations

import base64
import gzip
import json
from collections.abc import Sequence
from typing import Any

from devops_agent.agent import Investigation
from devops_agent.models import InvestigationJob
from devops_agent.redact import redact_value

# Above this the JSON is stored gzipped and base64-encoded; DynamoDB items cap at 400 KB.
MAX_PLAIN_SNAPSHOT_BYTES = 300_000
MAX_SNAPSHOT_BYTES = 380_000
# The fields of a reviewed prior finding the opening message reads.
PRIOR_FIELDS = (
    "created_at",
    "status",
    "resolution",
    "severity",
    "title",
    "fix_effort",
    "likely_cause",
)


def build_snapshot(
    *,
    env: str,
    job: InvestigationJob,
    context: str,
    prior: Sequence[dict[str, Any]],
    tools: Sequence[str],
    investigation: Investigation,
) -> dict[str, Any]:
    return {
        "env": env,
        "job": job.model_dump(mode="json", by_alias=True),
        "context": context,
        "prior": [
            {field: str(item[field]) for field in PRIOR_FIELDS if field in item} for item in prior
        ],
        "tools": list(tools),
        "model_id": investigation.model_id,
        "tokens_used": investigation.tokens_used,
        "weighted_tokens": investigation.weighted_tokens,
        "calls": [{**call, "input": redact_value(call["input"])} for call in investigation.calls],
    }


def encode_snapshot(snapshot: dict[str, Any]) -> dict[str, str] | None:
    """The item attribute holding the snapshot, or None when it is too large to store."""
    raw = json.dumps(snapshot, separators=(",", ":"), default=str)
    if len(raw.encode()) <= MAX_PLAIN_SNAPSHOT_BYTES:
        return {"snapshot": raw}
    packed = base64.b64encode(gzip.compress(raw.encode())).decode()
    if len(packed) > MAX_SNAPSHOT_BYTES:
        return None
    return {"snapshot_gz": packed}


def decode_snapshot(item: dict[str, Any]) -> dict[str, Any]:
    """The snapshot a snap# item holds."""
    if "snapshot_gz" in item:
        raw = gzip.decompress(base64.b64decode(item["snapshot_gz"])).decode()
    else:
        raw = item["snapshot"]
    snapshot: dict[str, Any] = json.loads(raw)
    return snapshot
