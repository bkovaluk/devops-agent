"""Export a stored finding and its snapshot as an eval case with an empty label.

    uv run python -m evals.export --table <findings-table> [--profile <profile>] \\
        --finding-id <id> --out evals/cases/<name>.json

--table defaults to FINDINGS_TABLE; without --profile, boto3's default credential chain
(AWS_PROFILE included) applies. Reads only: two GetItem calls on the findings table.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import boto3

from devops_agent.snapshot import decode_snapshot

# Fields of the original finding kept in the case for the person labelling it.
FINDING_FIELDS = (
    "title",
    "summary",
    "likely_cause",
    "evidence",
    "error_signature",
    "confidence",
    "confidence_reason",
    "hypotheses",
    "severity",
    "outcome",
    "status",
    "resolution",
    "resolution_note",
)


def build_case(finding: dict[str, Any], snapshot_item: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": finding["finding_id"],
        "snapshot": decode_snapshot(snapshot_item),
        "label": {"root_cause": "", "key_evidence": [], "notes": ""},
        "exclude": [],
        "finding": {field: finding[field] for field in FINDING_FIELDS if field in finding},
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a finding as an eval case.")
    parser.add_argument("--table", default=os.environ.get("FINDINGS_TABLE"))
    parser.add_argument("--profile", default=None)
    parser.add_argument("--finding-id", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args(argv)
    if not args.table:
        parser.error("--table is required when FINDINGS_TABLE is not set")

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    table = session.resource("dynamodb").Table(args.table)
    finding = table.get_item(Key={"pk": f"finding#{args.finding_id}"}).get("Item")
    snapshot_item = table.get_item(Key={"pk": f"snap#{args.finding_id}"}).get("Item")
    if finding is None or snapshot_item is None:
        missing = "finding" if finding is None else "snapshot"
        print(f"no {missing} stored for {args.finding_id}", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    case = build_case(finding, snapshot_item)
    args.out.write_text(json.dumps(case, indent=2, default=str) + "\n")
    print(f"wrote {args.out}; fill in label.root_cause and label.key_evidence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
