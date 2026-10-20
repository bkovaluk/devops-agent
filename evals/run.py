"""Replay every labelled case, grade each run, and report the scores.

    uv run python -m evals.run [--profile NAME] [--model ID] [--judge-model ID] \\
        [--cases evals/cases] [--repeat 3] [--min-mean 65]

A case passes (pass@k) when any of its k runs scores at least 65. Exits 1 when the
mean over all runs is below --min-mean, or when there is no labelled case.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config

from devops_agent.agent import MODEL_READ_TIMEOUT_SECONDS
from devops_agent.config import Settings
from evals.judge import PASS_SCORE, judge
from evals.replay import replay

DEFAULT_CASES = Path("evals/cases")
DEFAULT_RESULTS = Path("evals/results")
DEFAULT_MODEL_ID: str = Settings.model_fields["model_id"].default


@dataclass(frozen=True)
class RunResult:
    score: int
    reason: str
    tool_misses: int
    tool_approximate: int
    outcome: str
    title: str


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    runs: list[RunResult]

    @property
    def mean(self) -> float:
        return sum(run.score for run in self.runs) / len(self.runs)

    @property
    def passed(self) -> bool:
        return any(run.score >= PASS_SCORE for run in self.runs)

    @property
    def tool_misses(self) -> int:
        return sum(run.tool_misses for run in self.runs)

    @property
    def tool_approximate(self) -> int:
        return sum(run.tool_approximate for run in self.runs)


def is_labelled(case: dict[str, Any]) -> bool:
    return bool(str(case.get("label", {}).get("root_cause", "")).strip())


def load_cases(directory: Path) -> list[tuple[str, dict[str, Any]]]:
    """The labelled cases in a directory as (case id, case), by file name."""
    cases = [(path.stem, json.loads(path.read_text())) for path in sorted(directory.glob("*.json"))]
    return [(case_id, case) for case_id, case in cases if is_labelled(case)]


def summarize(results: Sequence[CaseResult]) -> dict[str, Any]:
    scores = [run.score for result in results for run in result.runs]
    return {
        "mean": sum(scores) / len(scores) if scores else 0.0,
        "pass_rate": sum(result.passed for result in results) / len(results) if results else 0.0,
        "tool_misses": sum(result.tool_misses for result in results),
        "tool_approximate": sum(result.tool_approximate for result in results),
    }


def format_table(results: Sequence[CaseResult], repeat: int) -> str:
    pass_header = f"pass@{repeat}"
    width = max([len("case"), *(len(result.case_id) for result in results)])
    header = (
        f"{'case':<{width}}  {'scores':<{repeat * 4}}  {'mean':>5}  {pass_header}  misses  approx"
    )
    lines = [header, "-" * len(header)]
    for result in results:
        scores = " ".join(f"{run.score:>3}" for run in result.runs)
        passed = "yes" if result.passed else "no"
        lines.append(
            f"{result.case_id:<{width}}  {scores:<{repeat * 4}}  {result.mean:>5.1f}  "
            f"{passed:<{len(pass_header)}}  {result.tool_misses:<6}  {result.tool_approximate}"
        )
    overall = summarize(results)
    lines.append(
        f"mean {overall['mean']:.1f}  {pass_header} {overall['pass_rate']:.0%}  "
        f"tool misses {overall['tool_misses']}  approximate {overall['tool_approximate']}"
    )
    return "\n".join(lines)


def _run_case(case: dict[str, Any], bedrock: Any, model_id: str, judge_model_id: str) -> RunResult:
    result = replay(case, bedrock, model_id, datetime.now(UTC))
    verdict = judge(bedrock, judge_model_id, case["label"], result.finding)
    return RunResult(
        verdict.score,
        verdict.reason,
        result.tool_misses,
        result.tool_approximate,
        result.finding.outcome,
        result.finding.title,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay and grade the labelled eval cases.")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--model", default=DEFAULT_MODEL_ID)
    parser.add_argument("--judge-model", default=DEFAULT_MODEL_ID)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--min-mean", type=float)
    args = parser.parse_args(argv)
    repeat = max(args.repeat, 1)

    cases = load_cases(args.cases)
    if not cases:
        print(f"no labelled cases in {args.cases}", file=sys.stderr)
        return 1
    bedrock = boto3.Session(profile_name=args.profile, region_name=args.region).client(
        "bedrock-runtime",
        config=Config(read_timeout=MODEL_READ_TIMEOUT_SECONDS, retries={"mode": "standard"}),
    )

    started_at = datetime.now(UTC)
    results = [
        CaseResult(
            case_id,
            [_run_case(case, bedrock, args.model, args.judge_model) for _ in range(repeat)],
        )
        for case_id, case in cases
    ]
    print(format_table(results, repeat))

    overall = summarize(results)
    args.results.mkdir(parents=True, exist_ok=True)
    out = args.results / f"{started_at.strftime('%Y%m%dT%H%M%SZ')}.json"
    record = {
        "started_at": started_at.isoformat(),
        "model_id": args.model,
        "judge_model_id": args.judge_model,
        "repeat": repeat,
        "cases": [
            {
                "case_id": result.case_id,
                "runs": [asdict(run) for run in result.runs],
                "mean": result.mean,
                "passed": result.passed,
            }
            for result in results
        ],
        **overall,
    }
    out.write_text(json.dumps(record, indent=2) + "\n")
    print(f"wrote {out}")

    if args.min_mean is not None and overall["mean"] < args.min_mean:
        print(f"mean {overall['mean']:.1f} is below {args.min_mean}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
