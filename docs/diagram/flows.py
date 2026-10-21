"""Renders the triage and investigator flowcharts, dark and light.

Run from the repo root: uv run python docs/diagram/flows.py docs
"""

import sys

from diagram import (
    STEP_W,
    decision,
    edge,
    head,
    outcome,
    step,
    text,
    write_both,
)

CX = 400  # the spine
ROW = 88  # vertical distance between nodes
TOP = 128
BRANCH_X = CX + STEP_W / 2 + 46  # where branch outcomes start
HALF = {"step": 29, "decision": 21, "pill": 14}

TRIAGE = [
    ("pill", "Alarms queue  ·  batches of up to 25 within 60 s", "integration"),
    ("step", "Parse", "signals by detail-type; drop non-ALARM and excluded names; dedupe"),
    ("step", "Settle", "resource keys from the metric, consumer Lambdas, Severity tag"),
    ("decision", "Tagged DevOpsAgent=off?", "yes", "skipped finding"),
    ("decision", "Already open, or closed within the cooldown?", "yes", "repeat: one more firing"),
    ("decision", "A running job or earlier signal shares a key?", "yes", "linked finding"),
    (
        "decision",
        "Alarm storm, or 5+ jobs left in the batch?",
        "yes",
        "the rest grouped onto one incident job",
    ),
    (
        "decision",
        "Within the budget for its priority?",
        "no",
        "P1/P2 deferred 15 min · P3/P4 skipped",
    ),
    ("step", "Emit", "claim the resource keys, count the budgets, send the job"),
    ("pill", "Work queue", "integration"),
]

INVESTIGATOR = [
    ("pill", "Work queue  ·  one job per run, at most 2 at once", "integration"),
    ("step", "Recall", "up to 3 reviewed findings on the same resource"),
    ("step", "Precheck", "code, no model: the context bundle for this alarm"),
    ("step", "Reason", "Bedrock Converse: hypotheses first, then pick a check"),
    ("step", "Read", "read-only tools: AWS through the guard, Datadog, GitHub"),
    ("loop", "Called report_finding?", 3, "no, next step"),
    ("step", "Redact", "credential shapes removed from every string field"),
    ("step", "Store", "the finding in DynamoDB, with its evidence trail"),
    ("step", "Notify", "optional: critical and high findings to the SNS topic"),
    ("step", "Remember", "which tool calls returned data, for next time"),
    ("pill", "Finding ready for review", "database"),
]


def pill(cy: float, label: str, cat: str, t: dict[str, str]) -> str:
    w = len(label) * 6.7 + 26
    return outcome(CX - w / 2, cy, label, cat, t)


def flow(nodes: list[tuple], t: dict[str, str]) -> list[str]:
    out: list[str] = []
    ys = [TOP + i * ROW for i in range(len(nodes))]
    n = 0
    for i, (node, y) in enumerate(zip(nodes, ys, strict=True)):
        kind = node[0]
        if kind == "pill":
            out.append(pill(y, node[1], node[2], t))
        elif kind == "step":
            n += 1
            out.append(step(CX, y, n, node[1], node[2], t))
        elif kind in ("decision", "loop"):
            out.append(decision(CX, y, node[1], t))
        if kind == "decision":
            _, _, branch, result = node
            out.append(
                edge([(CX + STEP_W / 2, y), (BRANCH_X, y)], t, branch, CX + STEP_W / 2 + 22, y - 7)
            )
            out.append(outcome(BRANCH_X + 4, y, result, "database", t))
        if kind == "loop":
            _, _, target, label = node
            ty = ys[target]
            left = CX - STEP_W / 2
            out.append(edge([(left, y), (left - 46, y), (left - 46, ty), (left, ty)], t))
            out.append(
                text(left - 52, (y + ty) / 2, label, t, size=10.5, fill="muted", anchor="end")
            )
        if i + 1 < len(nodes):
            nxt = nodes[i + 1][0]
            gap_from = y + HALF["decision" if kind == "loop" else kind]
            gap_to = ys[i + 1] - HALF["decision" if nxt == "loop" else nxt]
            label = None
            if kind == "decision":
                label = "yes" if node[2] == "no" else "no"
                if "incident" in node[3]:
                    label = "no, or the incident job"
            if kind == "loop":
                label = "yes"
            out.append(
                edge(
                    [(CX, gap_from), (CX, gap_to)],
                    t,
                    label,
                    CX + 8,
                    (gap_from + gap_to) / 2 + 4,
                    anchor="start",
                )
            )
    return out


def page(title: str, subtitle: str, nodes: list[tuple], footer: str):
    height = TOP + (len(nodes) - 1) * ROW + 70

    def draw(t: dict[str, str]) -> str:
        p = head(1100, height, t, title, subtitle)
        p.extend(flow(nodes, t))
        p.append(text(32, height - 18, footer, t, size=11.5, fill="dim", anchor="start"))
        p.append("</svg>")
        return "".join(p)

    return draw


if __name__ == "__main__":
    out = sys.argv[1]
    write_both(
        page(
            "Triage",
            "Decides, without a model, which signals earn an investigation. Every other signal still gets a finding.",
            TRIAGE,
            "Every decision writes one CloudWatch metric and one log line. A deferred signal goes back to the alarms queue while it stays in ALARM.",
        ),
        out,
        stem="triage-flow",
    )
    write_both(
        page(
            "Investigator",
            "Runs one investigation: read-only checks until the model reports, then a stored, redacted finding.",
            INVESTIGATOR,
            "The last step (MAX_STEPS, the token budget or the time reserve) is told to report from the evidence it has. If the model is unavailable, the fallback model runs.",
        ),
        out,
        stem="investigator-flow",
    )
