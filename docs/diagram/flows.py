"""Renders the triage and investigator flowcharts, dark and light.

High level on purpose: no batch sizes, budgets or limits, so the picture stays true when
those settings change.

Run from the repo root: uv run python docs/diagram/flows.py docs
"""

import sys

from diagram import CARD_W, boundary, card, edge, exit_pill, gate, head, text, tile, write_both

R = 27  # gate half-width
T = 26  # tile half-width
C = CARD_W / 2


def triage(t: dict[str, str]) -> str:
    width, height, lane = 1400, 500, 210
    p = head(
        width,
        height,
        t,
        "Triage",
        "Decides, without a model, which signals earn an investigation. Every decision is recorded.",
    )
    p.append(tile(70, lane, "sqs", "integration", "Alarms queue", "", t))
    p.append(card(205, lane, "Parse", "signals, deduped", t))
    p.append(card(345, lane, "Settle", "keys and severity", t))
    p.append(edge([(70 + T, lane), (205 - C, lane)], t))
    p.append(edge([(205 + C, lane), (345 - C, lane)], t))
    p.append(edge([(345, lane + 29), (345, 327)], t))
    p.append(exit_pill(345, 340, "dropped", t))
    p.append(text(345, 368, "unverified, stale or refused", t, size=10.5, fill="dim"))

    p.append(boundary(420, 120, 690, 290, "GATES  ·  no model", "region", t, dashed=True))
    gates = [
        ("Opted out?", "skipped"),
        ("Open or cooling down?", "repeat"),
        ("Shares a key?", "linked"),
        ("Part of a storm?", "grouped"),
        ("Over budget?", "deferred or skipped"),
    ]
    xs = [480 + i * 130 for i in range(len(gates))]
    p.append(edge([(345 + C, lane), (xs[0] - R, lane)], t))
    for i, (x, (question, leaves)) in enumerate(zip(xs, gates, strict=True)):
        p.append(gate(x, lane, question, t, r=R))
        p.append(edge([(x, lane + R), (x, 327)], t))
        p.append(exit_pill(x, 340, leaves, t))
        if i + 1 < len(xs):
            p.append(edge([(x + R, lane), (xs[i + 1] - R, lane)], t))
    p.append(text(765, 390, "each exit is recorded on a finding", t, size=11, fill="dim"))

    p.append(card(1190, lane, "Emit", "claim keys, send", t))
    p.append(tile(1325, lane, "sqs", "integration", "Work queue", "", t))
    p.append(edge([(xs[-1] + R, lane), (1190 - C, lane)], t))
    p.append(edge([(1190 + C, lane), (1325 - T, lane)], t))

    p.append(
        text(
            32,
            height - 18,
            "Right: the signal moves on. Down: it leaves there. A storm's head and urgent signals go on; "
            "the rest are grouped. Deferred signals return to the alarms queue while still in ALARM.",
            t,
            size=11.5,
            fill="dim",
            anchor="start",
        )
    )
    p.append("</svg>")
    return "".join(p)


def investigator(t: dict[str, str]) -> str:
    width, height, lane = 1520, 430, 220
    p = head(
        width,
        height,
        t,
        "Investigator",
        "Runs one investigation: read-only checks until the model reports, then a redacted, stored finding.",
    )
    p.append(tile(70, lane, "sqs", "integration", "Work queue", "", t))
    p.append(tile(185, lane, "iam", "security", "Session", "own or member role", t))
    p.append(edge([(70 + T, lane), (185 - T, lane)], t))
    x = 125  # everything after the session step
    p.append(card(200 + x, lane, "Recall", "past reviewed findings", t))
    p.append(card(340 + x, lane, "Precheck", "context, no model", t))
    p.append(edge([(185 + T, lane), (200 + x - C, lane)], t))
    p.append(edge([(200 + x + C, lane), (340 + x - C, lane)], t))

    p.append(boundary(410 + x, 120, 390, 230, "MODEL LOOP", "region", t, dashed=True))
    p.append(tile(500 + x, lane, "bedrock", "ml", "Reason", "hypotheses first", t))
    p.append(tile(625 + x, lane, "iam", "security", "Read", "read-only tools", t))
    p.append(gate(745 + x, lane, "Reported?", t, r=R))
    p.append(edge([(340 + x + C, lane), (500 + x - T, lane)], t))
    p.append(edge([(500 + x + T, lane), (625 + x - T, lane)], t))
    p.append(edge([(625 + x + T, lane), (745 + x - R, lane)], t))
    p.append(
        edge(
            [
                (745 + x, lane + R),
                (745 + x, 318),
                (428 + x, 318),
                (428 + x, lane),
                (500 + x - T, lane),
            ],
            t,
            "not yet",
            610 + x,
            311,
        )
    )

    p.append(card(870 + x, lane, "Redact", "credentials removed", t))
    p.append(tile(1005 + x, lane, "dynamodb", "database", "Store", "findings table", t))
    p.append(card(1135 + x, lane, "Remember", "when reported", t))
    p.append(card(1270 + x, lane, "Notify", "optional", t, dashed=True))
    p.append(edge([(745 + x + R, lane), (870 + x - C, lane)], t, "done", 790 + x, lane - 8))
    p.append(edge([(870 + x + C, lane), (1005 + x - T, lane)], t))
    p.append(edge([(1005 + x + T, lane), (1135 + x - C, lane)], t))
    p.append(edge([(1135 + x + C, lane), (1270 + x - C, lane)], t))

    p.append(
        text(
            32,
            height - 18,
            "The loop runs until the model reports or gives up; a run without a report is still stored, "
            "as incomplete. Limits make the model report from what it has; a fallback model covers outages. "
            "With member accounts, the session is that account's read-only role, for this job only.",
            t,
            size=11.5,
            fill="dim",
            anchor="start",
        )
    )
    p.append("</svg>")
    return "".join(p)


if __name__ == "__main__":
    write_both(triage, sys.argv[1], stem="triage-flow")
    write_both(investigator, sys.argv[1], stem="investigator-flow")
