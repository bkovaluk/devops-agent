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
    width, height, lane = 1400, 470, 210
    p = head(
        width,
        height,
        t,
        "Triage",
        "Decides, without a model, which signals earn an investigation. Every signal still gets a finding.",
    )
    p.append(tile(70, lane, "sqs", "integration", "Alarms queue", "", t))
    p.append(card(205, lane, "Parse", "signals, deduped", t))
    p.append(card(345, lane, "Settle", "keys and severity", t))
    p.append(edge([(70 + T, lane), (205 - C, lane)], t))
    p.append(edge([(205 + C, lane), (345 - C, lane)], t))

    p.append(boundary(420, 120, 690, 290, "GATES  ·  no model", "region", t, dashed=True))
    gates = [
        ("Opted out?", "skipped"),
        ("Already open?", "repeat"),
        ("Shares a key?", "linked"),
        ("Part of a storm?", "grouped"),
        ("Over budget?", "deferred"),
    ]
    xs = [480 + i * 130 for i in range(len(gates))]
    p.append(edge([(345 + C, lane), (xs[0] - R, lane)], t))
    for i, (x, (question, leaves)) in enumerate(zip(xs, gates, strict=True)):
        p.append(gate(x, lane, question, t, r=R))
        p.append(edge([(x, lane + R), (x, 327)], t))
        p.append(exit_pill(x, 340, leaves, t))
        if i + 1 < len(xs):
            p.append(edge([(x + R, lane), (xs[i + 1] - R, lane)], t))
    p.append(text(765, 390, "each exit records a finding", t, size=11, fill="dim"))

    p.append(card(1190, lane, "Emit", "claim keys, send", t))
    p.append(tile(1325, lane, "sqs", "integration", "Work queue", "", t))
    p.append(edge([(xs[-1] + R, lane), (1190 - C, lane)], t))
    p.append(edge([(1190 + C, lane), (1325 - T, lane)], t))

    p.append(
        text(
            32,
            height - 18,
            "Right: the signal moves on. Down: it leaves at that gate. Batch size, cooldowns, "
            "storm rate and budgets are settings, not shown here.",
            t,
            size=11.5,
            fill="dim",
            anchor="start",
        )
    )
    p.append("</svg>")
    return "".join(p)


def investigator(t: dict[str, str]) -> str:
    width, height, lane = 1400, 410, 220
    p = head(
        width,
        height,
        t,
        "Investigator",
        "Runs one investigation: read-only checks until the model reports, then a redacted, stored finding.",
    )
    p.append(tile(70, lane, "sqs", "integration", "Work queue", "", t))
    p.append(card(200, lane, "Recall", "past reviewed findings", t))
    p.append(card(340, lane, "Precheck", "context, no model", t))
    p.append(edge([(70 + T, lane), (200 - C, lane)], t))
    p.append(edge([(200 + C, lane), (340 - C, lane)], t))

    p.append(boundary(410, 120, 390, 230, "MODEL LOOP", "region", t, dashed=True))
    p.append(tile(500, lane, "bedrock", "ml", "Reason", "hypotheses first", t))
    p.append(tile(625, lane, "iam", "security", "Read", "read-only tools", t))
    p.append(gate(745, lane, "Reported?", t, r=R))
    p.append(edge([(340 + C, lane), (500 - T, lane)], t))
    p.append(edge([(500 + T, lane), (625 - T, lane)], t))
    p.append(edge([(625 + T, lane), (745 - R, lane)], t))
    p.append(
        edge(
            [(745, lane + R), (745, 318), (428, 318), (428, lane), (500 - T, lane)],
            t,
            "not yet",
            610,
            311,
        )
    )

    p.append(card(870, lane, "Redact", "credentials removed", t))
    p.append(tile(1005, lane, "dynamodb", "database", "Store", "findings table", t))
    p.append(card(1135, lane, "Notify", "optional", t, dashed=True))
    p.append(card(1270, lane, "Remember", "what returned data", t))
    p.append(edge([(745 + R, lane), (870 - C, lane)], t, "yes", 787, lane - 8))
    p.append(edge([(870 + C, lane), (1005 - T, lane)], t))
    p.append(edge([(1005 + T, lane), (1135 - C, lane)], t))
    p.append(edge([(1135 + C, lane), (1270 - C, lane)], t))

    p.append(
        text(
            32,
            height - 18,
            "The loop runs until the model reports. At its step, token or time limit it is told to "
            "report from the evidence it has; a fallback model covers outages.",
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
