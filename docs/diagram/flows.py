"""Renders the triage and investigator flowcharts, dark and light.

High level on purpose: no batch sizes, budgets or limits, so the picture stays true when
those settings change. Nodes are laid out left to right with one gap, so every arrow
between neighbours has the same length.

Run from the repo root: uv run python docs/diagram/flows.py docs
"""

import sys

from diagram import CARD_W, boundary, card, edge, exit_pill, gate, head, text, tile, write_both

GAP = 60  # arrow length between neighbouring nodes
LEFT = 44  # left edge of the first node
R = 27  # gate half-width
T = 26  # tile half-width
C = CARD_W / 2
HALF = {"tile": T, "card": C, "gate": R}


def place(kinds: list[str]) -> list[float]:
    """Centres for nodes of these kinds, left to right, GAP apart edge to edge."""
    xs, edge_x = [], LEFT
    for kind in kinds:
        xs.append(edge_x + HALF[kind])
        edge_x += 2 * HALF[kind] + GAP
    return xs


def chain(p: list[str], kinds: list[str], xs: list[float], lane: int, t: dict[str, str]) -> None:
    """One arrow from each node to the next."""
    for i in range(len(xs) - 1):
        p.append(edge([(xs[i] + HALF[kinds[i]], lane), (xs[i + 1] - HALF[kinds[i + 1]], lane)], t))


def footer(p: list[str], height: int, lines: str, t: dict[str, str]) -> None:
    p.append(text(32, height - 18, lines, t, size=11.5, fill="dim", anchor="start"))


def triage(t: dict[str, str]) -> str:
    lane = 210
    gates = [
        ("Opted out?", "skipped"),
        ("Open or cooling?", "repeat"),
        ("Shares a key?", "linked"),
        ("In a storm?", "grouped"),
        ("Over budget?", "deferred or skipped"),
    ]
    kinds = ["tile", "card", "card", *["gate"] * len(gates), "card", "tile"]
    xs = place(kinds)
    width, height = int(xs[-1] + T + 60), 500
    p = head(
        width,
        height,
        t,
        "Triage",
        "Decides, without a model, which signals earn an investigation. Every decision is recorded.",
    )
    queue, parse, settle, *gx, emit, work = xs
    p.append(tile(queue, lane, "sqs", "integration", "Alarms queue", "", t))
    p.append(card(parse, lane, "Parse", "signals, deduped", t))
    p.append(card(settle, lane, "Settle", "keys and severity", t))
    p.append(edge([(settle, lane + 29), (settle, 327)], t))
    p.append(exit_pill(settle, 340, "dropped", t))
    p.append(text(settle, 368, "unverified, stale or refused", t, size=10.5, fill="dim"))

    left, right = gx[0] - R - 44, gx[-1] + R + 52
    p.append(boundary(left, 120, right - left, 290, "GATES  ·  no model", "region", t, dashed=True))
    for x, (question, leaves) in zip(gx, gates, strict=True):
        p.append(gate(x, lane, question, t, r=R))
        p.append(edge([(x, lane + R), (x, 327)], t))
        p.append(exit_pill(x, 340, leaves, t))
    p.append(
        text((left + right) / 2, 390, "each exit is recorded on a finding", t, size=11, fill="dim")
    )

    p.append(card(emit, lane, "Emit", "claim keys, send", t))
    p.append(tile(work, lane, "sqs", "integration", "Work queue", "", t))
    chain(p, kinds, xs, lane, t)
    footer(
        p,
        height,
        "Right: the signal moves on. Down: it leaves there. A storm's head and urgent signals go on; "
        "the rest are grouped. Deferred signals return to the alarms queue while still in ALARM.",
        t,
    )
    p.append("</svg>")
    return "".join(p)


def investigator(t: dict[str, str]) -> str:
    lane = 220
    kinds = ["tile", "tile", "card", "card", "tile", "tile", "gate", "card", "tile", "card", "card"]
    xs = place(kinds)
    width, height = int(xs[-1] + C + 60), 430
    p = head(
        width,
        height,
        t,
        "Investigator",
        "Runs one investigation: read-only checks until the model reports, then a redacted, stored finding.",
    )
    queue, session, recall, precheck, reason, read, done, redact, store, remember, notify = xs
    p.append(tile(queue, lane, "sqs", "integration", "Work queue", "", t))
    p.append(tile(session, lane, "iam", "security", "Session", "own or member role", t))
    p.append(card(recall, lane, "Recall", "past reviewed findings", t))
    p.append(card(precheck, lane, "Precheck", "context, no model", t))

    left, right = reason - T - 50, done + R + 14
    p.append(boundary(left, 120, right - left, 230, "MODEL LOOP", "region", t, dashed=True))
    p.append(tile(reason, lane, "bedrock", "ml", "Reason", "hypotheses first", t))
    p.append(tile(read, lane, "iam", "security", "Read", "read-only tools", t))
    p.append(gate(done, lane, "Reported?", t, r=R))
    back = reason - T - 40  # clears the Reason label; enters Reason below the forward arrow
    p.append(
        edge(
            [
                (done, lane + R),
                (done, 318),
                (back, 318),
                (back, lane + 18),
                (reason - T, lane + 18),
            ],
            t,
            "not yet",
            (back + done) / 2,
            311,
        )
    )

    p.append(card(redact, lane, "Redact", "credentials removed", t))
    p.append(tile(store, lane, "dynamodb", "database", "Store", "findings table", t))
    p.append(card(remember, lane, "Remember", "when reported", t))
    p.append(card(notify, lane, "Notify", "optional", t, dashed=True))
    chain(p, kinds, xs, lane, t)
    p.append(text((right + redact - C) / 2, lane - 8, "done", t, size=10.5, fill="muted"))
    footer(
        p,
        height,
        "The loop runs until the model reports or gives up; a run without a report is still stored, "
        "as incomplete. With member accounts, the session is that account's read-only role, for this job only.",
        t,
    )
    p.append("</svg>")
    return "".join(p)


if __name__ == "__main__":
    write_both(triage, sys.argv[1], stem="triage-flow")
    write_both(investigator, sys.argv[1], stem="investigator-flow")
