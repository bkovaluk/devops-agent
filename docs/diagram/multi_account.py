"""Renders the multi-account diagram, dark and light: one central tooling account runs
the agent; every member account forwards its alarms and lends a read-only role.

Run from the repo root: uv run python docs/diagram/multi_account.py docs
"""

import sys

from diagram import boundary, edge, head, text, tile, write_both

ROW = 190  # the central pipeline
MEMBER_Y = 610  # tiles inside each member account
BUS_LANE = 768  # under the member accounts, then up the left edge to the central bus
TRUNK_X = 14  # the left edge the member buses climb
ROLE_LANE = 436  # STS down to each member's read-only role
MEMBERS = (("dev", 24), ("staging", 484), ("prod", 944))


def member(x0: int, env: str, t: dict[str, str]) -> list[str]:
    alarms, bus, role = x0 + 80, x0 + 220, x0 + 360
    return [
        boundary(x0, 490, 432, 250, f"MEMBER ACCOUNT  ·  {env}", "acct", t),
        tile(alarms, MEMBER_Y, "cloudwatch", "integration", "CloudWatch alarms", "any alarm", t),
        tile(bus, MEMBER_Y, "eventbridge", "integration", "Default bus", "rule: state ALARM", t),
        tile(role, MEMBER_Y, "iam", "security", "Read-only role", "trusts the agent", t),
        edge([(alarms + 28, MEMBER_Y), (bus - 28, MEMBER_Y)], t),
        # Out the bus's right side, under the accounts and up the left edge to the central
        # bus. The role lines come down from above, so the two never cross.
        edge(
            [
                (bus + 28, MEMBER_Y),
                (bus + 70, MEMBER_Y),
                (bus + 70, BUS_LANE),
                (TRUNK_X, BUS_LANE),
                (TRUNK_X, ROW),
                (82, ROW),
            ],
            t,
        ),
        # Down from STS to this account's role.
        edge([(680, 398), (680, ROLE_LANE), (role, ROLE_LANE), (role, MEMBER_Y - 28)], t),
    ]


def draw(t: dict[str, str]) -> str:
    width, height = 1400, 820
    p = head(
        width,
        height,
        t,
        "devops-agent, multi-account",
        "One tooling account runs the agent for every account. Members forward alarms and "
        "lend a read-only role; the agent never writes into a member account.",
    )
    p.append(
        boundary(24, 100, 1128, 316, "TOOLING ACCOUNT  ·  runs the agent  ·  one region", "acct", t)
    )
    p.append(boundary(1176, 100, 200, 316, "OUTBOUND, READ ONLY", "dim", t, dashed=True))

    p.append(
        tile(110, ROW, "eventbridge", "integration", "Central event bus", "org policy · rule", t)
    )
    p.append(tile(250, ROW, "sqs", "integration", "Alarms queue", "DLQ · backlog alarm", t))
    p.append(edge([(138, ROW), (222, ROW)], t))
    p.append(tile(390, ROW, "lambda", "compute", "Triage", "per-account budgets", t))
    p.append(edge([(278, ROW), (362, ROW)], t, "ESM", 320, ROW - 8))
    p.append(tile(530, ROW, "sqs", "integration", "Work queue", "DLQ · backlog alarm", t))
    p.append(edge([(418, ROW), (502, ROW)], t, "job", 460, ROW - 8))
    p.append(tile(680, ROW, "lambda", "compute", "Investigator", "one account per job", t))
    p.append(edge([(558, ROW), (652, ROW)], t, "ESM", 605, ROW - 8))

    # Findings and STS share one row under the pipeline; each gets one line in.
    p.append(tile(530, 330, "dynamodb", "database", "Findings table", "keyed by account", t))
    p.append(edge([(390, ROW + 68), (390, 330), (502, 330)], t, "claims", 398, 300, anchor="start"))
    p.append(
        edge(
            [(652, ROW + 20), (610, ROW + 20), (610, 330), (558, 330)],
            t,
            "findings",
            602,
            300,
            anchor="end",
        )
    )

    p.append(tile(680, 330, "iam", "security", "STS AssumeRole", "per job · per batch", t))
    p.append(edge([(680, ROW + 68), (680, 302)], t))

    p.append(tile(860, 330, "bedrock", "ml", "Amazon Bedrock", "own profiles", t))
    p.append(edge([(708, ROW + 20), (780, ROW + 20), (780, 330), (832, 330)], t))

    # The outbound line runs straight to Datadog; GitHub branches off a marked junction.
    out_y, fork_x = ROW - 14, 1110
    p.append(tile(1276, out_y, "saas", "saas", "Datadog API", "optional", t))
    p.append(tile(1276, 310, "code", "ext", "GitHub API", "optional", t))
    p.append(edge([(708, out_y), (1248, out_y)], t))
    p.append(edge([(fork_x, out_y), (fork_x, 310), (1248, 310)], t))
    p.append(f'<circle cx="{fork_x}" cy="{out_y}" r="3.5" fill="{t["arrow"]}"/>')

    for env, x0 in MEMBERS:
        p.extend(member(x0, env, t))

    p.append(
        text(
            330,
            BUS_LANE - 6,
            "ALARM events, cross-account rule, up to the central bus",
            t,
            size=11,
            fill="dim",
            anchor="start",
        )
    )
    p.append(text(690, 429, "assume role, read only", t, size=11, fill="dim", anchor="start"))

    p.append(
        text(
            32,
            height - 18,
            "Each member role trusts only the agent's role (with the external id, when set) and carries "
            "the same deny list. Triage and the investigator both read through it; every finding "
            "records the account it read.",
            t,
            size=11.5,
            fill="dim",
            anchor="start",
        )
    )
    p.append("</svg>")
    return "".join(p)


if __name__ == "__main__":
    write_both(draw, sys.argv[1], stem="multi-account")
