"""Renders the multi-account diagram, dark and light: one central tooling account runs
the agent; every member account forwards its alarms and lends a read-only role.

Run from the repo root: uv run python docs/diagram/multi_account.py docs
"""

import sys

from diagram import boundary, edge, head, text, tile, write_both

ROW = 190  # the central pipeline
MEMBER_Y = 610  # tiles inside each member account
BUS_LANE = 466  # member buses up to the central bus
ROLE_LANE = 450  # STS down to each member's read-only role
MEMBERS = (("dev", 24), ("staging", 484), ("prod", 944))


def member(x0: int, env: str, t: dict[str, str]) -> list[str]:
    alarms, bus, role = x0 + 80, x0 + 220, x0 + 360
    return [
        boundary(x0, 490, 432, 250, f"MEMBER ACCOUNT  ·  {env}", "acct", t),
        tile(alarms, MEMBER_Y, "cloudwatch", "integration", "CloudWatch alarms", "any alarm", t),
        tile(bus, MEMBER_Y, "eventbridge", "integration", "Default bus", "rule: state ALARM", t),
        tile(role, MEMBER_Y, "iam", "security", "Read-only role", "trusts the agent", t),
        edge([(alarms + 28, MEMBER_Y), (bus - 28, MEMBER_Y)], t),
        # Up to the central bus.
        edge([(bus, MEMBER_Y - 28), (bus, BUS_LANE), (48, BUS_LANE), (48, ROW), (82, ROW)], t),
        # Down from STS to this account's role.
        edge([(680, 398), (680, ROLE_LANE), (role, ROLE_LANE), (role, MEMBER_Y - 28)], t),
    ]


def draw(t: dict[str, str]) -> str:
    width, height = 1400, 800
    p = head(
        width,
        height,
        t,
        "devops-agent, multi-account",
        "One tooling account runs the agent for every account. Members forward alarms and "
        "lend a read-only role; nothing in a member account can write back.",
    )
    p.append(boundary(24, 100, 1128, 330, "TOOLING ACCOUNT  ·  runs the agent", "acct", t))
    p.append(boundary(1176, 100, 200, 330, "OUTBOUND, READ ONLY", "dim", t, dashed=True))

    p.append(
        tile(110, ROW, "eventbridge", "integration", "Central event bus", "org-only policy", t)
    )
    p.append(tile(250, ROW, "sqs", "integration", "Alarms queue", "DLQ · backlog alarm", t))
    p.append(edge([(138, ROW), (222, ROW)], t))
    p.append(tile(390, ROW, "lambda", "compute", "Triage", "per-account budgets", t))
    p.append(edge([(278, ROW), (362, ROW)], t, "ESM", 320, ROW - 8))
    p.append(tile(530, ROW, "sqs", "integration", "Work queue", "DLQ · backlog alarm", t))
    p.append(edge([(418, ROW), (502, ROW)], t, "job", 460, ROW - 8))
    p.append(tile(680, ROW, "lambda", "compute", "Investigator", "one account per job", t))
    p.append(edge([(558, ROW), (652, ROW)], t, "ESM", 605, ROW - 8))

    p.append(tile(530, 340, "dynamodb", "database", "Findings table", "keyed by account", t))
    p.append(edge([(390, ROW + 68), (390, 350), (502, 350)], t, "claims", 398, 300, anchor="start"))
    p.append(edge([(652, ROW + 14), (610, ROW + 14), (610, 330), (558, 330)], t))

    p.append(tile(680, 330, "iam", "security", "STS AssumeRole", "per job, 15 min", t))
    p.append(edge([(680, ROW + 68), (680, 302)], t))

    p.append(tile(860, 330, "bedrock", "ml", "Amazon Bedrock", "own profiles", t))
    p.append(edge([(708, ROW + 14), (780, ROW + 14), (780, 330), (832, 330)], t))

    p.append(tile(1276, 160, "saas", "saas", "Datadog API", "optional", t))
    p.append(tile(1276, 310, "code", "ext", "GitHub API", "optional", t))
    p.append(edge([(708, ROW - 14), (1110, ROW - 14), (1110, 160), (1248, 160)], t))
    p.append(edge([(1110, ROW - 14), (1110, 310), (1248, 310)], t))

    for env, x0 in MEMBERS:
        p.extend(member(x0, env, t))

    p.append(
        text(
            60,
            BUS_LANE - 6,
            "ALARM events, cross-account rule",
            t,
            size=11,
            fill="dim",
            anchor="start",
        )
    )
    p.append(text(690, 422, "assume role, read only", t, size=11, fill="dim", anchor="start"))

    p.append(
        text(
            32,
            height - 18,
            "Each member role trusts only the investigator's role and carries the same deny list. "
            "Every finding records the account it read. Optional SNS notify stays central.",
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
