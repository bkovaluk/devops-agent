"""Renders the README architecture diagram, dark and light.

Run from the repo root: uv run python docs/diagram/architecture.py docs
"""

import sys

from diagram import boundary, edge, head, text, tile, write_both


def draw(t: dict[str, str]) -> str:
    width, height = 1400, 740
    p = head(
        width,
        height,
        t,
        "devops-agent",
        "One deployment per AWS account and environment. Everything the agent touches is read only.",
    )
    p.append(boundary(250, 110, 900, 580, "AWS ACCOUNT  ·  one region", "acct", t))
    p.append(boundary(24, 110, 200, 230, "SAAS, OPTIONAL", "dim", t, dashed=True))
    p.append(boundary(1176, 110, 200, 340, "OUTBOUND, READ ONLY", "dim", t, dashed=True))

    p.append(tile(124, 215, "saas", "saas", "Datadog monitors", "devops_agent:true", t))
    p.append(tile(330, 410, "cloudwatch", "integration", "CloudWatch alarms", "any alarm", t))

    p.append(tile(490, 215, "eventbridge", "integration", "Partner bus", "Datadog source", t))
    p.append(tile(490, 410, "eventbridge", "integration", "Default bus", "state ALARM", t))
    p.append(edge([(152, 215), (462, 215)], t, "alert event", 300, 207))
    p.append(edge([(358, 410), (462, 410)], t))

    p.append(tile(640, 312, "sqs", "integration", "Alarms queue", "DLQ · backlog alarm", t))
    p.append(edge([(518, 215), (565, 215), (565, 300), (612, 300)], t))
    p.append(edge([(518, 410), (565, 410), (565, 324), (612, 324)], t))

    p.append(tile(790, 312, "lambda", "compute", "Triage", "no model · budgets", t))
    p.append(edge([(668, 312), (762, 312)], t, "ESM", 715, 304))
    p.append(tile(940, 312, "sqs", "integration", "Work queue", "DLQ · backlog alarm", t))
    p.append(edge([(818, 312), (912, 312)], t, "job", 865, 304))
    p.append(tile(1080, 312, "lambda", "compute", "Investigator", "max 2 at once", t))
    p.append(edge([(968, 312), (1052, 312)], t, "ESM", 1010, 304))

    p.append(tile(1080, 175, "bedrock", "ml", "Amazon Bedrock", "own profiles", t))
    p.append(edge([(1080, 284), (1080, 247)], t))

    p.append(tile(940, 175, "sqs", "integration", "SNS topic", "optional", t))
    p.append(edge([(1058, 286), (1058, 252), (990, 252), (990, 175), (968, 175)], t))

    p.append(tile(1276, 175, "saas", "saas", "Datadog API", "optional", t))
    p.append(tile(1276, 324, "code", "ext", "GitHub API", "optional", t))
    p.append(edge([(1108, 300), (1170, 300), (1170, 175), (1248, 175)], t))
    p.append(edge([(1108, 324), (1248, 324)], t))

    p.append(tile(1080, 500, "iam", "security", "Read-only role", "deny list wins", t))
    p.append(edge([(1080, 382), (1080, 472)], t, "tools", 1088, 430, anchor="start"))
    p.append(tile(940, 600, "grid", "ext", "AWS APIs", "read operations", t))
    p.append(edge([(1080, 570), (1080, 600), (968, 600)], t))

    p.append(tile(790, 500, "dynamodb", "database", "Findings table", "ttl 90 days", t))
    p.append(edge([(790, 382), (790, 472)], t, "claims, budgets", 798, 430, anchor="start"))
    p.append(edge([(1054, 330), (1018, 330), (1018, 500), (818, 500)], t, "findings", 914, 492))

    p.append(
        text(
            32,
            height - 18,
            "The agent writes only its own queues, findings table and optional topic. "
            "Alarm text, logs and code are data, never instructions.",
            t,
            size=11.5,
            fill="dim",
            anchor="start",
        )
    )
    p.append("</svg>")
    return "".join(p)


if __name__ == "__main__":
    write_both(draw, sys.argv[1])
