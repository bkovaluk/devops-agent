"""Publish critical and high findings to an SNS topic.

The message is JSON with ``severity``, ``message``, ``service``, ``channel`` and pre-built
Slack Block Kit ``blocks``; a subscriber (a Slack notifier Lambda or any other consumer)
can pass the blocks through to Slack as-is.
"""

from __future__ import annotations

import json
from typing import Any

from aws_lambda_powertools import Logger

from devops_agent.models import Finding, Severity
from devops_agent.severity import notifies

logger = Logger(service="devops-agent", child=True)

SERVICE = "devops-agent"
MAX_SUBJECT_CHARS = 100
MAX_HEADER_CHARS = 150
MAX_TEXT_CHARS = 3000
MAX_EVIDENCE_ITEMS = 5
MAX_ACTION_ITEMS = 5


def _escape(text: str) -> str:
    # Slack parses <...> as links and mentions and links bare URLs; findings quote
    # untrusted text.
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("://", "[:]//")
    )


def _section(text: str) -> dict[str, Any]:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text[:MAX_TEXT_CHARS]}}


def _headline(finding: Finding, storm_size: int | None) -> str:
    title = f"Storm: {storm_size} alarms in 60 s" if storm_size else finding.title
    return f"{finding.env.upper()} {finding.severity.value.upper()}: {title}"


def subject_for(finding: Finding, storm_size: int | None = None) -> str:
    # SNS subjects are printable ASCII on one line.
    headline = _escape(_headline(finding, storm_size))
    text = "".join(c if 32 <= ord(c) < 127 else " " for c in f"[DevOps agent] {headline}")
    return " ".join(text.split())[:MAX_SUBJECT_CHARS]


def build_blocks(finding: Finding, storm_size: int | None = None) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": _headline(finding, storm_size)[:MAX_HEADER_CHARS],
            },
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"Effort {_escape(finding.fix_effort.label)}"}],
        },
    ]
    if storm_size:
        blocks.append(_section(f"*{_escape(finding.title)}*"))
    blocks.append(_section(f"*Summary*\n{_escape(finding.summary)}"))
    if finding.likely_cause:
        blocks.append(_section(f"*Likely cause*\n{_escape(finding.likely_cause)}"))
    if finding.evidence:
        bullets = "\n".join(
            f"• *{_escape(item.kind)}*: {_escape(item.detail)}"
            for item in finding.evidence[:MAX_EVIDENCE_ITEMS]
        )
        blocks.append(_section(f"*Evidence*\n{bullets}"))
    if finding.suggested_actions:
        actions = "\n".join(
            f"{number}. {_escape(action)}"
            for number, action in enumerate(finding.suggested_actions[:MAX_ACTION_ITEMS], start=1)
        )
        blocks.append(_section(f"*Suggested actions*\n{actions}"))
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"Alarm `{_escape(finding.alarm_name)}` · finding "
                        f"`{finding.finding_id}` · {finding.outcome}"
                    )[:MAX_TEXT_CHARS],
                }
            ],
        }
    )
    return blocks


def build_payload(finding: Finding, channel: str, storm_size: int | None = None) -> dict[str, Any]:
    headline = _headline(finding, storm_size)
    return {
        "severity": "critical" if finding.severity is Severity.CRITICAL else "error",
        "message": _escape(f"{headline}. {finding.summary}")[:MAX_TEXT_CHARS],
        "service": SERVICE,
        "channel": channel,
        "blocks": build_blocks(finding, storm_size),
    }


def publish_finding(
    sns: Any, topic_arn: str, channel: str, finding: Finding, storm_size: int | None = None
) -> bool:
    """Publish a critical or high finding. False when skipped or when publishing fails.

    ``storm_size`` is the alarm count of an incident finding; it sets the headline.
    """
    if not notifies(finding.severity):
        return False
    try:
        sns.publish(
            TopicArn=topic_arn,
            Subject=subject_for(finding, storm_size),
            Message=json.dumps(build_payload(finding, channel, storm_size)),
        )
    except Exception:
        logger.exception("finding publish failed", extra={"finding_id": finding.finding_id})
        return False
    return True
