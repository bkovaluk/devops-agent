"""Credential-shape redaction for tool output and findings."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from devops_agent.models import Finding

REDACTED = "[redacted]"

_ACCESS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
# A Basic credential is base64, so it has a digit, +, / or = or a case change; that keeps
# prose like "Basic Auth" or "basic check" intact.
_AUTH_SCHEME = re.compile(
    r"\b((?i:bearer)\s+|(?i:basic)\s+(?=[A-Za-z0-9+/]*(?:[0-9+/=]|[a-z][A-Z])))"
    r"[A-Za-z0-9\-._~+/]+=*"
)
_KEY_NAMES = (
    "x-api-key|api_key|api-key|apikey|authorization|auth|credentials|credential"
    "|passphrase|password|passwd|pass|pwd|secret|token"
)
# A quoted value is redacted to its closing quote, or to the end of the line when cut.
_KEY_VALUE = re.compile(
    rf"(?i)(?P<key>{_KEY_NAMES})(?P<sep>[\"']?\s*[=:]\s*)"
    r"(?:(?P<open>[\"'])(?:(?!(?P=open))[^\n])*(?P<close>(?P=open))?"
    r"|(?!(?i:bearer|basic)\s)[^\s\"',;&}]+)"
)
_PREFIXED_TOKEN = re.compile(
    r"\b(?:xox[abprs]-[A-Za-z0-9-]+|gh[pousr]_[A-Za-z0-9]{36,}|sk-[A-Za-z0-9_-]{20,})"
)
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s/@]+@")
# Exactly 32 lowercase hex is a Datadog API key; 40 (git) and 64 (sha256) are digests.
_HEX_KEY = re.compile(r"(?<![0-9A-Za-z])[0-9a-f]{32}(?![0-9A-Za-z])")
# An unterminated block (cut mid-key) is redacted to the end of the string.
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[\s\S]*)"
)
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_MIN_ENTROPY_BITS = 4.2


def _entropy(text: str) -> float:
    counts = Counter(text)
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def _is_high_entropy(text: str) -> bool:
    # Mixed case plus digits keeps hex digests and long identifiers out.
    return (
        any(c.isupper() for c in text)
        and any(c.islower() for c in text)
        and any(c.isdigit() for c in text)
        and _entropy(text) >= _MIN_ENTROPY_BITS
    )


def _redact_base64(match: re.Match[str]) -> str:
    return REDACTED if _is_high_entropy(match.group(0)) else match.group(0)


def _redact_key_value(match: re.Match[str]) -> str:
    opening = match.group("open") or ""
    closing = match.group("close") or ""
    return f"{match.group('key')}{match.group('sep')}{opening}{REDACTED}{closing}"


def redact(text: str) -> str:
    """Replace credential-shaped substrings with [redacted]."""
    text = _PEM_PRIVATE_KEY.sub(REDACTED, text)
    text = _ACCESS_KEY_ID.sub(REDACTED, text)
    text = _URL_USERINFO.sub(rf"\g<1>{REDACTED}@", text)
    text = _PREFIXED_TOKEN.sub(REDACTED, text)
    text = _AUTH_SCHEME.sub(rf"\g<1>{REDACTED}", text)
    text = _KEY_VALUE.sub(_redact_key_value, text)
    text = _HEX_KEY.sub(REDACTED, text)
    return _BASE64_RUN.sub(_redact_base64, text)


def redact_value(value: Any) -> Any:
    """Redact every string inside a JSON-like value."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    return value


def redact_finding(finding: Finding) -> Finding:
    """The finding with every string field redacted."""
    return Finding.model_validate(redact_value(finding.model_dump(mode="json")))
