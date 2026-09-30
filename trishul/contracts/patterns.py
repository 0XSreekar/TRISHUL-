# SPDX-License-Identifier: Apache-2.0
"""Secret / PII detection patterns shared by redaction, event validation and log scrubbing."""

import re

_B = r"(?<![A-Za-z0-9])"
_E = r"(?![A-Za-z0-9])"

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("api_key", re.compile(r"(?<![A-Za-z0-9])(?:sk|pk|rk)-[A-Za-z0-9_-]{12,}")),
    ("api_key", re.compile(_B + r"(?:AKIA|ASIA)[0-9A-Z]{16}" + _E)),
    ("api_key", re.compile(_B + r"gh[pousr]_[A-Za-z0-9]{20,}")),
    (
        "api_key",
        re.compile(r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*[^\s,;\"']{6,}"),
    ),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")),
    ("aadhaar", re.compile(_B + r"\d{4}[ -]?\d{4}[ -]?\d{4}" + _E)),
    ("pan", re.compile(_B + r"[A-Z]{5}[0-9]{4}[A-Z]" + _E)),
    ("phone", re.compile(_B + r"(?:\+91[ -]?|91[ -]?|0)?[6-9]\d{4}[ -]?\d{5}" + _E)),
)


def find_secrets(text: str) -> list[str]:
    """Return the kinds of secrets/PII found in ``text`` (empty if none)."""
    return [kind for kind, pattern in PATTERNS if pattern.search(text)]


def contains_secret(text: str) -> bool:
    return any(pattern.search(text) for _, pattern in PATTERNS)


def scrub_text(text: str) -> str:
    """Replace every detected secret/PII span with ``[REDACTED:<kind>]``."""
    for kind, pattern in PATTERNS:
        text = pattern.sub(f"[REDACTED:{kind}]", text)
    return text


def contains_secret_deep(value: object) -> bool:
    """Recursively check strings (and dict keys) inside a JSON-like structure."""
    if isinstance(value, str):
        return contains_secret(value)
    if isinstance(value, dict):
        return any(contains_secret(str(k)) or contains_secret_deep(v) for k, v in value.items())
    if isinstance(value, list | tuple):
        return any(contains_secret_deep(v) for v in value)
    return False
