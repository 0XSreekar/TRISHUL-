# SPDX-License-Identifier: Apache-2.0
"""PII recognizers (email, Indian mobile, PAN, Aadhaar with Verhoeff) and label derivation."""

import re
from collections.abc import Mapping

from trishul.contracts.labels import Tag, close_tags

Span = tuple[int, int]

# Verhoeff dihedral-group tables.
_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_valid(number: str) -> bool:
    """True iff ``number`` (ASCII digits, check digit last) passes the Verhoeff checksum."""
    if not number or not (number.isascii() and number.isdigit()):
        return False
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
PHONE_RE = re.compile(r"(?<!\d)(?:\+91[\s-]?|91[\s-]?|0)?[6-9]\d{9}(?!\d)")
PAN_RE = re.compile(r"(?<![A-Z0-9])[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z](?![A-Z0-9])")
AADHAAR_RE = re.compile(r"(?<!\d)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\d)")

KIND_TAG: dict[str, Tag] = {
    "email": Tag.PII_EMAIL,
    "phone": Tag.PII_PHONE,
    "pan": Tag.PII_PAN,
    "aadhaar": Tag.PII_AADHAAR,
}
# Field names whose *values* are personal data even when they do not match a recognizer.
FIELD_TAGS: dict[str, Tag] = {
    "email": Tag.PII_EMAIL,
    "phone": Tag.PII_PHONE,
    "mobile": Tag.PII_PHONE,
    "pan": Tag.PII_PAN,
    "aadhaar": Tag.PII_AADHAAR,
    "name": Tag.PII,
    "address": Tag.PII,
    "dob": Tag.PII,
}


def find_pii(text: str) -> list[tuple[str, Span]]:
    """All recognised PII in ``text`` as ``(kind, (start, end))``, ordered by position."""
    found: list[tuple[str, Span]] = []
    for m in EMAIL_RE.finditer(text):
        found.append(("email", m.span()))
    for m in PHONE_RE.finditer(text):
        found.append(("phone", m.span()))
    for m in PAN_RE.finditer(text):
        found.append(("pan", m.span()))
    for m in AADHAAR_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if verhoeff_valid(digits):
            found.append(("aadhaar", m.span()))
    return sorted(found, key=lambda item: (item[1], item[0]))


def _walk(value: object, tags: set[Tag], depth: int) -> None:
    if depth > 64:
        return
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, str):
        tags.update(KIND_TAG[kind] for kind, _ in find_pii(value))
    elif isinstance(value, int):
        _walk(str(value), tags, depth)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _walk(str(key), tags, depth + 1)
            _walk(item, tags, depth + 1)
    elif isinstance(value, list | tuple):
        for item in value:
            _walk(item, tags, depth + 1)


def label_pii(value: object) -> frozenset[Tag]:
    """Tags for every PII kind found anywhere in a JSON-like value (closed: specific => PII)."""
    tags: set[Tag] = set()
    _walk(value, tags, 0)
    return close_tags(tags)
