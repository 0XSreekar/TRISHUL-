# SPDX-License-Identifier: Apache-2.0
"""Redaction (§6): label-driven, plus a pattern backstop for unlabeled leaks."""

import hashlib
import hmac
import secrets
from collections.abc import Mapping
from typing import Final

from pydantic import JsonValue

from trishul.contracts.canonical import canonical_json, escape_token, is_prefix
from trishul.contracts.labels import PII_TAGS, Label, Tag
from trishul.contracts.patterns import find_secrets, scrub_text
from trishul.contracts.values import Redacted, RedactedJson
from trishul.provenance.lattice import join_all

_PROCESS_KEY: Final = secrets.token_bytes(32)


def pseudonym(value: object) -> str:
    """Keyed, process-local pseudonym (16 hex chars). Stable within a run, unlinkable across."""
    text = value if isinstance(value, str) else canonical_json(value)
    return hmac.new(_PROCESS_KEY, text.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def redact(value: JsonValue, label: Label) -> RedactedJson:
    """Redact ``value`` given its label; unlabeled secrets are caught by the pattern backstop."""
    if Tag.SECRET in label.tags:
        return Redacted(reason="secret", digest=None)
    if label.tags & PII_TAGS:
        return Redacted(reason="pii", digest=pseudonym(value))
    return _backstop(value)


def _backstop(value: object) -> RedactedJson:
    if isinstance(value, str):
        kinds = find_secrets(value)
        return Redacted(reason=f"pattern:{kinds[0]}", digest=pseudonym(value)) if kinds else value
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        kinds = find_secrets(str(value))
        return Redacted(reason=f"pattern:{kinds[0]}", digest=pseudonym(value)) if kinds else value
    if isinstance(value, list | tuple):
        return [_backstop(v) for v in value]
    if isinstance(value, dict):
        return {scrub_text(str(k)): _backstop(v) for k, v in value.items()}
    return Redacted(reason="unsupported-type", digest=None)


def _redact_at(path: str, value: JsonValue, labels: Mapping[str, Label]) -> RedactedJson:
    label = join_all(lab for p, lab in labels.items() if is_prefix(p, path))
    if label.tags & (PII_TAGS | {Tag.SECRET}):
        return redact(value, label)
    if isinstance(value, dict):
        return {
            scrub_text(k): _redact_at(f"{path}/{escape_token(k)}", v, labels)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_at(f"{path}/{i}", v, labels) for i, v in enumerate(value)]
    return _backstop(value)


def redact_args(
    args: Mapping[str, JsonValue], arg_labels: Mapping[str, Label]
) -> dict[str, RedactedJson]:
    """Redact every argument using labels on the argument or any ancestor pointer."""
    return {
        scrub_text(name): _redact_at(f"/{escape_token(name)}", value, arg_labels)
        for name, value in args.items()
    }
