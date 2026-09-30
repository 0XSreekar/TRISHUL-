"""Canonical JSON (A4), SHA-256 digests, float rejection (A3) and JSON-pointer helpers."""

import hashlib
import json
import re
from collections.abc import Iterator

from trishul.contracts.values import ABSENT, Absent

MAX_DEPTH = 128


class CanonicalError(ValueError):
    """Raised when a value cannot be represented in canonical JSON."""


def ensure_canonical(value: object, *, _depth: int = 0) -> None:
    """Raise ``CanonicalError`` for floats, non-string keys or non-JSON types."""
    if _depth > MAX_DEPTH:
        raise CanonicalError("value nested too deeply")
    if value is None or isinstance(value, bool | int | str):
        return
    if isinstance(value, float):
        raise CanonicalError("floats are not allowed; use integer minor units")
    if isinstance(value, list | tuple):
        for item in value:
            ensure_canonical(item, _depth=_depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError("object keys must be strings")
            ensure_canonical(item, _depth=_depth + 1)
        return
    raise CanonicalError(f"unsupported type {type(value).__name__}")


def canonical_json(value: object) -> str:
    """Sorted keys, compact separators, UTF-8 (unescaped), no NaN, no floats."""
    ensure_canonical(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def digest(value: object) -> str:
    """SHA-256 hex digest of the canonical JSON encoding."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


# --- JSON pointers (RFC 6901) -------------------------------------------------------------


def escape_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _unescape_token(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


_POINTER = re.compile(r"^(?:/(?:[^~/]|~[01])*)+$")


def is_pointer(path: str) -> bool:
    """True for a non-root, well-formed pointer such as ``/payee/vpa``."""
    return _POINTER.fullmatch(path) is not None


def pointer_tokens(path: str) -> tuple[str, ...]:
    if not is_pointer(path):
        raise CanonicalError("not a JSON pointer")
    return tuple(_unescape_token(t) for t in path[1:].split("/"))


def is_prefix(prefix: str, path: str) -> bool:
    """True if ``prefix`` equals ``path`` or is one of its ancestors."""
    return path == prefix or path.startswith(prefix + "/")


def resolve_pointer(value: object, path: str) -> object | Absent:
    """Return the value at ``path`` or ``ABSENT``. An explicit JSON null is returned as None."""
    current: object = value
    for token in pointer_tokens(path):
        if isinstance(current, dict):
            if token not in current:
                return ABSENT
            current = current[token]
        elif isinstance(current, list):
            if not token.isascii() or not token.isdigit() or (len(token) > 1 and token[0] == "0"):
                return ABSENT
            index = int(token)
            if index >= len(current):
                return ABSENT
            current = current[index]
        else:
            return ABSENT
    return current


def leaf_paths(value: object, base: str = "") -> Iterator[tuple[str, object]]:
    """Yield ``(pointer, leaf)`` for scalars and empty containers under ``value``."""
    if isinstance(value, dict) and value:
        for key, item in value.items():
            yield from leaf_paths(item, f"{base}/{escape_token(str(key))}")
    elif isinstance(value, list) and value:
        for index, item in enumerate(value):
            yield from leaf_paths(item, f"{base}/{index}")
    else:
        yield base, value
