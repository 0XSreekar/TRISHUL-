# SPDX-License-Identifier: Apache-2.0
"""RFC 8785 JSON Canonicalization Scheme for the subset TRISHUL signs.

Supported: objects, arrays, strings, integers, booleans, null. Floats are rejected (integer
minor units only, A3). Object keys sort by UTF-16 code units; lone surrogates are rejected.
"""

import json

MAX_DEPTH = 128


class JcsError(ValueError):
    """Raised when a value cannot be canonicalised."""


def _check_str(value: str) -> str:
    for ch in value:
        if "\ud800" <= ch <= "\udfff":
            raise JcsError("lone surrogate in string")
    return value


def _enc(value: object, depth: int, out: list[str]) -> None:
    if depth > MAX_DEPTH:
        raise JcsError("value nested too deeply")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(str(int(value)))
    elif isinstance(value, float):
        raise JcsError("floats are not allowed; use integers")
    elif isinstance(value, str):
        out.append(json.dumps(_check_str(value), ensure_ascii=False))
    elif isinstance(value, list | tuple):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _enc(item, depth + 1, out)
        out.append("]")
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise JcsError("object keys must be strings")
            _check_str(key)
        out.append("{")
        for i, key in enumerate(sorted(value, key=lambda k: k.encode("utf-16-be"))):
            if i:
                out.append(",")
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(":")
            _enc(value[key], depth + 1, out)
        out.append("}")
    else:
        raise JcsError(f"unsupported type {type(value).__name__}")


def jcs(value: object) -> bytes:
    """Canonical UTF-8 bytes of ``value``."""
    out: list[str] = []
    _enc(value, 0, out)
    return "".join(out).encode("utf-8")
