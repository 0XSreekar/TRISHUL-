# SPDX-License-Identifier: Apache-2.0
"""Ollama endpoint from ``OLLAMA_HOST`` (host, host:port or full URL); default localhost:11434."""

import os
from urllib.parse import urlsplit

DEFAULT_HOST, DEFAULT_PORT = "127.0.0.1", 11434


def ollama_endpoint() -> tuple[str, int]:
    raw = os.environ.get("OLLAMA_HOST", "").strip()
    if not raw:
        return DEFAULT_HOST, DEFAULT_PORT
    parts = urlsplit(raw if "://" in raw else f"//{raw}")
    try:
        port = parts.port
    except ValueError:
        return DEFAULT_HOST, DEFAULT_PORT
    host = parts.hostname or DEFAULT_HOST
    return (DEFAULT_HOST if host in ("0.0.0.0", "::") else host), port or DEFAULT_PORT  # noqa: S104


def ollama_openai_url() -> str:
    host, port = ollama_endpoint()
    host = f"[{host}]" if ":" in host else host
    return f"http://{host}:{port}/v1"
