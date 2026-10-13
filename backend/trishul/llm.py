# SPDX-License-Identifier: Apache-2.0
"""Local LLM for the quarantined reader: RAM-based model selection, pin check, Ollama client.

Fail closed: a missing server, a digest that differs from the pin, or any transport error means
"not available" and the reader falls back to the deterministic extractors, labelled as such.
"""

import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

from trishul.ml.models import LLM_PINS
from trishul.ollama import ollama_endpoint, ollama_openai_url

GIB = 1024**3
RAM_THRESHOLD_BYTES = 16 * GIB
PRIMARY, FALLBACK = "Qwen/Qwen3-8B", "Qwen/Qwen3-4B"
SEED = 42
DEFAULT_TIMEOUT_S = 60.0


class LLMError(Exception):
    """Transport/server failure talking to the model."""


class LLM(Protocol):
    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> str:
        """One fresh, tool-less, temperature-0 completion constrained to ``schema``."""
        ...


@dataclass(frozen=True)
class ModelChoice:
    hf_id: str
    ollama_tag: str
    digest: str
    selected_by: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class LlmStatus:
    state: str  # ok | unavailable | digest_mismatch | model_missing
    detail: str = ""
    observed_digest: str | None = None

    @property
    def ok(self) -> bool:
        return self.state == "ok"


def total_ram_bytes() -> int:
    if sys.platform == "darwin":
        out = subprocess.run(
            ["sysctl", "-n", "hw.memsize"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return int(out.strip())
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    return int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))


def select_model(ram_bytes: int | None = None) -> ModelChoice:
    """>= 16 GiB -> Qwen/Qwen3-8B, otherwise Qwen/Qwen3-4B. Unknown RAM selects the smaller one."""
    try:
        ram = total_ram_bytes() if ram_bytes is None else ram_bytes
    except (OSError, ValueError, subprocess.SubprocessError):
        ram = 0
    big = ram >= RAM_THRESHOLD_BYTES
    pin = LLM_PINS[PRIMARY if big else FALLBACK]
    rule = f"ram {'>=' if big else '<'} 16GiB ({ram // GIB} GiB detected)"
    return ModelChoice(pin["hf_id"], pin["ollama_tag"], pin["digest"], rule)


def probe(choice: ModelChoice, *, timeout_s: float = 1.0) -> LlmStatus:
    """Ask Ollama ``/api/tags``: is the pinned tag installed with the pinned digest?"""
    host, port = ollama_endpoint()
    host = f"[{host}]" if ":" in host else host
    try:
        resp = httpx.get(f"http://{host}:{port}/api/tags", timeout=timeout_s)
        resp.raise_for_status()
        models = resp.json().get("models", [])
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        return LlmStatus("unavailable", type(exc).__name__)
    for m in models:
        if isinstance(m, dict) and m.get("name") == choice.ollama_tag:
            digest = str(m.get("digest", ""))
            if digest == choice.digest:
                return LlmStatus("ok", observed_digest=digest)
            return LlmStatus("digest_mismatch", "digest differs from pin", digest)
    return LlmStatus("model_missing", choice.ollama_tag)


class OllamaLLM:
    """Ollama's OpenAI-compatible chat endpoint with a JSON-schema ``response_format``."""

    def __init__(
        self,
        choice: ModelChoice | None = None,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_tokens: int = 512,
    ) -> None:
        self.choice = choice or select_model()
        self.timeout_s = timeout_s
        self.max_tokens = max_tokens

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> str:
        body = {
            "model": self.choice.ollama_tag,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "seed": SEED,
            "max_tokens": self.max_tokens,
            "reasoning_effort": "none",
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "extraction", "strict": True, "schema": schema},
            },
            # no "tools": the reader has no capabilities
        }
        try:
            resp = httpx.post(
                f"{ollama_openai_url()}/chat/completions", json=body, timeout=self.timeout_s
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMError(type(exc).__name__) from exc
        if not isinstance(content, str):
            raise LLMError("non-text completion")
        return content


def reader_mode() -> str:
    """``TRISHUL_READER``: ``llm`` or ``replay`` (default). Unknown values mean ``replay``."""
    wanted = os.environ.get("TRISHUL_READER", "replay").strip().lower()
    return "llm" if wanted == "llm" else "replay"


def system_start_record(
    choice: ModelChoice, status: LlmStatus, mode: str, ts: str
) -> dict[str, Any]:
    """Audit leaf body for ``trishul start``."""
    return {
        "domain": "core",
        "type": "system_start",
        "llm": choice.as_dict(),
        "llm_state": status.state,
        "reader_mode": mode,
        "reader": "llm" if mode == "llm" and status.ok else "deterministic-fallback",
        "ts": ts,
    }
