"""Wiring for the reader: default reader for the gateway, and the ``trishul start`` hook that
logs the chosen model, records the ``system_start`` audit leaf and attaches the live reader to
the red-team wall."""

import functools
import logging
import os
from typing import Any

from trishul.gateway.taint import SessionHandles
from trishul.llm import (
    LlmStatus,
    ModelChoice,
    OllamaLLM,
    probe,
    reader_mode,
    select_model,
    system_start_record,
)
from trishul.reader.reader import FALLBACK_LABEL, LLM_LABEL, QuarantinedReader
from trishul.store.db import iso

log = logging.getLogger("trishul.reader")


@functools.cache
def chosen_model() -> ModelChoice:
    return select_model()


def build_default_reader(handles: SessionHandles) -> QuarantinedReader:
    """Gateway reader: ``TRISHUL_READER=llm`` uses the pinned local model when it is up and its
    digest matches the pin; anything else is the labelled deterministic fallback."""
    mode = reader_mode()
    llm = None
    if mode == "llm":
        choice = chosen_model()
        if probe(choice).ok:
            llm = OllamaLLM(choice)
    return QuarantinedReader(handles, llm, mode)


def reader_info(choice: ModelChoice, status: LlmStatus, mode: str) -> dict[str, Any]:
    return {
        "mode": mode,
        "reader": LLM_LABEL if mode == "llm" and status.ok else FALLBACK_LABEL,
        "llm": choice.as_dict(),
        "llm_state": status.state,
    }


def live_reader_info() -> dict[str, Any]:
    """Current reader status for ``/readyz`` (probes the server; fail closed on any error)."""
    return reader_info(chosen_model(), probe(chosen_model(), timeout_s=0.3), reader_mode())


def start_reader(gateway: Any) -> dict[str, Any]:
    """Called by ``trishul start``: log the model, audit ``system_start``, enable the live
    red-team reader when the model is up (``TRISHUL_READER=replay`` forces the fallback)."""
    choice = chosen_model()
    status = probe(choice)
    mode = reader_mode()
    wall_live = status.ok and os.environ.get("TRISHUL_READER", "").strip().lower() != "replay"
    llm = OllamaLLM(choice) if status.ok else None
    wall = QuarantinedReader(gateway.pipeline.handles, llm, "llm" if wall_live else "replay")
    gateway.backend.redteam.reader = wall
    info = {**reader_info(choice, status, mode), "redteam_reader": wall.effective()}
    log.info(
        "local LLM: %s (%s) state=%s reader=%s",
        choice.hf_id,
        choice.selected_by,
        status.state,
        info["reader"],
    )
    gateway.backend.reader_info = info
    p = gateway.pipeline
    record = system_start_record(choice, status, mode, iso(p.clock()))
    record["redteam_reader"] = wall.effective()
    p.audit.append(record)
    return info
