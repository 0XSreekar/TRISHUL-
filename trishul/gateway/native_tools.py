# SPDX-License-Identifier: Apache-2.0
"""Gateway-native tools: the quarantined reader ``extract_field`` and ``voice_command``.

The FastMCP tool bodies are schema stubs: every call is intercepted by ``PolicyMiddleware`` and
executed by ``NativeExecutor`` only after the pipeline returned ALLOW.
"""

import json
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools import ToolResult
from mcp.types import TextContent

from trishul.gateway.taint import EXTRACTORS, HandleMeta, SessionHandles
from trishul.reader.reader import QuarantinedReader
from trishul.reader.runtime import build_default_reader
from trishul.reader.schemas import SCHEMAS


def register_native_tools(mcp: FastMCP) -> None:
    @mcp.tool
    async def extract_field(handle: str, field: str) -> dict[str, Any]:
        """Quarantined reader: pull ``payee_vpa`` / ``amount_paise`` / ``invoice_id`` out of a
        document handle. Returns a ``$VAR_n`` handle whose label is derived from the document."""
        raise ToolError("extract_field must be invoked through the gateway pipeline")

    @mcp.tool
    async def read_handle(handle: str, schema: str) -> dict[str, Any]:
        """Quarantined reader: extract typed fields (``invoice`` / ``voice_command`` /
        ``email``) from a ``$DOC``/``$EMAIL``/``$VOICE`` handle. Returns one ``$VAR_n`` handle per
        field; each inherits the source handle's label. Invalid reader output is a DENY."""
        raise ToolError("read_handle must be invoked through the gateway pipeline")

    @mcp.tool
    async def voice_command(clip_b64: str, clip_id: str, nonce_id: str) -> dict[str, Any]:
        """Run VoiceTrust on a base64 wav clip answering a nonce challenge."""
        raise ToolError("voice_command must be invoked through the gateway pipeline")


def wrap(obj: Any) -> ToolResult:
    return ToolResult(
        content=[TextContent(type="text", text=json.dumps(obj, sort_keys=True))],
        structured_content=obj,
    )


class NativeExecutor:
    """Executes native tools once the pipeline has allowed the call."""

    def __init__(self, handles: SessionHandles, reader: QuarantinedReader | None = None) -> None:
        self.handles = handles
        # default: TRISHUL_READER=replay (deterministic, labelled) unless =llm and the model is up
        self.reader = reader or build_default_reader(handles)

    def __call__(self, st: Any) -> ToolResult:
        if st.tool == "extract_field":
            return self._extract(st)
        if st.tool == "read_handle":
            return self._read_handle(st)
        if st.tool == "voice_command":
            return self._voice(st)
        raise ToolError(f"unknown native tool {st.tool}")

    def _extract(self, st: Any) -> ToolResult:
        handle, name = st.call.args.get("handle"), st.call.args.get("field")
        extractor = EXTRACTORS.get(name) if isinstance(name, str) else None
        if extractor is None or not isinstance(handle, str):
            raise ToolError(f"unsupported field; expected one of {sorted(EXTRACTORS)}")
        try:
            var_id, labeled, reader = self.reader.extract_field(handle, name)
        except KeyError as exc:
            raise ToolError("unknown or non-document handle") from exc
        except LookupError as exc:
            raise ToolError(str(exc)) from exc
        st.reader = reader
        kind = "integer" if isinstance(labeled.value, int) else "string"
        return wrap(
            {
                "handle": var_id,
                "summary": {"field": name, "type": kind, "source": handle, "reader": reader},
            }
        )

    def _read_handle(self, st: Any) -> ToolResult:
        handle, schema = st.call.args.get("handle"), st.call.args.get("schema")
        if schema not in SCHEMAS or not isinstance(handle, str):
            raise ToolError(f"unsupported schema; expected one of {sorted(SCHEMAS)}")
        try:
            result = self.reader.read(handle, schema)
        except KeyError as exc:
            raise ToolError("unknown or non-source handle") from exc
        st.reader = result.reader
        handles: dict[str, str] = {}
        types: dict[str, str] = {}
        for name, item in result.values.items():
            var_id, _ = self.handles.store_var(handle, name, item, reader=result.reader)
            handles[name] = var_id
            types[name] = "integer" if isinstance(item.value, int) else "string"
        return wrap(
            {
                "handles": handles,
                "summary": {
                    "schema": schema,
                    "fields": types,
                    "source": handle,
                    "reader": result.reader,
                },
            }
        )

    def _voice(self, st: Any) -> ToolResult:
        assessment = st.voice
        if assessment is None:
            raise ToolError("voice assessment missing")
        handle = None
        transcript = assessment.transcript
        if transcript is not None:
            handle = self.handles.put_doc(
                transcript.value,
                transcript.label,
                HandleMeta(kind="voice", ref=assessment.clip_id, source_kind="voice"),
            )
        return wrap(
            {
                "handle": handle,
                "summary": {
                    "clip_id": assessment.clip_id,
                    # an approved retry re-checks an already-consumed nonce (raw: mismatch);
                    # it only executes because that same nonce matched for this exact call
                    "liveness": "match"
                    if getattr(st, "voice_resumed", False)
                    else assessment.liveness,
                    "resumed_after_approval": bool(getattr(st, "voice_resumed", False)),
                    "quality": assessment.quality.quality,
                    "asr_ran": assessment.asr.ran,
                    "chars": 0 if transcript is None else len(transcript.value),
                },
            }
        )
