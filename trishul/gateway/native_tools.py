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


def register_native_tools(mcp: FastMCP) -> None:
    @mcp.tool
    async def extract_field(handle: str, field: str) -> dict[str, Any]:
        """Quarantined reader: pull ``payee_vpa`` / ``amount_paise`` / ``invoice_id`` out of a
        document handle. Returns a ``$VAR_n`` handle whose label is derived from the document."""
        raise ToolError("extract_field must be invoked through the gateway pipeline")

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

    def __init__(self, handles: SessionHandles) -> None:
        self.handles = handles

    def __call__(self, st: Any) -> ToolResult:
        if st.tool == "extract_field":
            return self._extract(st)
        if st.tool == "voice_command":
            return self._voice(st)
        raise ToolError(f"unknown native tool {st.tool}")

    def _extract(self, st: Any) -> ToolResult:
        handle, name = st.call.args.get("handle"), st.call.args.get("field")
        extractor = EXTRACTORS.get(name) if isinstance(name, str) else None
        if extractor is None or not isinstance(handle, str):
            raise ToolError(f"unsupported field; expected one of {sorted(EXTRACTORS)}")
        try:
            var_id, labeled = self.handles.extract(handle, name, extractor)
        except KeyError as exc:
            raise ToolError("unknown or non-document handle") from exc
        except LookupError as exc:
            raise ToolError(str(exc)) from exc
        kind = "integer" if isinstance(labeled.value, int) else "string"
        return wrap({"handle": var_id, "summary": {"field": name, "type": kind, "source": handle}})

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
