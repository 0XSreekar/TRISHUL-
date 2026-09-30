"""FastMCP middleware that routes every ``tools/call`` through the gateway pipeline."""

import re
from collections.abc import Callable
from typing import Any

import mcp.types as mt
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult

from trishul.gateway.pipeline import CallRequest, Pipeline, State


def _request_meta(context: MiddlewareContext[mt.CallToolRequestParams]) -> dict[str, Any]:
    """Only a cosmetic ``agent`` label is honoured; the task always comes from the trusted
    binding channel, never from the client (otherwise an agent could pick its own purpose)."""
    raw: Any = None
    try:
        fc = context.fastmcp_context
        raw = fc.request_context.meta if fc is not None else None  # type: ignore[union-attr]
    except Exception:
        raw = None
    if raw is None:
        raw = context.message.meta
    if raw is not None and not isinstance(raw, dict):
        dump = getattr(raw, "model_dump", None)
        raw = dump() if callable(dump) else {}
    data = raw if isinstance(raw, dict) else {}
    agent = data.get("agent")
    if isinstance(agent, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", agent):
        return {"agent": agent}
    return {}


class PolicyMiddleware(Middleware):
    def __init__(self, pipeline: Pipeline, native: Callable[[State], ToolResult]) -> None:
        super().__init__()
        self.pipeline = pipeline
        self.native = native

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        params = context.message
        request = CallRequest(
            name=params.name,
            arguments=dict(params.arguments or {}),
            meta=_request_meta(context),
        )

        async def execute(args: dict[str, Any]) -> ToolResult:
            forwarded = mt.CallToolRequestParams(name=params.name, arguments=args)
            return await call_next(context.copy(message=forwarded))

        return await self.pipeline.run(request, execute, self.native)
