"""FastMCP middleware that routes every ``tools/call`` through the gateway pipeline."""

import re
from collections.abc import Callable
from typing import Any

import mcp.types as mt
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult

from trishul.crypto.toolauth import TOKEN_ARG, ToolTokenMinter
from trishul.gateway.pipeline import CallRequest, Pipeline, State, split_name


def _request_meta(context: MiddlewareContext[mt.CallToolRequestParams]) -> dict[str, Any]:
    """The ``agent`` label is cosmetic; ``task_id`` may only select an already-bound task (the
    purpose/category still come from the trusted binding channel, never from the client)."""
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
    out: dict[str, Any] = {}
    if isinstance(agent, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", agent):
        out["agent"] = agent
    task_id = data.get("task_id")  # pins a call to an already-bound task; unknown id => DENY
    if isinstance(task_id, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", task_id):
        out["task_id"] = task_id
        task_pin = data.get("task_pin")  # secret proving the caller owns a pinnable task
        if isinstance(task_pin, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", task_pin):
            out["task_pin"] = task_pin
    return out


class PolicyMiddleware(Middleware):
    def __init__(
        self,
        pipeline: Pipeline,
        native: Callable[[State], ToolResult],
        minter: ToolTokenMinter,
    ) -> None:
        super().__init__()
        self.pipeline = pipeline
        self.native = native
        self.minter = minter

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        params = context.message
        if TOKEN_ARG in (params.arguments or {}):
            # the token channel belongs to the gateway; an agent must never supply one
            raise ToolError(f"argument {TOKEN_ARG!r} is reserved")
        request = CallRequest(
            name=params.name,
            arguments=dict(params.arguments or {}),
            meta=_request_meta(context),
        )

        async def execute(args: dict[str, Any]) -> ToolResult:
            # minted only here, after ALLOW, for exactly this server, tool and argument set
            server, tool = split_name(params.name)
            token = self.minter.mint(server, tool, args)
            forwarded = mt.CallToolRequestParams(
                name=params.name, arguments={**args, TOKEN_ARG: token}
            )
            return await call_next(context.copy(message=forwarded))

        return await self.pipeline.run(request, execute, self.native)
