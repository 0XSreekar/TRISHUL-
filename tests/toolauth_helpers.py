"""Test helpers that play the gateway: mint a per-call token for a directly used tool server."""

import sqlite3
from collections.abc import Callable
from typing import Any

from fastmcp import Client, FastMCP

from trishul.crypto.keys import KeyRing
from trishul.crypto.toolauth import TOKEN_ARG, ToolTokenMinter, ToolTokenVerifier


class TokenClient:
    """``Client`` for one in-process tool server that attaches a fresh gateway token per call."""

    def __init__(
        self,
        name: str,
        build: Callable[[ToolTokenVerifier], FastMCP],
        conn: sqlite3.Connection,
        keys: KeyRing | None = None,
    ) -> None:
        self.keys = keys or KeyRing.generate()
        self.name = name
        self.minter = ToolTokenMinter(self.keys)
        self.client = Client(build(ToolTokenVerifier(conn, self.keys.public_ring())))

    async def __aenter__(self) -> "TokenClient":
        await self.client.__aenter__()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.client.__aexit__(*exc)  # type: ignore[arg-type]

    async def call_tool(self, tool: str, args: dict[str, Any] | None = None, **kw: Any) -> Any:
        body = dict(args or {})
        token = self.minter.mint(self.name, tool, body)
        return await self.client.call_tool(tool, {**body, TOKEN_ARG: token}, **kw)
