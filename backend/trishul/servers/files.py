# SPDX-License-Identifier: Apache-2.0
"""Document demo server; each document carries a ``trust`` column the gateway uses for labels."""

import sqlite3
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from trishul.crypto.toolauth import ToolAuthMiddleware, ToolTokenVerifier


def build_files_server(conn: sqlite3.Connection, *, verifier: ToolTokenVerifier) -> FastMCP:
    server = FastMCP("files")
    server.add_middleware(ToolAuthMiddleware(verifier, "files"))

    @server.tool
    async def read_document(doc_id: str) -> dict[str, Any]:
        """Return ``{doc_id, trust, content}`` for a stored document."""
        row = conn.execute(
            "SELECT doc_id, trust, content FROM documents WHERE doc_id=?", (doc_id,)
        ).fetchone()
        if row is None:
            raise ToolError(f"unknown document {doc_id}")
        return {"doc_id": row["doc_id"], "trust": row["trust"], "content": row["content"]}

    return server
