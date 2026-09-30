"""Mail demo server: sends into an outbox table, reads a seeded inbox."""

import sqlite3
from collections.abc import Callable
from datetime import datetime
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from trishul.crypto.toolauth import ToolAuthMiddleware, ToolTokenVerifier
from trishul.store.db import DEMO_NOW, iso, transaction
from trishul.store.ids import IdGen

DEMO_SENDER = "assistant@trishul.example"


def build_mail_server(
    conn: sqlite3.Connection,
    ids: IdGen,
    *,
    verifier: ToolTokenVerifier,
    clock: Callable[[], datetime] = lambda: DEMO_NOW,
) -> FastMCP:
    server = FastMCP("mail")
    server.add_middleware(ToolAuthMiddleware(verifier, "mail"))

    @server.tool
    async def send_email(to: str, subject: str, body: str) -> dict[str, Any]:
        """Queue an email in the outbox."""
        if "@" not in to:
            raise ToolError("invalid recipient address")
        mail_id = ids.new("mail")
        with transaction(conn):
            conn.execute(
                "INSERT INTO outbox(mail_id, sender, to_addr, subject, body, ts)"
                " VALUES (?,?,?,?,?,?)",
                (mail_id, DEMO_SENDER, to, subject, body, iso(clock())),
            )
        return {"mail_id": mail_id, "status": "queued"}

    @server.tool
    async def read_inbox() -> dict[str, Any]:
        """List inbox messages (oldest first)."""
        rows = conn.execute("SELECT * FROM inbox ORDER BY ts, mail_id").fetchall()
        return {
            "messages": [
                {k: r[k] for k in ("mail_id", "sender", "subject", "body", "ts")} for r in rows
            ]
        }

    return server
