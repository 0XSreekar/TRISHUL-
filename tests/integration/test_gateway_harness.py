"""Shared harness for gateway integration tests plus basic gateway behaviour tests."""

import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from trishul.audit.verify import verify
from trishul.crypto.keys import KeyRing
from trishul.gateway.app import Gateway, build_gateway, seed_demo_mandate
from trishul.store.db import DEMO_NOW, connect, reset
from trishul.store.ids import IdGen


class Clock:
    def __init__(self) -> None:
        self.now = DEMO_NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now = self.now + timedelta(**kw)


@dataclass
class Env:
    gw: Gateway
    client: Client[Any]
    conn: sqlite3.Connection
    ids: IdGen
    keys: KeyRing
    clock: Clock
    events: list[dict[str, Any]]

    def doc_id(self, name: str) -> str:
        row = self.conn.execute("SELECT doc_id FROM documents WHERE name=?", (name,)).fetchone()
        return str(row["doc_id"])

    def ledger_rows(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0])

    def balance(self) -> int:
        return int(self.conn.execute("SELECT balance_paise FROM accounts").fetchone()[0])

    async def call(self, name: str, args: Mapping[str, Any] | None = None) -> dict[str, Any]:
        result = await self.client.call_tool(name, dict(args or {}))
        assert isinstance(result.structured_content, dict)
        return result.structured_content

    async def denied(self, name: str, args: Mapping[str, Any] | None = None) -> dict[str, Any]:
        with pytest.raises(ToolError) as info:
            await self.client.call_tool(name, dict(args or {}))
        return parse_error(info.value)

    def call_events(self) -> list[dict[str, Any]]:
        return [e for e in self.events if e.get("type") == "call"]


def parse_error(exc: ToolError) -> dict[str, Any]:
    text = str(exc)
    return json.loads(text[text.index("{") :])  # type: ignore[no-any-return]


def make_env_sync(
    tmp_path: Path, **kw: Any
) -> tuple[Gateway, sqlite3.Connection, IdGen, KeyRing, Clock, list[dict[str, Any]]]:
    conn = connect(tmp_path / "gw.db")
    ids = reset(conn, seed=42)
    keys = KeyRing.from_seed(42)
    clock = Clock()
    payees = kw.pop("payees", None)
    mandate = kw.pop("mandate", True)
    if mandate:
        seed_demo_mandate(conn, keys, now=DEMO_NOW, payees=payees, **kw.pop("mandate_kw", {}))
    gw = build_gateway(conn, ids, seed=42, keys=keys, clock=clock, **kw)
    events: list[dict[str, Any]] = []
    original = gw.bus.publish

    def spy(event: dict[str, Any]) -> int:
        events.append(event)
        return original(event)

    gw.bus.publish = spy  # type: ignore[method-assign]
    return gw, conn, ids, keys, clock, events


TRUSTED_INVOICE = "inv_trusted.html"
INJECTED_INVOICE = "inv_injected.html"
FAR = datetime(2030, 1, 1, tzinfo=UTC)


# --- basic behaviour ---------------------------------------------------------------------------


async def test_unbound_task_is_denied(env: Env) -> None:
    body = await env.denied("upi_get_balance")
    assert body["decision"] == "DENY" and "CORE.TASK.UNBOUND" in body["rules"]


async def test_lists_namespaced_and_native_tools(env: Env) -> None:
    names = {t.name for t in await env.client.list_tools()}
    assert {"upi_pay_upi", "crm_read_customer_data", "mail_send_email", "files_read_document"} <= (
        names
    )
    assert {"extract_field", "voice_command"} <= names


async def test_balance_allowed_and_audited(env: Env) -> None:
    env.gw.bind_task(purpose="payment_processing", category="READ", text="check balance")
    out = await env.call("upi_get_balance")
    assert out["balance_paise"] == 5_000_000
    assert verify(env.conn, env.keys).ok
    ev = env.call_events()[-1]
    assert ev["decision"] == "ALLOW" and ev["audit_hash"] and ev["tree_head"]["size"] >= 1
