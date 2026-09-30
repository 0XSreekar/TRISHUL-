"""Demo MCP servers exercised through fastmcp.Client (in-process, real MCP protocol)."""

import json
import sqlite3

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from trishul.servers import (
    build_crm_server,
    build_files_server,
    build_mail_server,
    build_upi_server,
)
from trishul.store.db import DEMO_BALANCE_PAISE, connect, reset
from trishul.store.ids import IdGen

ACME = "acme.supplies@okbank"


@pytest.fixture
def db() -> tuple[sqlite3.Connection, IdGen]:
    conn = connect(":memory:")
    return conn, reset(conn)


def balance(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT balance_paise FROM accounts").fetchone()[0])


async def test_pay_upi_commits_ledger_and_balance(db: tuple[sqlite3.Connection, IdGen]) -> None:
    conn, ids = db
    async with Client(build_upi_server(conn, ids)) as c:
        res = await c.call_tool("pay_upi", {"payee_vpa": ACME, "amount_paise": 450_000})
    assert res.data["balance_after"] == DEMO_BALANCE_PAISE - 450_000
    assert balance(conn) == DEMO_BALANCE_PAISE - 450_000
    row = conn.execute("SELECT * FROM ledger").fetchone()
    assert row["txn_id"] == res.data["txn_id"] and row["amount_paise"] == 450_000


async def test_insufficient_funds_errors_without_change(
    db: tuple[sqlite3.Connection, IdGen],
) -> None:
    conn, ids = db
    async with Client(build_upi_server(conn, ids)) as c:
        with pytest.raises(ToolError, match="insufficient funds"):
            await c.call_tool(
                "pay_upi", {"payee_vpa": ACME, "amount_paise": DEMO_BALANCE_PAISE + 1}
            )
    assert balance(conn) == DEMO_BALANCE_PAISE
    assert conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0] == 0
    assert not conn.in_transaction


async def test_nonpositive_amount_rejected(db: tuple[sqlite3.Connection, IdGen]) -> None:
    conn, ids = db
    async with Client(build_upi_server(conn, ids)) as c:
        for bad in (0, -5):
            with pytest.raises(ToolError):
                await c.call_tool("pay_upi", {"payee_vpa": ACME, "amount_paise": bad})
    assert balance(conn) == DEMO_BALANCE_PAISE


async def test_balance_payees_add_payee(db: tuple[sqlite3.Connection, IdGen]) -> None:
    conn, ids = db
    async with Client(build_upi_server(conn, ids)) as c:
        assert (await c.call_tool("get_balance", {})).data["balance_paise"] == DEMO_BALANCE_PAISE
        vpas = [p["vpa"] for p in (await c.call_tool("list_payees", {})).data["payees"]]
        assert ACME in vpas and len(vpas) == 3
        added = await c.call_tool("add_payee", {"vpa": "new@okbank", "name": "New"})
        assert added.data["added"] is True
        again = await c.call_tool("add_payee", {"vpa": "new@okbank", "name": "New"})
        assert again.data["added"] is False
        assert len((await c.call_tool("list_payees", {})).data["payees"]) == 4


async def test_reset_is_deterministic(db: tuple[sqlite3.Connection, IdGen]) -> None:
    conn, ids = db
    async with Client(build_upi_server(conn, ids)) as c:
        first = (await c.call_tool("pay_upi", {"payee_vpa": ACME, "amount_paise": 100})).data
    ids = reset(conn)
    assert balance(conn) == DEMO_BALANCE_PAISE
    async with Client(build_upi_server(conn, ids)) as c:
        second = (await c.call_tool("pay_upi", {"payee_vpa": ACME, "amount_paise": 100})).data
    assert first == second


async def test_crm_returns_full_record(db: tuple[sqlite3.Connection, IdGen]) -> None:
    conn, _ = db
    async with Client(build_crm_server(conn)) as c:
        rec = (
            await c.call_tool("read_customer_data", {"customer_id": "C-1042", "fields": ["name"]})
        ).data
        assert rec["customer_id"] == "C-1042" and rec["pan"] == "ABCPS5678K"
        assert rec["email"] and rec["aadhaar"] and rec["city"] == "Bangalore"
        out = (
            await c.call_tool("export_records", {"customer_ids": ["C-1042"], "destination": "x"})
        ).data
        assert out["count"] == 1 and out["destination"] == "x"
        with pytest.raises(ToolError):
            await c.call_tool("read_customer_data", {"customer_id": "nope", "fields": []})


async def test_mail_outbox_and_inbox(db: tuple[sqlite3.Connection, IdGen]) -> None:
    conn, ids = db
    conn.execute(
        "INSERT INTO inbox(mail_id, sender, subject, body, ts)"
        " VALUES ('m1','a@x.example','hi','yo','2026-09-30T00:00:00Z')"
    )
    async with Client(build_mail_server(conn, ids)) as c:
        sent = (
            await c.call_tool("send_email", {"to": "b@x.example", "subject": "s", "body": "b"})
        ).data
        assert sent["status"] == "queued"
        inbox = (await c.call_tool("read_inbox", {})).data
        assert [m["mail_id"] for m in inbox["messages"]] == ["m1"]
        with pytest.raises(ToolError):
            await c.call_tool("send_email", {"to": "nobody", "subject": "s", "body": "b"})
    row = conn.execute("SELECT * FROM outbox").fetchone()
    assert row["mail_id"] == sent["mail_id"] and row["to_addr"] == "b@x.example"


async def test_files_read_document(db: tuple[sqlite3.Connection, IdGen]) -> None:
    conn, _ = db
    docs = {r["name"]: r["doc_id"] for r in conn.execute("SELECT doc_id, name FROM documents")}
    async with Client(build_files_server(conn)) as c:
        good = (await c.call_tool("read_document", {"doc_id": docs["inv_trusted.html"]})).data
        bad = (await c.call_tool("read_document", {"doc_id": docs["inv_injected.html"]})).data
        assert good["trust"] == "user_upload" and "acme@okaxis" in good["content"]
        assert bad["trust"] == "external"
        assert set(good) == {"doc_id", "trust", "content"}
        with pytest.raises(ToolError):
            await c.call_tool("read_document", {"doc_id": "missing"})
    json.dumps(good)
