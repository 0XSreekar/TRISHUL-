"""The gateway over real stdio subprocess servers (what ``trishul start`` runs)."""

import json
from pathlib import Path

import pytest
from fastmcp import Client

from trishul.crypto.keys import KeyRing
from trishul.gateway.app import build_stdio_gateway, seed_demo_mandate
from trishul.store.db import DEMO_NOW, connect, reset

ACME = "acme@okaxis"


async def test_pay_over_stdio_subprocess_servers(tmp_path: Path) -> None:
    db = tmp_path / "stdio.db"
    conn = connect(db)
    ids = reset(conn, seed=42)
    keys = KeyRing.from_seed(42)
    seed_demo_mandate(conn, keys, now=DEMO_NOW)
    gw = build_stdio_gateway(conn, ids, db, seed=42, keys=keys)
    args = {"payee_vpa": ACME, "amount_paise": 100_000}
    async with Client(gw.mcp) as client:
        gw.bind_task(purpose="payment_processing", category="PAYMENT", text="pay", params=args)
        ok = await client.call_tool("upi_pay_upi", args)
        assert ok.structured_content and ok.structured_content["balance_after"] == 4_900_000
        bad = await client.call_tool(
            "upi_pay_upi", {"payee_vpa": "evil@okaxis", "amount_paise": 1}, raise_on_error=False
        )
        assert bad.is_error
        assert json.loads(bad.content[0].text[bad.content[0].text.index("{") :])["decision"] == (  # type: ignore[union-attr]
            "DENY"
        )
    assert conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0] == 1
    conn.close()
    assert pytest is not None
