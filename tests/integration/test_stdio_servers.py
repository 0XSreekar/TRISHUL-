"""Stdio subprocess servers: a fresh process per request must not re-issue stored ids."""

from pathlib import Path

from fastmcp import Client

from trishul.crypto.keys import KeyRing
from trishul.crypto.keystore import write_public
from trishul.crypto.toolauth import TOKEN_ARG, ToolTokenMinter
from trishul.gateway.app import stdio_config
from trishul.store.db import connect, reset


async def test_sequential_stdio_payments_get_distinct_txn_ids(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    conn = connect(db)
    reset(conn, seed=42)
    keys = KeyRing.generate()
    write_public(keys, tmp_path / "pub")
    minter = ToolTokenMinter(keys)
    cfg = stdio_config(db, tmp_path / "pub")
    for amount in (1000, 2000, 3000):  # each call below spawns a new subprocess
        args = {"payee_vpa": "acme@okaxis", "amount_paise": amount}
        token = minter.mint("upi", "pay_upi", args)
        async with Client(cfg) as c:
            await c.call_tool("upi_pay_upi", {**args, TOKEN_ARG: token})
    rows = conn.execute("SELECT txn_id FROM ledger").fetchall()
    assert len({r[0] for r in rows}) == 3
