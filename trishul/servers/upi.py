"""UPI demo server. ``pay_upi`` succeeds only if the ledger row and the balance change commit
atomically; ``preview_pay_upi`` runs the same logic inside a SAVEPOINT and rolls it back."""

import sqlite3
from collections.abc import Callable
from datetime import datetime
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from trishul.store.db import DEMO_NOW, DEMO_PRINCIPAL, iso, transaction
from trishul.store.ids import IdGen


class PaymentError(Exception):
    """Payment refused (insufficient funds, bad amount, unknown account); nothing changed."""


def _apply_payment(
    conn: sqlite3.Connection,
    principal: str,
    payee_vpa: str,
    amount_paise: int,
    note: str,
    txn_id: str,
    ts: datetime,
) -> dict[str, Any]:
    """Debit + ledger insert. Caller owns the surrounding transaction / savepoint."""
    if isinstance(amount_paise, bool) or amount_paise <= 0:
        raise PaymentError("amount must be a positive integer number of paise")
    if not payee_vpa.strip():
        raise PaymentError("payee_vpa must not be empty")
    acct = conn.execute(
        "SELECT account_id, balance_paise FROM accounts WHERE principal_id=?", (principal,)
    ).fetchone()
    if acct is None:
        raise PaymentError("no account for principal")
    before = int(acct["balance_paise"])
    if before < amount_paise:
        raise PaymentError("insufficient funds")
    after = before - amount_paise
    conn.execute(
        "UPDATE accounts SET balance_paise=? WHERE account_id=?", (after, acct["account_id"])
    )
    conn.execute(
        "INSERT INTO ledger(txn_id, principal_id, account_id, payee_vpa, amount_paise,"
        " balance_after, note, ts) VALUES (?,?,?,?,?,?,?,?)",
        (txn_id, principal, acct["account_id"], payee_vpa, amount_paise, after, note, iso(ts)),
    )
    # verify inside the same transaction: the row exists and the balance really dropped
    check = conn.execute(
        "SELECT a.balance_paise AS b, (SELECT COUNT(*) FROM ledger WHERE txn_id=?) AS n"
        " FROM accounts a WHERE a.account_id=?",
        (txn_id, acct["account_id"]),
    ).fetchone()
    if check["n"] != 1 or check["b"] != after:
        raise PaymentError("ledger/balance inconsistency; rolled back")
    return {"txn_id": txn_id, "balance_after": after}


def preview_pay_upi(
    conn: sqlite3.Connection,
    payee_vpa: str,
    amount_paise: int,
    note: str = "",
    *,
    principal: str = DEMO_PRINCIPAL,
    now: datetime = DEMO_NOW,
) -> dict[str, Any]:
    """Dry run: returns ``{summary, balance_after}`` and never commits anything."""
    conn.execute("SAVEPOINT trishul_preview")
    try:
        result = _apply_payment(conn, principal, payee_vpa, amount_paise, note, "preview", now)
    finally:
        conn.execute("ROLLBACK TO trishul_preview")
        conn.execute("RELEASE trishul_preview")
    rupees = f"{amount_paise // 100}.{amount_paise % 100:02d}"
    return {
        "summary": f"Pay INR {rupees} to {payee_vpa}",
        "balance_after": result["balance_after"],
    }


def build_upi_server(
    conn: sqlite3.Connection,
    ids: IdGen,
    *,
    principal: str = DEMO_PRINCIPAL,
    clock: Callable[[], datetime] = lambda: DEMO_NOW,
) -> FastMCP:
    server = FastMCP("upi")

    # Tools are async without awaits: they run atomically on the event loop, so the shared
    # SQLite connection is never used from two threads at once.
    @server.tool
    async def pay_upi(payee_vpa: str, amount_paise: int, note: str = "") -> dict[str, Any]:
        """Pay ``amount_paise`` to ``payee_vpa``. Returns ``{txn_id, balance_after}``."""
        try:
            with transaction(conn):
                return _apply_payment(
                    conn, principal, payee_vpa, amount_paise, note, ids.new("txn"), clock()
                )
        except PaymentError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool
    async def get_balance() -> dict[str, Any]:
        """Current account balance in paise."""
        row = conn.execute(
            "SELECT balance_paise, currency FROM accounts WHERE principal_id=?", (principal,)
        ).fetchone()
        if row is None:
            raise ToolError("no account for principal")
        return {"balance_paise": int(row["balance_paise"]), "currency": row["currency"]}

    @server.tool
    async def list_payees() -> dict[str, Any]:
        """Saved payees for the principal."""
        rows = conn.execute(
            "SELECT vpa, name FROM payees WHERE principal_id=? ORDER BY payee_id", (principal,)
        ).fetchall()
        return {"payees": [{"vpa": r["vpa"], "name": r["name"]} for r in rows]}

    @server.tool
    async def add_payee(vpa: str, name: str) -> dict[str, Any]:
        """Save a payee. Idempotent on ``vpa``."""
        if not vpa.strip() or not name.strip():
            raise ToolError("vpa and name must not be empty")
        with transaction(conn):
            cur = conn.execute(
                "INSERT OR IGNORE INTO payees(payee_id, principal_id, vpa, name, added_by,"
                " created_ts) VALUES (?,?,?,?,?,?)",
                (ids.new("payee"), principal, vpa, name, "agent", iso(clock())),
            )
        return {"vpa": vpa, "name": name, "added": cur.rowcount == 1}

    return server
