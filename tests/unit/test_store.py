import sqlite3
from pathlib import Path

import pytest

from trishul.store.db import DEMO_PRINCIPAL, TABLES, connect, reset, transaction
from trishul.store.ids import IdGen


def dump(conn: sqlite3.Connection) -> dict[str, list[tuple[object, ...]]]:
    return {
        t: [tuple(r) for r in conn.execute(f"SELECT * FROM {t} ORDER BY 1")]  # noqa: S608
        for t in TABLES
    }


def test_wal_foreign_keys_and_busy_timeout(tmp_path: Path) -> None:
    conn = connect(tmp_path / "t.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] >= 1000
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert set(TABLES) <= names
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO mandate_nonces(nonce, mandate_id, ts) VALUES ('n','nope','t')")


def test_transaction_rolls_back(tmp_path: Path) -> None:
    conn = connect(tmp_path / "t.db")
    with pytest.raises(RuntimeError), transaction(conn):
        conn.execute("INSERT INTO meta(key, value) VALUES ('k','v')")
        raise RuntimeError
    assert conn.execute("SELECT COUNT(*) FROM meta").fetchone()[0] == 0


def test_reset_is_deterministic_and_wipes(tmp_path: Path) -> None:
    a, b = connect(tmp_path / "a.db"), connect(tmp_path / "b.db")
    ids_a = reset(a, 42)
    a.execute("UPDATE accounts SET balance_paise = 1")
    a.execute("INSERT INTO inbox(mail_id, sender, subject, body, ts) VALUES ('m','s','s','b','t')")
    reset(a, 42)
    reset(b, 42)
    assert dump(a) == dump(b)
    assert ids_a.new("evt") == IdGen(42, start=ids_a.counter - 1).new("evt")
    acct = a.execute("SELECT balance_paise FROM accounts").fetchone()[0]
    assert acct == 5_000_000
    payees = [
        r[0]
        for r in a.execute("SELECT payee_id FROM payees WHERE principal_id=?", (DEMO_PRINCIPAL,))
    ]
    other = connect(tmp_path / "c.db")
    reset(other, 7)
    assert payees != [r[0] for r in other.execute("SELECT payee_id FROM payees")]


def test_reset_loads_fixtures_when_present(tmp_path: Path) -> None:
    conn = connect(tmp_path / "t.db")
    reset(conn, 42)
    assert conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0] >= 6
    assert conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0] >= 2
    empty = tmp_path / "nofix"
    empty.mkdir()
    reset(conn, 42, fixtures_dir=empty)
    assert conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0] == 0


def test_idgen() -> None:
    g, h = IdGen(42), IdGen(42)
    seq = [g.new("evt"), g.new("call"), g.new("evt")]
    assert seq == [h.new("evt"), h.new("call"), h.new("evt")]
    assert len(set(seq)) == 3
    assert seq[0].startswith("evt_000001")
    assert IdGen(1).new("evt") != IdGen(2).new("evt")
    with pytest.raises(ValueError):
        g.new("bad_prefix")
