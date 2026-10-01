import sqlite3
from datetime import UTC, datetime

import pytest

from trishul.audit import merkle
from trishul.audit.log import AuditLog, redact
from trishul.audit.verify import verify
from trishul.crypto.keys import KeyRing
from trishul.store.db import connect

T0 = datetime(2026, 9, 30, tzinfo=UTC)


def make_log(sth_every: int = 4) -> tuple[AuditLog, sqlite3.Connection, KeyRing]:
    conn = connect(":memory:")
    keys = KeyRing.from_seed(42)
    return AuditLog(conn, keys, sth_every=sth_every, clock=lambda: T0), conn, keys


def fill(log: AuditLog, n: int) -> None:
    for i in range(n):
        log.append({"i": i, "decision": "ALLOW", "call_digest": "d" * 8})


def test_append_verify_and_sth_cadence() -> None:
    log, conn, keys = make_log(4)
    fill(log, 10)
    assert log.size() == 10
    sizes = [r[0] for r in conn.execute("SELECT size FROM tree_heads ORDER BY size")]
    assert sizes == [4, 8]
    result = verify(conn, keys)
    assert result.ok and result.size == 10 and result.bad_index is None
    assert log.sth_now().size == 10
    assert log.sth_now().size == 10  # idempotent
    assert verify(conn, keys).ok


def test_redaction_keeps_digests_drops_secrets() -> None:
    log, _, _ = make_log()
    log.append(
        {"call_digest": "abc", "signature": "s", "nested": {"api_key": "k", "ok": [{"seed": 1}]}}
    )
    assert log.payload(0) == b'{"call_digest":"abc","nested":{"ok":[{}]}}'
    assert redact({"password": 1}) == {}


def test_proofs_against_log_and_sth() -> None:
    log, _, keys = make_log(4)
    fill(log, 13)
    for i in range(13):
        proof = log.inclusion_proof(i)
        assert proof.check()
        assert proof.root == merkle.hexd(log.root())
    old = log.sth_for(8)
    assert old is not None
    cons = log.consistency_proof(8)
    assert cons.check() and cons.first_root == old.root
    assert log.inclusion_proof(2, size=8).root == old.root
    assert keys.verify(old.key_id, old.signed_payload(), old.sig)


@pytest.mark.acceptance(16)
def test_leaf_tamper_reports_exact_index_and_covering_sths() -> None:
    log, conn, keys = make_log(4)
    fill(log, 10)
    conn.execute("UPDATE audit_leaves SET payload = ? WHERE idx = 5", (b'{"i":999}',))
    result = verify(conn, keys)
    assert not result.ok
    assert result.bad_index == 5
    assert result.invalid_sths == (8,)


def test_leaf_hash_tamper_and_deleted_row() -> None:
    log, conn, keys = make_log(4)
    fill(log, 6)
    conn.execute("UPDATE audit_leaves SET leaf_hash = ? WHERE idx = 2", ("00" * 32,))
    assert verify(conn, keys).bad_index == 2
    log, conn, keys = make_log(4)
    fill(log, 6)
    conn.execute("DELETE FROM audit_leaves WHERE idx = 1")
    result = verify(conn, keys)
    assert result.bad_index == 1 and 4 in result.invalid_sths


def test_sth_tamper_and_forgery() -> None:
    log, conn, keys = make_log(4)
    fill(log, 8)
    conn.execute("UPDATE tree_heads SET root = ? WHERE size = 4", ("11" * 32,))
    result = verify(conn, keys)
    assert result.bad_index is None and result.invalid_sths == (4,) and not result.ok
    # a validly-shaped head signed by the wrong key
    forged = KeyRing.from_seed(7)
    good_root = merkle.hexd(merkle.mth(log.leaf_hashes(4)))
    head = {"size": 4, "root": good_root, "ts": "2026-09-30T00:00:00Z"}
    conn.execute(
        "UPDATE tree_heads SET root=?, sig=? WHERE size=4",
        (good_root, forged.sign("gateway", head)),
    )
    assert verify(conn, keys).invalid_sths == (4,)


def test_sth_beyond_log_is_invalid() -> None:
    log, conn, keys = make_log(4)
    fill(log, 8)
    conn.execute("DELETE FROM audit_leaves WHERE idx >= 6")
    assert verify(conn, keys).invalid_sths == (8,)


def test_concurrent_writers_do_not_corrupt(tmp_path: pytest.TempPathFactory) -> None:
    path = tmp_path / "a.db"  # type: ignore[operator]
    keys = KeyRing.from_seed(1)
    a = AuditLog(connect(path), keys, sth_every=3)
    b = AuditLog(connect(path), keys, sth_every=3)
    for i in range(9):
        (a if i % 2 else b).append({"i": i})
    assert verify(a.conn, keys).ok and a.size() == 9
