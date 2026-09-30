import copy
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import make_call
from trishul.audit.log import AuditLog
from trishul.crypto.keys import KeyRing
from trishul.domains.dpdp import dpdp_report, verify_dpdp_report
from trishul.domains.purposelock import audit_event
from trishul.store.db import connect, reset

KEYS = KeyRing.from_seed(42)


@pytest.fixture
def setup(tmp_path: Path) -> Iterator[tuple[Any, AuditLog]]:
    conn = connect(tmp_path / "t.db")
    reset(conn)
    log = AuditLog(conn, KEYS, sth_every=4)
    call = make_call("read_customer_data", {"customer_id": "C-1042"})
    for i in range(7):
        log.append({"domain": "gateway", "type": "decision", "n": i})
        if i % 2 == 0:
            log.append(
                audit_event(call, "order_support", {"consent_active": True}, "ALLOW", [f"r{i}"])
            )
    yield conn, log
    conn.close()


def test_report_contains_only_purposelock_events_with_proofs(setup) -> None:  # type: ignore[no-untyped-def]
    conn, log = setup
    report = dpdp_report(conn, KEYS)
    assert [e["event"]["domain"] for e in report["entries"]] == ["purposelock"] * 4
    assert [e["index"] for e in report["entries"]] == [1, 4, 7, 10]
    assert report["sth"]["size"] == log.size() == 11
    assert report["unanchored"] == []
    assert verify_dpdp_report(report, KEYS.public_ring())
    # survives a JSON round trip (what `report --dpdp` would emit)
    assert verify_dpdp_report(json.loads(json.dumps(report)), KEYS.public_ring())


def test_tampered_event_fails(setup) -> None:  # type: ignore[no-untyped-def]
    report = dpdp_report(setup[0], KEYS)
    bad = copy.deepcopy(report)
    bad["entries"][0]["event"]["decision"] = "DENY"
    assert not verify_dpdp_report(bad, KEYS.public_ring())


def test_tampered_proof_fails(setup) -> None:  # type: ignore[no-untyped-def]
    report = dpdp_report(setup[0], KEYS)

    def swap_path(r: dict[str, Any]) -> None:
        path = list(r["entries"][0]["proof"]["path"])
        path[0] = "00" * 32
        r["entries"][0]["proof"]["path"] = path

    def bump_index(r: dict[str, Any]) -> None:
        r["entries"][0]["proof"]["index"] = 0

    def bad_root(r: dict[str, Any]) -> None:
        r["entries"][0]["proof"]["root"] = "11" * 32

    def duplicate(r: dict[str, Any]) -> None:
        r["entries"][1] = r["entries"][0]

    for mutate in (swap_path, bump_index, bad_root, duplicate):
        bad = copy.deepcopy(report)
        mutate(bad)
        assert not verify_dpdp_report(bad, KEYS.public_ring()), mutate.__name__


def test_tampered_or_wrong_sth_fails(setup) -> None:  # type: ignore[no-untyped-def]
    report = dpdp_report(setup[0], KEYS)
    bad = copy.deepcopy(report)
    bad["sth"]["root"] = "22" * 32
    assert not verify_dpdp_report(bad, KEYS.public_ring())
    assert not verify_dpdp_report(report, KeyRing.from_seed(7).public_ring())
    assert not verify_dpdp_report({"garbage": 1}, KEYS.public_ring())


def test_report_detects_tampered_log_row(setup) -> None:  # type: ignore[no-untyped-def]
    conn, _ = setup
    row = conn.execute("SELECT idx, payload FROM audit_leaves WHERE idx = 1").fetchone()
    conn.execute(
        "UPDATE audit_leaves SET payload = ? WHERE idx = 1",
        (bytes(row["payload"]).replace(b"ALLOW", b"DENY!"),),
    )
    report = dpdp_report(conn, KEYS)  # proofs use the stored (unchanged) leaf_hash ...
    assert not verify_dpdp_report(report, KEYS.public_ring())  # ... event no longer matches


def test_empty_log(tmp_path: Path) -> None:
    conn = connect(tmp_path / "e.db")
    report = dpdp_report(conn, KEYS)
    assert report["entries"] == [] and verify_dpdp_report(report, KEYS.public_ring())
    conn.close()


def test_public_only_keys_use_stored_sth(setup) -> None:  # type: ignore[no-untyped-def]
    conn, _ = setup
    report = dpdp_report(conn, KEYS.public_ring())  # cannot sign: latest STH (size 8)
    assert report["sth"]["size"] == 8
    assert report["unanchored"] == [10]
    assert [e["index"] for e in report["entries"]] == [1, 4, 7]
    assert verify_dpdp_report(report, KEYS.public_ring())
