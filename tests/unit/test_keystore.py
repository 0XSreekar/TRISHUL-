"""Runtime key management: random keys, 0700/0600, kid in every signature, rotation."""

import json
import os
import stat
from pathlib import Path

import pytest

from tests.conftest import NOW, make_call
from trishul.approvals import ApprovalService
from trishul.audit.log import AuditLog
from trishul.audit.verify import verify
from trishul.cli.main import main
from trishul.crypto.keys import PURPOSES, KeyRing, purpose_of
from trishul.crypto.keystore import (
    KeyStoreError,
    keys_dir,
    load_or_create,
    load_public,
    load_ring,
    rotate,
    write_public,
)
from trishul.domains.payshield import issue_mandate
from trishul.store.db import connect
from trishul.store.ids import IdGen


def test_keys_are_random_with_strict_permissions(tmp_path: Path) -> None:
    a = load_or_create(tmp_path / "a")
    b = load_or_create(tmp_path / "b")
    for purpose in PURPOSES:
        kid = a.active_kid(purpose)
        assert kid.startswith(purpose + "-") and len(kid) == len(purpose) + 13
        assert purpose_of(kid) == purpose
        assert a.public_bytes(kid) != b.public_bytes(b.active_kid(purpose))  # nothing seed-derived
    directory = keys_dir(tmp_path / "a")
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    files = [f for f in directory.iterdir() if f.is_file() and f.name != ".lock"]
    assert len(files) == 2 * len(PURPOSES) + 1  # .key + .pub per purpose + keyring.json
    assert all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in files)
    index = json.loads((directory / "keyring.json").read_text())
    assert set(index) == set(PURPOSES)


def test_load_returns_the_same_keys_and_creation_is_idempotent(tmp_path: Path) -> None:
    first = load_or_create(tmp_path)
    again = load_or_create(tmp_path)
    assert first.key_ids() == again.key_ids()
    sig = first.sign(first.active_kid("gateway-tool"), {"x": 1})
    assert again.verify(first.active_kid("gateway-tool"), {"x": 1}, sig)


@pytest.mark.parametrize("target", ["dir", "key", "index"])
def test_group_or_world_accessible_keys_are_refused(tmp_path: Path, target: str) -> None:
    ring = load_or_create(tmp_path)
    directory = keys_dir(tmp_path)
    path = {
        "dir": directory,
        "key": directory / f"{ring.active_kid('mandate-signer')}.key",
        "index": directory / "keyring.json",
    }[target]
    os.chmod(path, 0o755 if target == "dir" else 0o644)
    with pytest.raises(KeyStoreError, match="accessible by group/other"):
        load_ring(tmp_path)
    with pytest.raises(KeyStoreError):
        load_or_create(tmp_path)


def test_missing_or_tampered_key_files_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(KeyStoreError):
        load_ring(tmp_path / "nothing")
    ring = load_or_create(tmp_path)
    kid = ring.active_kid("approval-signer")
    other = ring.active_kid("tree-head-signer")
    directory = keys_dir(tmp_path)
    (directory / f"{kid}.key").write_text((directory / f"{other}.key").read_text())
    with pytest.raises(KeyStoreError, match="does not match its key id"):
        load_ring(tmp_path)


def test_rotation_keeps_old_signatures_verifiable_and_records_kid(tmp_path: Path) -> None:
    conn = connect(":memory:")
    ring = load_or_create(tmp_path)
    old_tree = ring.active_kid("tree-head-signer")
    log = AuditLog(conn, ring, sth_every=1, clock=lambda: NOW)
    log.append({"type": "t", "n": 1})
    old_sth = log.latest_sth()
    assert old_sth is not None and old_sth.key_id == old_tree

    new_tree = rotate(tmp_path, "tree-head-signer")
    assert new_tree != old_tree and purpose_of(new_tree) == "tree-head-signer"
    ring2 = load_ring(tmp_path)
    assert ring2.active_kid("tree-head-signer") == new_tree
    assert {old_tree, new_tree} <= set(ring2.key_ids())
    log2 = AuditLog(conn, ring2, sth_every=1, clock=lambda: NOW)
    log2.append({"type": "t", "n": 2})
    heads = [log2.sth_for(1), log2.sth_for(2)]
    assert [h.key_id for h in heads if h] == [old_tree, new_tree]
    result = verify(conn, ring2.public_ring())  # old and new heads both verify
    assert result.ok, result
    with pytest.raises(KeyStoreError):
        rotate(tmp_path, "nonsense")


def test_approval_and_mandate_signatures_record_their_kid(tmp_path: Path) -> None:
    from datetime import timedelta

    from trishul.domains.payshield import MandatePayee

    ring = load_or_create(tmp_path)
    svc = ApprovalService(connect(":memory:"), ring, IdGen(1), clock=lambda: NOW)
    call = make_call("pay_upi", {"payee_vpa": "a@b", "amount_paise": 5})
    svc.request(call)
    token = svc.approve(svc.pending()[0]["approval_id"], "alice")
    assert token.key_id == ring.active_kid("approval-signer")
    assert svc.check(call, NOW).valid
    mandate = issue_mandate(
        ring,
        principal="p",
        payees=[MandatePayee(vpa="a@b", name="A", cap=100)],
        per_txn_cap=100,
        daily_cap=100,
        categories=("PAYMENT",),
        nbf=NOW,
        exp=NOW + timedelta(days=1),
        nonce="n",
    )
    assert mandate.key_id == ring.active_kid("mandate-signer")


def test_public_only_load_never_opens_private_files(tmp_path: Path) -> None:
    ring = load_or_create(tmp_path)
    write_public(ring, tmp_path / "pub")
    assert not list((tmp_path / "pub").glob("*.key"))
    pub = load_public(tmp_path / "pub")
    kid = ring.active_kid("gateway-tool")
    assert pub.verify(kid, {"a": 1}, ring.sign(kid, {"a": 1}))
    with pytest.raises(KeyError):
        pub.sign(kid, {"a": 1})


def test_cli_reset_creates_random_keys_and_rotate_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = str(tmp_path / "k.db")
    assert main(["demo", "reset", "--seed", "42", "--db", db]) == 0
    first = json.loads(capsys.readouterr().out)["key_ids"]
    assert main(["demo", "reset", "--seed", "42", "--db", db]) == 0
    assert json.loads(capsys.readouterr().out)["key_ids"] == first  # kept, not regenerated
    assert main(["demo", "reset", "--seed", "42", "--db", db, "--rotate-keys"]) == 0
    rotated = json.loads(capsys.readouterr().out)["key_ids"]
    assert all(rotated[p] != first[p] for p in PURPOSES)
    ring = load_ring()
    assert all(k in ring.key_ids() for k in (*first.values(), *rotated.values()))
    assert main(["keys", "rotate", "gateway-tool"]) == 0
    assert json.loads(capsys.readouterr().out)["purpose"] == "gateway-tool"
    assert main(["keys", "rotate", "bogus"]) == 1


def test_seed_derived_ring_is_not_a_runtime_default() -> None:
    from trishul.gateway.app import build_gateway

    conn = connect(":memory:")
    gw = build_gateway(conn, IdGen(42), seed=42)
    assert gw.pipeline.keys.public_bytes(gw.pipeline.keys.active_kid("gateway-tool")) != (
        KeyRing.from_seed(42).public_bytes("gateway-tool")
    )
