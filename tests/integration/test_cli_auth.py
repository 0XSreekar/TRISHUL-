"""CLI approve/reject authenticate as an approver; reset provisions accounts and audits itself."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from tests.integration.test_gateway_cli import ACME, parse_error_text, run
from trishul.auth.service import user_id_for
from trishul.crypto.keys import KeyRing
from trishul.gateway.app import build_gateway, seed_demo_mandate
from trishul.store.db import DEMO_NOW, connect, reset

PW = "cli-approver-pw-123"


def first_leaf(db: Path) -> dict[str, Any]:
    conn = connect(db)
    row = conn.execute("SELECT payload FROM audit_leaves WHERE idx=0").fetchone()
    conn.close()
    return json.loads(bytes(row["payload"]))  # type: ignore[no-any-return]


def test_reset_creates_accounts_from_env_and_writes_first_leaf(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRISHUL_APPROVER_PASSWORD", PW)
    monkeypatch.delenv("TRISHUL_OPERATOR_PASSWORD", raising=False)
    db = tmp_path / "r.db"
    code, out = run(capsys, "demo", "reset", "--seed", "42", "--db", str(db))
    assert code == 0 and out["accounts"]["approver"] == "created"
    assert out["accounts"]["operator"].startswith("not created: set TRISHUL_OPERATOR_PASSWORD")
    assert PW not in json.dumps(out)
    leaf = first_leaf(db)
    assert leaf["type"] == "operator_action" and leaf["action"] == "demo_reset"
    assert leaf["actor"] == "cli"
    conn = connect(db)
    names = [r[0] for r in conn.execute("SELECT username FROM users")]
    conn.close()
    assert names == ["approver"]


async def test_cli_approve_authenticates_and_records_approver_id(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRISHUL_APPROVER_PASSWORD", PW)
    db = tmp_path / "a.db"
    run(capsys, "demo", "reset", "--seed", "42", "--db", str(db))
    conn = connect(db)
    ids = reset(conn, seed=42)
    keys = KeyRing.from_seed(42)
    seed_demo_mandate(conn, keys, now=DEMO_NOW)
    gw = build_gateway(conn, ids, seed=42, keys=keys)
    args = {"payee_vpa": ACME, "amount_paise": 750_000}
    async with Client(gw.mcp) as c:
        gw.bind_task(purpose="payment_processing", category="PAYMENT", text="pay", params=args)
        res = await c.call_tool("upi_pay_upi", args, raise_on_error=False)
        approval = parse_error_text(res.content[0].text)["approval_id"]  # type: ignore[union-attr]
        monkeypatch.setenv("TRISHUL_APPROVER_PASSWORD", "wrong-password-999")
        code, _ = run(capsys, "approve", approval, "--db", str(db))
        assert code == 1 and gw.pipeline.approvals.get(approval)["status"] == "pending"
        code, _ = run(capsys, "approve", approval, "--db", str(db), "--user", "nobody")
        assert code == 1 and gw.pipeline.approvals.get(approval)["status"] == "pending"
        monkeypatch.setenv("TRISHUL_APPROVER_PASSWORD", PW)
        code, out = run(capsys, "approve", approval, "--db", str(db))
        assert code == 0 and out["status"] == "approved"
    row = gw.pipeline.approvals.get(approval)
    assert row["approver"] == user_id_for("approver")
    assert json.loads(row["token"])["approver"] == user_id_for("approver")
    conn.close()


def test_cli_approve_fails_closed_without_an_account(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TRISHUL_APPROVER_PASSWORD", raising=False)
    db = tmp_path / "n.db"
    run(capsys, "demo", "reset", "--seed", "42", "--db", str(db))
    monkeypatch.setenv("TRISHUL_APPROVER_PASSWORD", PW)
    code, _ = run(capsys, "approve", "apr_1", "--db", str(db))
    assert code == 1
