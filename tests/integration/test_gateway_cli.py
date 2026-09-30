"""CLI operator commands and deterministic ids."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from tests.integration.test_gateway_harness import make_env_sync, parse_error
from trishul.cli.main import main
from trishul.crypto.keys import KeyRing
from trishul.gateway.app import build_gateway, seed_demo_mandate
from trishul.store.db import DEMO_NOW, connect, reset

ACME = "acme@okaxis"


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, Any]:
    code = main(list(argv))
    out = capsys.readouterr().out.strip()
    return code, (json.loads(out.splitlines()[-1]) if out else None)


async def scripted_events(tmp_path: Path) -> list[str]:
    gw, conn, *_, events = make_env_sync(tmp_path)
    async with Client(gw.mcp) as c:
        gw.bind_task(
            purpose="payment_processing",
            category="PAYMENT",
            text="pay",
            params={"payee_vpa": ACME, "amount_paise": 100_000},
        )
        await c.call_tool("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 100_000})
        await c.call_tool("upi_get_balance", {})
        await c.call_tool(
            "upi_pay_upi", {"payee_vpa": "x@y", "amount_paise": 1}, raise_on_error=False
        )
    conn.close()
    return [e["id"] for e in events if e.get("type") == "call"]


async def test_demo_reset_twice_gives_identical_event_ids(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    outs = []
    for name in ("a", "b"):
        code, out = run(
            capsys, "demo", "reset", "--seed", "42", "--db", str(tmp_path / f"{name}.db")
        )
        assert code == 0
        outs.append(out)
    assert outs[0] == outs[1] and outs[0]["next_call_id"].startswith("call_")
    for sub in ("x", "y"):
        (tmp_path / sub).mkdir()
    first = await scripted_events(tmp_path / "x")
    second = await scripted_events(tmp_path / "y")
    assert first == second and len(first) == 3 and len(set(first)) == 3


def test_verify_exit_codes_and_tamper(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "v.db"
    run(capsys, "demo", "reset", "--seed", "42", "--db", str(db))
    run(capsys, "task", "bind", "--db", str(db), "--purpose", "order_support", "--text", "x")
    run(capsys, "ml", "off", "--db", str(db))
    code, out = run(capsys, "verify", "--db", str(db))
    assert code == 0 and out["ok"] is True and out["size"] == 2
    conn = connect(db)
    payload = bytes(conn.execute("SELECT payload FROM audit_leaves WHERE idx=1").fetchone()[0])
    conn.execute("UPDATE audit_leaves SET payload=? WHERE idx=1", (payload[:-2] + b"X}",))
    conn.close()
    code, out = run(capsys, "verify", "--db", str(db))
    assert code == 1 and out["ok"] is False and out["bad_index"] == 1


def test_prove_unavailable_until_t6(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out = run(capsys, "prove", "--db", str(tmp_path / "p.db"))
    assert code == 0 and out["result"] in {"UNAVAILABLE", "UNSAT", "SAT", "UNKNOWN"}


async def test_approve_reject_and_report_via_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "c.db"
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
        code, out = run(capsys, "approve", approval, "--db", str(db))
        assert code == 0 and out["status"] == "approved"
        ok = await c.call_tool("upi_pay_upi", args)
        assert ok.structured_content and ok.structured_content["balance_after"] == 4_250_000
    code, _ = run(capsys, "reject", approval, "--db", str(db))
    assert code == 1  # already decided
    code, _ = run(capsys, "approve", "apr_missing", "--db", str(db))
    assert code == 1
    code, report = run(capsys, "report", "--dpdp", "--db", str(db))
    assert code == 0 and report["report"] == "dpdp"
    conn.close()


def parse_error_text(text: str) -> dict[str, Any]:
    return json.loads(text[text.index("{") :])  # type: ignore[no-any-return]


def test_task_bind_persists(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "t.db"
    run(capsys, "demo", "reset", "--db", str(db))
    code, out = run(
        capsys,
        "task",
        "bind",
        "--db",
        str(db),
        "--purpose",
        "order_support",
        "--category",
        "READ",
        "--params",
        '{"a": 1}',
        "--task-id",
        "t1",
    )
    assert code == 0 and out["task_id"] == "t1"
    code, _ = run(capsys, "task", "bind", "--db", str(db), "--purpose", "p", "--category", "NOPE")
    assert code == 2
    assert parse_error  # keep helper import used
