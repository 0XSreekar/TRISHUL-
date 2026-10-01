"""Regression tests for the independent-verification bugs (reset feed, FinBot decisions, demo
approvals, voice warm-up, live clock, audit health)."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from starlette.testclient import TestClient

from tests.integration.test_gateway_harness import Env, make_env_sync
from trishul.finbot.agent import FinBot
from trishul.gateway.app import live_clock
from trishul.telemetry import EventBus


def _call(cid: str) -> dict[str, Any]:
    return {"type": "call", "id": cid, "tool": "pay_upi", "decision": "ALLOW"}


def test_bus_reset_forgets_seen_calls_and_announces_reset() -> None:
    bus = EventBus()
    first = bus.publish(_call("call_1"))
    assert bus.publish(_call("call_1")) == first  # dedup within one run
    reset_seq = bus.reset()
    assert reset_seq > first and [e["type"] for e in bus.snapshot()] == ["reset"]
    again = bus.publish(_call("call_1"))  # same deterministic id after a reset is a NEW call
    assert again > reset_seq and bus.snapshot(reset_seq)[0]["id"] == "call_1"


async def test_reset_then_same_moment_step_publishes_call_event(env: Env) -> None:
    with TestClient(env.gw.api(allowed_origins=["null"])) as c:
        assert c.post("/demo/reset", json={"seed": 42}).status_code == 200
        first = await env.gw.backend.demo_moment(3, 1)
        assert first["event_ids"]
        assert c.post("/demo/reset", json={"seed": 42}).status_code == 200
        n_first = len(env.call_events())
        assert n_first > 0
        second = await env.gw.backend.demo_moment(3, 1)
    assert second["event_ids"] and second["event_ids"] == first["event_ids"]
    assert len(env.call_events()) == 2 * n_first  # the re-run calls reached the bus
    assert "reset" in [e["type"] for e in env.events]


async def test_finbot_never_invents_allow_when_no_event_arrives(env: Env) -> None:
    class Silent:
        seq = 0

        def snapshot(self, after: int = 0) -> list[dict[str, Any]]:
            return []

    bot = FinBot(env.client, env.gw.backend, Silent(), agent="finbot")  # type: ignore[arg-type]
    bot.bind(purpose="payment_processing", category="READ", text="balance")
    res = await bot.call("upi_get_balance")
    assert res["decision"] == "UNKNOWN" and res["error"] == "no_decision_event"


async def test_moment_3_step_by_step_never_auto_approves(env: Env) -> None:
    backend = env.gw.backend
    s3 = (await backend.demo_moment(3, 3))["steps"][0]
    assert s3["status"] == "awaiting_approval" and "auto_approved" not in s3
    row = env.conn.execute("SELECT status, approver FROM approvals").fetchone()
    assert row["status"] == "pending" and row["approver"] is None
    first5 = (await backend.demo_moment(3, 5))["steps"][0]
    assert first5["status"] == "awaiting_approval" and "auto_approved" not in first5
    again = (await backend.demo_moment(3, 5))["steps"][0]  # still pending: no new call
    assert again["status"] == "awaiting_approval"
    backend.resolve_approval(first5["approval_id"], "approve", "real-approver")
    changed = (await backend.demo_moment(3, 5))["steps"][0]
    assert changed["decision"] == "DENY"
    assert "PAYSHIELD.APPROVAL.BINDING_MISMATCH" in changed["rules"]
    assert changed["approver"] == "real-approver"


async def test_moment_3_run_all_labels_demo_script_approver(env: Env) -> None:
    out = await env.gw.backend.demo_moment(3)
    by = {s["name"]: s for s in out["steps"]}
    for name in ("over_cap_step_up", "approve_then_change_amount"):
        assert by[name]["auto_approved"] is True and by[name]["approved_by"] == "demo-script"
        assert "auto-approved by demo script" in by[name]["auto_approval_note"]
    approvers = {r["approver"] for r in env.conn.execute("SELECT approver FROM approvals")}
    assert approvers == {"demo-script"}


async def test_moment_6_warms_models_before_issuing_nonce(tmp_path: Path) -> None:
    from trishul.domains.voice_adapters import DeterministicSpoofAdapter, ScriptedASR
    from trishul.domains.voicetrust import NonceService, VoiceTrust

    nonces = NonceService()
    order: list[str] = []

    class Cold(VoiceTrust):
        def warmup(self) -> str:
            order.append(f"warm:live_nonces={sum(len(b) for b in nonces._live.values())}")
            self.warm_state = "warm"
            return self.warm_state

    vt = Cold(nonces, ScriptedASR(None), DeterministicSpoofAdapter())
    gw, conn, *_ = make_env_sync(tmp_path, voice=vt)
    try:
        assert vt.warm_state == "cold"
        await gw.backend.demo_moment(6, 1)
        assert order == ["warm:live_nonces=0"]
    finally:
        conn.close()


def test_console_ml_state_is_served_by_mode_endpoint(env: Env) -> None:
    env.gw.backend.set_ml(False)
    with TestClient(env.gw.api(allowed_origins=["null"])) as c:
        assert c.get("/mode").json()["ml"] is False


async def test_live_clock_stamps_real_time_and_seeded_mandate_is_valid(tmp_path: Path) -> None:
    from fastmcp import Client

    from trishul.crypto.keystore import load_or_create
    from trishul.gateway.app import build_gateway, seed_demo_mandate
    from trishul.store.db import connect, reset

    conn = connect(tmp_path / "live.db")
    now = live_clock()
    ids = reset(conn, seed=42, now=now)
    keys = load_or_create()
    seed_demo_mandate(conn, keys, now=now)
    gw = build_gateway(conn, ids, seed=42, keys=keys, clock=live_clock)
    try:
        async with Client(gw.mcp) as client:
            args = {"payee_vpa": "acme@okaxis", "amount_paise": 100_000}
            gw.bind_task(
                purpose="payment_processing", category="PAYMENT", text="Pay Acme", params=args
            )
            ok = await client.call_tool("upi_pay_upi", args)
            assert ok.structured_content
        ts = [e for e in gw.bus.snapshot() if e["type"] == "call"][-1]["ts"]
        stamp = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        assert abs(stamp - datetime.now(UTC)) < timedelta(minutes=1)
        (m,) = gw.backend.mandates()
        assert m["state"] == "valid" and m["used_today"] == 100_000
    finally:
        conn.close()


async def test_readyz_and_dpdp_flag_a_failing_audit_log(env: Env) -> None:
    env.gw.bind_task(purpose="payment_processing", category="READ", text="balance")
    await env.call("upi_get_balance")
    with TestClient(env.gw.api(allowed_origins=["null"])) as c:
        assert c.get("/readyz").json()["checks"]["audit"] == "ok"
        assert "warning" not in c.get("/report/dpdp").json()
        env.conn.execute("UPDATE audit_leaves SET payload=x'7b7d' WHERE idx=0")
        ready = c.get("/readyz")
        assert ready.status_code == 503 and ready.json()["checks"]["audit"] == "fail"
        report = c.get("/report/dpdp").json()
        assert report["audit_verified"] is False and "FAILED VERIFICATION" in report["warning"]
