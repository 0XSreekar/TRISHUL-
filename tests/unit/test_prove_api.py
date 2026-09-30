"""AT-13: POST /prove. The unsafe fixture yields a SAT counterexample; the live policy is never
swapped (digest equal before/after) and still denies afterwards."""

from pathlib import Path

from starlette.testclient import TestClient

from tests.integration.test_gateway_harness import make_env_sync
from trishul.policy.compiler import compile_files
from trishul.verify.showcase import UNSAFE_DIR


def test_unsafe_fixture_is_compiled_separately_from_live() -> None:
    assert (
        Path(__file__).resolve().parents[2] / "trishul" / "fixtures" / "unsafe_policy" == UNSAFE_DIR
    )
    live = compile_files([Path(__file__).resolve().parents[2] / "policies"])
    assert compile_files([UNSAFE_DIR]).digest != live.digest


def test_at13_unsafe_fixture_sat_with_counterexample_and_live_untouched(tmp_path: Path) -> None:
    gw, *_ = make_env_sync(tmp_path)
    live_before = gw.pipeline.policy.digest
    live_obj = gw.pipeline.policy
    with TestClient(gw.api(allowed_origins=["null"])) as c:
        r = c.post("/prove", json={"policy": "unsafe_fixture"})
        assert r.status_code == 200
        body = r.json()
        assert body["solver"] == "z3" and body["result"] == "SAT"
        assert body["policy_digest"] != live_before
        assert body["live_policy_digest"] == live_before
        sat = [row for row in body["per_invariant"] if row["result"] == "SAT"]
        assert sat and all(isinstance(row["counterexample"], dict) for row in sat)
        assert {"I1"} <= {row["id"] for row in sat}
        assert all(
            isinstance(row["solve_ms"], (int, float)) and row["solve_ms"] >= 0
            for row in body["per_invariant"]
        )
        replay = body["replay"]
        assert replay["decision_under_unsafe"] == "ALLOW"
        assert replay["decision_under_live"] == "DENY"
        assert replay["call"]["tool"] == "pay_upi"

        live = c.post("/prove", json={"policy": "live"}).json()
        assert live["result"] == "UNSAT" and live["policy_digest"] == live_before
        assert live["replay"] is None
        assert all(row["counterexample"] is None for row in live["per_invariant"])
        assert c.post("/prove").json()["policy"] == "live"  # bodyless console POST = live
        assert c.post("/prove", json={"policy": "../../etc"}).status_code == 400
        assert c.post("/prove", json={"policy": 5}).status_code == 400
    assert gw.pipeline.policy is live_obj and gw.pipeline.policy.digest == live_before
    proofs = [e for e in gw.bus.snapshot(0) if e["type"] == "proof"]
    assert [p["policy"] for p in proofs][:2] == ["unsafe_fixture", "live"]
    assert proofs[0]["result"] == "SAT" and proofs[0]["per_invariant"]


async def test_live_policy_still_denies_after_unsafe_proof(tmp_path: Path) -> None:
    from fastmcp import Client

    gw, conn, *_ = make_env_sync(tmp_path)
    gw.backend.prove("unsafe_fixture")
    gw.bind_task(purpose="payment_processing", category="PAYMENT", text="Pay")
    async with Client(gw.mcp) as client:
        res = await client.call_tool(
            "upi_pay_upi",
            {"payee_vpa": "refund.desk@ybl", "amount_paise": 1},
            raise_on_error=False,
        )
    assert res.is_error
    assert conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0] == 0
