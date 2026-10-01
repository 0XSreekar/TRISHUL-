"""Phase 3 acceptance tests AT-11 (OFF mode), AT-12 (ML off), AT-15 (audit tamper + proofs)."""

import json
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from tests.integration.test_gateway_harness import Env, make_env_sync
from trishul.audit import merkle
from trishul.cli.main import main
from trishul.domains.voice_adapters import ScriptedASR, SpoofResult
from trishul.domains.voicetrust import NonceService, VoiceTrust
from trishul.finbot.agent import parse_intent
from trishul.redteam.service import load_queue

ATTACKER = "refund.desk@ybl"


class _LowSpoof:
    def available(self) -> bool:
        return True

    def score(self, samples: object) -> SpoofResult:
        return SpoofResult(0.01, True, "fixed-test-double")


def dbpath(env: Env) -> str:
    return next(r[2] for r in env.conn.execute("PRAGMA database_list") if r[1] == "main")


def audit_events(env: Env) -> list[dict[str, Any]]:
    rows = env.conn.execute("SELECT payload FROM audit_leaves ORDER BY idx").fetchall()
    return [json.loads(bytes(r["payload"])) for r in rows]


def protected_snapshot(env: Env) -> tuple[int, int, int, int]:
    q = env.conn.execute
    return (
        q("SELECT COUNT(*) FROM ledger").fetchone()[0],
        q("SELECT balance_paise FROM accounts").fetchone()[0],
        q("SELECT COUNT(*) FROM outbox").fetchone()[0],
        q("SELECT COUNT(*) FROM payees").fetchone()[0],
    )


# --- AT-11 -------------------------------------------------------------------------------------
@pytest.mark.acceptance("S-OFF")
async def test_at11_off_mode_executes_only_in_demo_off_and_is_audited(env: Env) -> None:
    before = protected_snapshot(env)
    info = env.gw.backend.set_mode("off")
    assert info == {
        "mode": "off",
        "namespace": "demo_off",
        "disabled": ["taint", "policy", "mandate", "approval", "ml"],
    }
    # no task bound, attacker payee: unguarded, exactly what OFF means
    out = await env.call("upi_pay_upi", {"payee_vpa": ATTACKER, "amount_paise": 450_000})
    assert out["namespace"] == "demo_off" and out["balance_after"] == 5_000_000 - 450_000
    assert protected_snapshot(env) == before  # protected ledger, balance, payees, outbox untouched
    row = env.conn.execute("SELECT * FROM ns_ledger").fetchone()
    assert row["namespace"] == "demo_off" and row["payee_vpa"] == ATTACKER
    assert row["amount_paise"] == 450_000
    ev = env.call_events()[-1]
    assert ev["mode"] == "off" and ev["decision"] == "UNGUARDED" and ev["namespace"] == "demo_off"
    assert ev["audit_hash"] and ev["tree_head"]["size"] >= 1
    mine = [e for e in audit_events(env) if e.get("call_id") == ev["id"]]
    assert {e["type"] for e in mine} == {"decision", "execution"}
    assert all(e["mode"] == "off" and e["namespace"] == "demo_off" for e in mine)
    assert any(e.get("type") == "mode" and e["mode"] == "off" for e in audit_events(env))
    assert any(e["type"] == "mode" and e["mode"] == "off" for e in env.events)
    # a second OFF call cannot overdraw the isolated namespace either
    body = await env.client.call_tool(
        "upi_pay_upi", {"payee_vpa": ATTACKER, "amount_paise": 9_000_000}, raise_on_error=False
    )
    assert body.is_error and protected_snapshot(env) == before
    # ON again: the very same call is refused and nothing executes
    env.gw.backend.set_mode("on")
    denied = await env.denied("upi_pay_upi", {"payee_vpa": ATTACKER, "amount_paise": 450_000})
    assert denied["decision"] == "DENY" and protected_snapshot(env) == before
    assert env.call_events()[-1].get("mode") != "off"


@pytest.mark.acceptance("S-OFF")
async def test_at11_off_audit_failure_refuses_the_call(env: Env) -> None:
    env.gw.backend.set_mode("off")

    def boom(_event: Any) -> Any:
        raise RuntimeError("audit down")

    env.gw.pipeline.audit.append = boom  # type: ignore[method-assign]
    res = await env.client.call_tool(
        "upi_pay_upi", {"payee_vpa": ATTACKER, "amount_paise": 100}, raise_on_error=False
    )
    assert res.is_error  # never a silent success when the audit cannot record it


async def test_mode_default_on_and_reset_restores_on(env: Env) -> None:
    assert env.gw.backend.mode()["mode"] == "on"
    env.gw.backend.set_mode("off")
    out = env.gw.backend.demo_reset(42)
    assert out["mode"] == "on" and env.gw.backend.mode()["mode"] == "on"
    assert env.conn.execute("SELECT COUNT(*) FROM ns_ledger").fetchone()[0] == 0


# --- AT-12 -------------------------------------------------------------------------------------
@pytest.mark.acceptance(5)
async def test_at12_ml_off_top_attacks_still_denied(env: Env) -> None:
    before = protected_snapshot(env)
    env.gw.backend.set_ml(False)
    assert env.gw.pipeline.ml_enabled() is False
    done = await env.gw.backend.redteam.fallback(5, 0)
    assert [r["decision"] for r in done] == ["DENY"] * 5
    assert not any(r["succeeded"] for r in done)
    assert protected_snapshot(env) == before
    assert any(e.get("ml") == "off" for e in env.call_events())
    assert any(e["type"] == "ml_state" and e["enabled"] is False for e in env.events)


async def test_fallback_queue_is_20_deterministic_items_and_never_succeeds(env: Env) -> None:
    queue = load_queue()
    assert len(queue) == 20 and len({i["id"] for i in queue}) == 20
    before = protected_snapshot(env)
    done = await env.gw.backend.redteam.fallback()
    assert len(done) == 20 and all(r["source"] == "fallback_queue" for r in done)
    assert not any(r["succeeded"] for r in done) and protected_snapshot(env) == before
    assert {r["decision"] for r in done} <= {"DENY", "STEP_UP", "NO_ACTION"}
    stats = env.gw.backend.redteam_stats()
    assert stats == {"attempted": 20, "succeeded": 0, "killed": False}
    # every queue item that asks for an action was parsed into a real tool attempt
    assert sum(parse_intent(i["text"]).tool is not None for i in queue) >= 15


async def test_redteam_refused_when_mode_off(env: Env) -> None:
    from trishul.redteam.errors import RedTeamError

    env.gw.backend.set_mode("off")
    try:
        await env.gw.backend.redteam.fallback(1)
    except RedTeamError as exc:
        assert exc.code == "mode_off"
    else:  # pragma: no cover
        raise AssertionError("red team must not run against the unguarded namespace")


# --- AT-15 -------------------------------------------------------------------------------------
@pytest.mark.acceptance(16)
async def test_at15_cli_tamper_reports_exact_bad_index_and_proofs_verify(
    env: Env, capsys: Any
) -> None:
    env.gw.bind_task(purpose="payment_processing", category="READ", text="balance")
    for _ in range(5):
        await env.call("upi_get_balance")
    size = env.gw.pipeline.audit.size()
    assert size >= 8
    with TestClient(env.gw.api(allowed_origins=["null"])) as c:
        head = c.get("/audit/head").json()
        assert head["size"] == size and len(head["root"]) == 64
        old = size - 3
        for idx in (0, size // 2, size - 1):
            proof = c.get("/audit/proof/inclusion", params={"idx": idx}).json()
            assert proof["verified"] is True and proof["payload_intact"] is True
            assert merkle.verify_inclusion(  # independent client-side check
                merkle.unhex(proof["leaf_hash"]),
                idx,
                proof["tree_size"],
                [merkle.unhex(p) for p in proof["path"]],
                merkle.unhex(head["root"]),
            )
        cons = c.get("/audit/proof/consistency", params={"old": old}).json()
        assert cons["verified"] is True and cons["first"] == old and cons["second"] == size
        assert merkle.verify_consistency(
            old,
            size,
            merkle.unhex(cons["first_root"]),
            merkle.unhex(cons["second_root"]),
            [merkle.unhex(p) for p in cons["path"]],
        )
        leaves = c.get("/audit/leaves", params={"from": 2, "limit": 3}).json()
        assert [x["idx"] for x in leaves["leaves"]] == [2, 3, 4]
        assert c.get("/audit/proof/inclusion", params={"idx": size}).status_code == 404
        assert c.get("/audit/proof/consistency", params={"old": 0}).status_code == 400
        assert c.get("/audit/leaves", params={"from": "x"}).status_code == 400
        assert c.get("/audit/verify").json()["ok"] is True

        target = 4
        assert main(["demo", "tamper", "--idx", str(target), "--db", dbpath(env)]) == 0
        capsys.readouterr()
        assert main(["verify", "--db", dbpath(env)]) == 1
        out = json.loads(capsys.readouterr().out)
        assert out["ok"] is False and out["bad_index"] == target
        rest = c.get("/audit/verify").json()
        assert rest["ok"] is False and rest["bad_index"] == target
        assert rest["tree_head"]["size"] == size
        after = c.get("/audit/proof/inclusion", params={"idx": target}).json()
        assert after["payload_intact"] is False  # the explorer shows the leaf as tampered
        assert (
            c.get("/audit/leaves", params={"from": target, "limit": 1}).json()["leaves"][0][
                "intact"
            ]
            is False
        )
    assert main(["demo", "tamper", "--idx", "9999", "--db", dbpath(env)]) == 1


async def test_demo_reset_via_rest_restores_clean_state(env: Env) -> None:
    env.gw.bind_task(purpose="payment_processing", category="READ", text="balance")
    await env.call("upi_get_balance")
    assert env.gw.pipeline.audit.size() > 0
    with TestClient(env.gw.api(allowed_origins=["null"])) as c:
        assert c.post("/demo/reset", json={"seed": 7}).status_code == 400  # seed is fixed
        out = c.post("/demo/reset", json={"seed": 42}).json()
    assert out["reset"] is True and out["mode"] == "on"
    assert env.gw.pipeline.audit.size() == 1  # only the reset operator_action record
    assert env.gw.pipeline.ml_enabled() is True
    assert any(e["type"] == "demo" and e["step"] == "reset" for e in env.events)
    # the reseeded ids restart deterministically
    env.gw.bind_task(purpose="payment_processing", category="READ", text="balance")
    await env.call("upi_get_balance")
    assert env.call_events()[-1]["id"].startswith("call_")


# --- demo moments ------------------------------------------------------------------------------
async def test_moment_1_off_pays_hidden_vpa_into_demo_off_only(env: Env) -> None:
    before = protected_snapshot(env)
    out = await env.gw.backend.demo_moment(1)
    step = out["steps"][0]
    assert step["status"] == "ok" and step["payee"] == "refund.desk@ybl"
    assert step["effect"]["namespace"] == "demo_off" and step["decision"] == "UNGUARDED"
    assert protected_snapshot(env) == before
    assert env.conn.execute("SELECT COUNT(*) FROM ns_ledger").fetchone()[0] == 1


async def test_moment_3_after_moment_1_forces_on_and_never_runs_unguarded(env: Env) -> None:
    await env.gw.backend.demo_moment(1)  # leaves the gateway OFF; presenter skips moment 2
    out = await env.gw.backend.demo_moment(3)
    assert out["mode_forced_on"]["mode"] == "on"
    by = {s["name"]: s for s in out["steps"]}
    assert all(s.get("decision") != "UNGUARDED" for s in out["steps"])
    assert by["injected_invoice"]["decision"] == "DENY"
    assert by["approve_then_change_amount"]["decision"] == "DENY"


async def test_moment_3_scripted_flow(env: Env) -> None:
    out = await env.gw.backend.demo_moment(3)
    by = {s["name"]: s for s in out["steps"]}
    assert by["injected_invoice"]["decision"] == "DENY"
    assert by["normal_bill"]["decision"] == "ALLOW"
    assert by["over_cap_step_up"]["decision"] == "STEP_UP"
    assert by["retry_after_approval"]["decision"] == "ALLOW"
    assert by["approve_then_change_amount"]["decision"] == "DENY"
    assert "PAYSHIELD.APPROVAL.BINDING_MISMATCH" in by["approve_then_change_amount"]["rules"]
    assert out["event_ids"] and env.conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0] == 2


async def test_moment_5_ml_off_and_proofs(env: Env) -> None:
    digest = env.gw.pipeline.policy.digest
    out = await env.gw.backend.demo_moment(5)
    by = {s["name"]: s for s in out["steps"]}
    assert [r["decision"] for r in by["ml_off_top5"]["results"]] == ["DENY"] * 5
    assert by["prove_live"]["result"] == "UNSAT"
    assert by["prove_unsafe_fixture"]["result"] == "SAT"
    assert by["prove_unsafe_fixture"]["replay"]["decision_under_live"] == "DENY"
    assert env.gw.pipeline.policy.digest == digest and env.gw.pipeline.ml_enabled() is True
    assert {"proof", "demo", "ml_state"} <= {e["type"] for e in env.events}


class _HearsLatestNonce(ScriptedASR):
    """Test double: the speaker genuinely says the most recently issued challenge phrase."""

    def __init__(self, nonces: NonceService) -> None:
        super().__init__(None)
        self._nonces = nonces
        self.phrase = ""

    def transcribe(self, samples: Any) -> Any:
        live = [n for b in self._nonces._live.values() for n in b.values()]
        if live:
            self.phrase = live[-1].phrase
        self._text = f"please {self.phrase} thanks"
        return super().transcribe(samples)


async def test_moment_6_voice_replay_and_verify(tmp_path: Path) -> None:
    nonces = NonceService()
    vt = VoiceTrust(nonces, _HearsLatestNonce(nonces), _LowSpoof())
    gw, conn, *_ = make_env_sync(tmp_path, voice=vt)
    try:
        out = await gw.backend.demo_moment(6)
        by = {s["name"]: s for s in out["steps"]}
        # the genuine clip raised an approval, the operator approved, the call ran and consumed it
        assert by["spoof_clip"]["auto_approved"] is True
        assert by["spoof_clip"]["after_approval"]["decision"] == "ALLOW"
        # replaying the recording after that consumption is a flat DENY (nonce spent)
        assert by["replayed_nonce"]["decision"] == "DENY"
        assert "VOICETRUST.LIVENESS.MISMATCH" in by["replayed_nonce"]["rules"]
        assert not by["replayed_nonce"]["approval_id"]
        assert by["audit_and_report"]["verify"]["ok"] is True
    finally:
        conn.close()


# --- REST surface smoke ------------------------------------------------------------------------
async def test_health_mode_mandates_and_dpdp_endpoints(env: Env) -> None:
    with TestClient(env.gw.api(allowed_origins=["null"])) as c:
        assert c.get("/healthz").json() == {"ok": True}
        ready = c.get("/readyz")
        body = ready.json()
        assert ready.status_code == 200 and body["ready"] is True
        assert {"db", "policy", "audit", "voice_models", "ollama"} == set(body["checks"])
        assert body["checks"]["voice_models"] in {"available", "unavailable"}
        assert c.get("/mode").json() == {"mode": "on", "namespace": "protected", "disabled": []}
        assert c.post("/mode", json={"mode": "maybe"}).status_code == 400
        assert c.post("/mode", json={"mode": "off"}).json()["namespace"] == "demo_off"
        assert c.post("/mode", json={"mode": "on"}).json()["mode"] == "on"
        m = c.get("/mandates").json()["mandates"]
        assert len(m) == 1 and m[0]["state"] == "valid"
        assert m[0]["per_txn_cap"] == 500_000 and m[0]["daily_cap"] == 1_000_000
        assert m[0]["used_today"] == 0 and m[0]["uses"] == 0
        r = c.get("/report/dpdp")
        assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
        assert r.json()["report"] == "dpdp"
        assert c.post("/demo/moment/9", json={}).status_code == 400
        assert c.post("/demo/moment/3", json={"step": "x"}).status_code == 400


def test_unreadable_mode_state_fails_closed_to_on(env: Env) -> None:
    env.gw.backend.set_mode("off")
    env.conn.execute("ALTER TABLE meta RENAME TO meta_gone")
    assert env.gw.pipeline.mode() == "on"
    env.conn.execute("ALTER TABLE meta_gone RENAME TO meta")


async def test_latency_ms_is_decision_latency_and_off_has_none(env: Env) -> None:
    await env.gw.backend.demo_moment(1)
    await env.gw.backend.demo_moment(3)
    calls = [e for e in env.gw.bus.snapshot() if e.get("type") == "call"]
    off = [e for e in calls if e.get("mode") == "off"]
    on = [e for e in calls if e.get("mode") != "off"]
    assert off and all(e["latency_ms"] is None for e in off)  # OFF makes no decision
    assert on
    for e in on:
        lat, total = e["latency_ms"], e["total_ms"]
        assert isinstance(lat, float) and isinstance(total, float)
        assert 0 <= lat <= total  # decision time excludes upstream tool execution


def test_console_static_is_revalidated_every_load(env: Env) -> None:
    with TestClient(env.gw.api(allowed_origins=["null"])) as c:
        r = c.get("/console/Trishul-Console.dc.html")
        assert r.status_code == 200 and r.headers["cache-control"] == "no-cache"


def test_bench_results_reachable_from_console_relative_link(env: Env) -> None:
    with TestClient(env.gw.api(allowed_origins=["null"])) as c:
        a, b = c.get("/bench/results.json"), c.get("/console/bench/results.json")
        assert a.status_code == b.status_code and a.content == b.content
