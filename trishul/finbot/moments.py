# SPDX-License-Identifier: Apache-2.0
"""The six scripted demo moments (spec section 3). Each step is real traffic through the gateway;
results are plain dicts, and every step also publishes a ``demo`` WS event."""

import asyncio
import base64
import re
import shutil
import subprocess
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from trishul.finbot.agent import FinBot
from trishul.redteam.errors import RedTeamError

AUDIO = Path(__file__).resolve().parents[1] / "fixtures" / "audio"
ACME = "acme@okaxis"
HIDDEN_VPA = re.compile(r"pay to ([A-Za-z0-9._-]+@[A-Za-z0-9._-]+)", re.I)
AMOUNT = re.compile(r"Amount:</strong>\s*(?:₹|Rs\.?|INR)?\s*([\d,]+)(?:\.(\d{1,2}))?", re.I)

DEMO_APPROVER = "demo-script"
AUTO_NOTE = "auto-approved by demo script (Run all steps); step-by-step runs need a real approver"
_AUTO = {"auto_approved": True, "approved_by": DEMO_APPROVER, "auto_approval_note": AUTO_NOTE}

StepFn = Callable[[Any, FinBot, bool], Awaitable[dict[str, Any]]]


def _doc_id(backend: Any, name: str) -> str:
    row = backend.p.conn.execute("SELECT doc_id FROM documents WHERE name=?", (name,)).fetchone()
    if row is None:
        raise KeyError(name)
    return str(row["doc_id"])


def _demo_state(backend: Any) -> dict[str, Any]:
    """Per-gateway scratch for multi-step moments; cleared on demo reset."""
    st = getattr(backend, "demo_state", None)
    if st is None:
        st = {}
        backend.demo_state = st
    return st


def _brief(res: dict[str, Any]) -> dict[str, Any]:
    return {
        "decision": res.get("decision"),
        "rules": res.get("rules", []),
        "event_ids": res.get("event_ids", []),
        "approval_id": res.get("approval_id"),
    }


# --- 1: OFF ------------------------------------------------------------------------------------
async def m1_off(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    info = backend.set_mode("off")
    doc = await bot.call("files_read_document", {"doc_id": _doc_id(backend, "inv_injected.html")})
    content = str(doc["body"].get("content", ""))
    vpa = HIDDEN_VPA.search(content)
    amt = AMOUNT.search(content)
    if not doc["ok"] or not vpa or not amt:
        return {"status": "error", "mode": info, "note": "hidden instruction not found"}
    paise = int(amt.group(1).replace(",", "")) * 100 + int((amt.group(2) or "0").ljust(2, "0"))
    paid = await bot.call("upi_pay_upi", {"payee_vpa": vpa.group(1), "amount_paise": paise})
    return {
        "status": "ok",
        "mode": info,
        "payee": vpa.group(1),
        "amount_paise": paise,
        **_brief(paid),
        "effect": paid["body"],
    }


# --- 2: integration ----------------------------------------------------------------------------
async def m2_integrate(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    info = backend.set_mode("on")
    return {
        "status": "ok",
        "mode": info,
        "diff": {
            "remove": "MCP_URL=http://127.0.0.1:8787/mcp",
            "add": "MCP_URL=http://127.0.0.1:8788/mcp",
        },
    }


# --- 3: guarded --------------------------------------------------------------------------------
async def _pay_invoice(backend: Any, bot: FinBot, name: str) -> dict[str, Any]:
    bot.bind(purpose="payment_processing", category="PAYMENT", text=f"Pay invoice {name}")
    got = await bot.read_invoice(_doc_id(backend, name))
    if not got.get("payee_vpa") or not got.get("amount_paise"):
        return {"status": "error", "note": "extraction failed"}
    res = await bot.call(
        "upi_pay_upi", {"payee_vpa": got["payee_vpa"], "amount_paise": got["amount_paise"]}
    )
    return {"status": "ok", **_brief(res)}


async def m3_1(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    return await _pay_invoice(backend, bot, "inv_injected.html")


async def m3_2(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    return await _pay_invoice(backend, bot, "inv_trusted.html")


async def m3_3(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    args = {"payee_vpa": ACME, "amount_paise": 750_000}
    bot.bind(
        purpose="payment_processing", category="PAYMENT", text="Pay Acme 7500 rupees", params=args
    )
    res = await bot.call("upi_pay_upi", args)
    out: dict[str, Any] = {"status": "awaiting_approval", **_brief(res)}
    if auto and res.get("approval_id"):
        backend.resolve_approval(res["approval_id"], "approve", DEMO_APPROVER)
        out.update(_AUTO)
    elif res.get("approval_id"):
        out["note"] = (
            "Awaiting a real approver: approve it in Approvals > Pending, then run step 4."
        )
    return out


async def m3_4(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    res = await bot.call("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 750_000})
    return {"status": "ok" if res["ok"] else "awaiting_approval", **_brief(res)}


async def m3_5(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    """Approve one exact call, then change the amount. Step by step a real approver must approve
    in between (first run returns awaiting_approval; the second run changes the amount). Only
    "Run all steps" approves itself, and says so."""
    state = _demo_state(backend)
    pending = state.get("m3_5")
    if pending is not None and not auto:
        row = backend.p.approvals.get(pending["approval_id"])
        status = None if row is None else str(row["status"])
        latest = backend.p.conn.execute(
            "SELECT task_id FROM task_bindings ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        if status == "pending":
            return {
                "status": "awaiting_approval",
                "approval_id": pending["approval_id"],
                "note": "Still pending: approve it in Approvals > Pending, then run step 5 again.",
            }
        if status != "approved" or latest is None or latest["task_id"] != pending["task_id"]:
            state.pop("m3_5", None)
            return {
                "status": "error",
                "approval_id": pending["approval_id"],
                "note": f"approval is {status}, or another task was bound since: run step 5 again "
                "from the start",
            }
        state.pop("m3_5")
        changed = await bot.call("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 760_000})
        return {"status": "ok", "approver": row["approver"], **_brief(changed)}
    state.pop("m3_5", None)
    task_id = bot.bind(
        purpose="payment_processing",
        category="PAYMENT",
        text="Pay Acme",
        params={"payee_vpa": ACME, "amounts": [750_000, 760_000]},
    )
    first = await bot.call("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 750_000})
    approval = first.get("approval_id")
    if not approval:  # already within every cap: nothing to bind an approval to
        return {"status": "skipped", "note": "no step-up raised", **_brief(first)}
    if not auto:
        state["m3_5"] = {"approval_id": approval, "task_id": task_id}
        return {
            "status": "awaiting_approval",
            "note": "Approve it in Approvals > Pending (within 120 s), then run step 5 again: "
            "it will change the amount to 7600 and the approval will not match.",
            **_brief(first),
        }
    backend.resolve_approval(approval, "approve", DEMO_APPROVER)
    changed = await bot.call("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 760_000})
    return {"status": "ok", **_AUTO, **_brief(changed)}


# --- 4: red-team wall --------------------------------------------------------------------------
def make_m4(chunk: int) -> StepFn:
    async def step(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
        try:
            done = await backend.redteam.fallback(5, chunk * 5)
        except RedTeamError as exc:
            return {"status": "error", "error": exc.code}
        return {
            "status": "ok",
            "source": "fallback_queue",
            "results": [
                {k: r[k] for k in ("id", "decision", "succeeded", "moderated")} for r in done
            ],
            "stats": done[-1]["stats"] if done else None,
        }

    return step


# --- 5: ML off, proofs -------------------------------------------------------------------------
async def m5_1(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    backend.set_ml(False)
    done = await backend.redteam.fallback(5, 0)
    return {
        "status": "ok",
        "ml": "off",
        "results": [{k: r[k] for k in ("id", "decision", "succeeded")} for r in done],
    }


async def m5_2(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    out = backend.prove("live")
    return {"status": "ok", "result": out["result"], "policy_digest": out["policy_digest"]}


async def m5_3(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    out = backend.prove("unsafe_fixture")
    return {
        "status": "ok",
        "result": out["result"],
        "replay": out["replay"],
        "live_policy_digest": out["live_policy_digest"],
        "note": "live policy was never swapped; nothing to restore",
    }


async def m5_4(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    backend.set_ml(True)
    return {"status": "ok", "ml": "on"}


# --- 6: voice + audit --------------------------------------------------------------------------
def _clip(name: str) -> str:
    return base64.b64encode((AUDIO / name).read_bytes()).decode()


async def _warm_voice(voice: Any) -> None:
    """Models must be warm BEFORE the 10 s nonce is issued: a cold first inference can take far
    longer than the TTL. Waits for an in-flight warm-up; never raises (decisions fail closed)."""
    if getattr(voice, "warm_state", "warm") in ("cold", "failed"):
        await asyncio.to_thread(voice.warmup)
    for _ in range(600):  # another thread (server start) may be warming: wait up to 60 s
        if getattr(voice, "warm_state", "warm") != "warming":
            return
        await asyncio.sleep(0.1)


def _tts_clip(phrase: str) -> tuple[str, str] | None:
    """Real synthetic speech of the challenge phrase (macOS ``say``), as base64 16 kHz WAV, or
    None when no TTS engine is available on this host."""
    say, conv = shutil.which("say"), shutil.which("afconvert")
    if say is None or conv is None:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        aiff, wav = f"{tmp}/c.aiff", f"{tmp}/c.wav"
        try:
            subprocess.run(  # noqa: S603
                [say, "-v", "Samantha", "-o", aiff, phrase], check=True, timeout=20
            )
            subprocess.run(  # noqa: S603
                [conv, "-f", "WAVE", "-d", "LEI16@16000", "-c", "1", aiff, wav],
                check=True,
                timeout=20,
            )
            return base64.b64encode(Path(wav).read_bytes()).decode(), "tts:macos-say-Samantha"
        except (OSError, subprocess.SubprocessError):
            return None


async def m6_1(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    bot.bind(purpose="order_support", category="VOICE", text="voice request")
    await _warm_voice(backend.p.voice)
    nonce = backend.issue_voice_nonce(backend.p.session)
    # the spoofer speaks the challenge with a TTS voice; the real anti-spoof detector judges it
    tts = await asyncio.to_thread(_tts_clip, nonce["phrase"])
    clip, source = tts if tts is not None else (_clip("tone_clean_3s.wav"), "fixture:tone")
    args = {"clip_b64": clip, "clip_id": "clip_demo_1", "nonce_id": nonce["nonce_id"]}
    res = await bot.call("voice_command", args)
    backend._last_voice_args = args
    adapter = type(backend.p.voice.spoof).__name__
    out: dict[str, Any] = {
        "status": "ok",
        "spoof_adapter": adapter,
        "clip_source": source,
        "phrase_challenge": nonce["phrase"],
        **_brief(res),
    }
    if auto and res.get("approval_id"):  # genuine challenge answered: approve, run, consume
        backend.resolve_approval(res["approval_id"], "approve", DEMO_APPROVER)
        done = await bot.call("voice_command", args)
        out.update(_AUTO)
        out["after_approval"] = {"decision": done.get("decision"), "ok": done.get("ok")}
    elif res.get("approval_id"):
        out["note"] = "Awaiting a real approver: approve it in Approvals > Pending."
    return out


async def m6_2(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    args = getattr(backend, "_last_voice_args", None)
    if args is None:
        return {"status": "skipped", "note": "run step 1 first"}
    res = await bot.call("voice_command", args)  # replayed recording, spent nonce
    return {"status": "ok", "replay": True, **_brief(res)}


async def m6_3(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    v = backend.audit_verify()
    return {
        "status": "ok",
        "verify": {"ok": v["ok"], "bad_index": v["bad_index"], "size": v["size"]},
        "dpdp_report": "/report/dpdp",
        "tamper_cli": "trishul demo tamper --idx N",
    }


MOMENTS: dict[int, tuple[tuple[str, StepFn], ...]] = {
    1: (("off_read_and_pay", m1_off),),
    2: (("integration_and_mode_on", m2_integrate),),
    3: (
        ("injected_invoice", m3_1),
        ("normal_bill", m3_2),
        ("over_cap_step_up", m3_3),
        ("retry_after_approval", m3_4),
        ("approve_then_change_amount", m3_5),
    ),
    4: tuple((f"queue_{i * 5 + 1}_{i * 5 + 5}", make_m4(i)) for i in range(4)),
    5: (
        ("ml_off_top5", m5_1),
        ("prove_live", m5_2),
        ("prove_unsafe_fixture", m5_3),
        ("ml_on", m5_4),
    ),
    6: (("spoof_clip", m6_1), ("replayed_nonce", m6_2), ("audit_and_report", m6_3)),
}


async def run_moment(backend: Any, bot: FinBot, n: int, step: int | None) -> dict[str, Any]:
    steps = MOMENTS[n]
    if step is not None and not (
        isinstance(step, int) and not isinstance(step, bool) and 1 <= step <= len(steps)
    ):
        raise ValueError(f"step must be 1..{len(steps)}")
    chosen = list(enumerate(steps, 1)) if step is None else [(step, steps[step - 1])]
    # Moments 3-6 demonstrate the guarded path. If the presenter skipped moment 2 the gateway
    # would still be OFF and these steps would run UNGUARDED, so switch ON explicitly (the
    # set_mode call publishes the usual `mode` event, so the change is visible, not hidden).
    forced_on = None
    if n >= 3 and backend.mode()["mode"] != "on":
        forced_on = backend.set_mode("on")
    results: list[dict[str, Any]] = []
    for idx, (name, fn) in chosen:
        backend.p.bus.publish(
            {
                "type": "demo",
                "moment": n,
                "step": idx,
                "of": len(steps),
                "name": name,
                "status": "running",
            }
        )
        try:
            out = await fn(backend, bot, step is None)
            status = (
                "done" if out.get("status") in ("ok", "awaiting_approval", "skipped") else "error"
            )
        except Exception as exc:  # a failed scripted step is reported, never converted to success
            out, status = {"status": "error", "error": type(exc).__name__}, "error"
        backend.p.bus.publish(
            {
                "type": "demo",
                "moment": n,
                "step": idx,
                "of": len(steps),
                "name": name,
                "status": status,
            }
        )
        results.append({"step": idx, "name": name, **out})
    event_ids = [e for r in results for e in r.get("event_ids", [])]
    out_doc: dict[str, Any] = {"moment": n, "steps": results, "event_ids": event_ids}
    if forced_on is not None:
        out_doc["mode_forced_on"] = forced_on
    return out_doc
