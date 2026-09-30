"""The six scripted demo moments (spec section 3). Each step is real traffic through the gateway;
results are plain dicts, and every step also publishes a ``demo`` WS event."""

import base64
import re
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from trishul.finbot.agent import FinBot
from trishul.redteam.errors import RedTeamError

AUDIO = Path(__file__).resolve().parents[1] / "fixtures" / "audio"
ACME = "acme@okaxis"
HIDDEN_VPA = re.compile(r"pay to ([A-Za-z0-9._-]+@[A-Za-z0-9._-]+)", re.I)
AMOUNT = re.compile(r"Amount:</strong>\s*(?:₹|Rs\.?|INR)?\s*([\d,]+)(?:\.(\d{1,2}))?", re.I)

StepFn = Callable[[Any, FinBot, bool], Awaitable[dict[str, Any]]]


def _doc_id(backend: Any, name: str) -> str:
    row = backend.p.conn.execute("SELECT doc_id FROM documents WHERE name=?", (name,)).fetchone()
    if row is None:
        raise KeyError(name)
    return str(row["doc_id"])


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
        backend.resolve_approval(res["approval_id"], "approve", "console")
        out["auto_approved"] = True
    return out


async def m3_4(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    res = await bot.call("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 750_000})
    return {"status": "ok" if res["ok"] else "awaiting_approval", **_brief(res)}


async def m3_5(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    bot.bind(
        purpose="payment_processing",
        category="PAYMENT",
        text="Pay Acme",
        params={"payee_vpa": ACME, "amounts": [750_000, 760_000]},
    )
    first = await bot.call("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 750_000})
    approval = first.get("approval_id")
    if not approval:  # already within every cap: nothing to bind an approval to
        return {"status": "skipped", "note": "no step-up raised", **_brief(first)}
    backend.resolve_approval(approval, "approve", "console")
    changed = await bot.call("upi_pay_upi", {"payee_vpa": ACME, "amount_paise": 760_000})
    return {"status": "ok", **_brief(changed)}


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


async def m6_1(backend: Any, bot: FinBot, auto: bool) -> dict[str, Any]:
    bot.bind(purpose="order_support", category="VOICE", text="voice request")
    nonce = backend.issue_voice_nonce(backend.p.session)
    args = {
        "clip_b64": _clip("tone_clean_3s.wav"),
        "clip_id": "clip_demo_1",
        "nonce_id": nonce["nonce_id"],
    }
    res = await bot.call("voice_command", args)
    backend._last_voice_args = args
    adapter = type(backend.p.voice.spoof).__name__
    out: dict[str, Any] = {
        "status": "ok",
        "spoof_adapter": adapter,
        "phrase_challenge": nonce["phrase"],
        **_brief(res),
    }
    if auto and res.get("approval_id"):  # genuine challenge answered: approve, run, consume
        backend.resolve_approval(res["approval_id"], "approve", "console")
        done = await bot.call("voice_command", args)
        out["auto_approved"] = True
        out["after_approval"] = {"decision": done.get("decision"), "ok": done.get("ok")}
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
    results: list[dict[str, Any]] = []
    for idx, (name, fn) in chosen:
        backend.p.bus.publish(
            {"type": "demo", "moment": n, "step": idx, "name": name, "status": "running"}
        )
        try:
            out = await fn(backend, bot, step is None)
            status = (
                "done" if out.get("status") in ("ok", "awaiting_approval", "skipped") else "error"
            )
        except Exception as exc:  # a failed scripted step is reported, never converted to success
            out, status = {"status": "error", "error": type(exc).__name__}, "error"
        backend.p.bus.publish(
            {"type": "demo", "moment": n, "step": idx, "name": name, "status": status}
        )
        results.append({"step": idx, "name": name, **out})
    event_ids = [e for r in results for e in r.get("event_ids", [])]
    return {"moment": n, "steps": results, "event_ids": event_ids}
