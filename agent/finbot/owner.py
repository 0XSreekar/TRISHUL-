# SPDX-License-Identifier: Apache-2.0
"""Owner requests: a typed payment instruction from the account owner (the trusted user channel).

Unlike a red-team submission (text the agent *reads*, labelled UNTRUSTED), the owner's sentence is
bound as the task itself, so the payee and amount carry TRUSTED_USER labels. The gateway still
decides on its own: ALLOW inside the signed mandate, STEP_UP over a cap, DENY for a payee the
mandate does not cover. Nothing here approves anything.
"""

import re
from typing import Any

from agent.finbot.agent import _AMOUNT, FinBot, parse_intent

MAX_CHARS = 500
_STATE = "owner_last"  # key in backend.demo_state: re-sending the same request reuses its task


def _has_amount(text: str) -> bool:
    return any(p.search(text) for p in _AMOUNT)


_CUSTOMER = re.compile(r"\bC-\d{3,6}\b", re.I)
_LOOKUP = re.compile(
    r"\b(show|look ?up|check|get|fetch|read|view|find|open|status|details?)\b", re.I
)
# the purpose comes from the user's own words; the consent registry decides whether it is allowed
_PURPOSES = (
    (re.compile(r"\b(marketing|promotion|promo|offers?|advert)", re.I), "marketing"),
    (re.compile(r"\b(reminder|remind)", re.I), "payment_reminders"),
)


def _purpose_of(text: str) -> str:
    return next((p for rx, p in _PURPOSES if rx.search(text)), "order_support")


async def _data_lookup(bot: FinBot, text: str, customer_id: str) -> dict[str, Any]:
    """PurposeLock: read one customer's record for the purpose the user stated. Allowed only when
    that customer's active consent covers the purpose; the gateway also minimises the fields."""
    purpose = _purpose_of(text)
    args = {"customer_id": customer_id, "fields": ["name", "order_status"]}
    task_id, pin = bot._bind(
        purpose=purpose, category="READ", text=text, params=args, pinnable=True
    )
    res = await bot.call("crm_read_customer_data", args, task_id=task_id, task_pin=pin)
    raw = res.get("body")
    body: dict[str, Any] = raw if isinstance(raw, dict) else {}
    shown = {k: v for k, v in body.items() if k in ("customer_id", "name", "order_status", "city")}
    return {
        "decision": res.get("decision"),
        "rules": res.get("rules", []),
        "kind": "data",
        "customer_id": customer_id,
        "purpose": purpose,
        "shown": shown if res.get("ok") else {},
        "event_ids": res.get("event_ids", []),
    }


async def owner_request(backend: Any, bot: FinBot, text: str) -> dict[str, Any]:
    intent = parse_intent(text)
    customer = _CUSTOMER.search(text)
    if intent.kind not in ("pay", "export", "email") and customer and _LOOKUP.search(text):
        return await _data_lookup(bot, text, customer.group(0).upper())
    if intent.kind != "pay" or not _has_amount(text):
        return {
            "decision": "NO_ACTION",
            "rules": [],
            "note": "Try: Pay Rs 2000 to acme@okaxis  or  Show order status for customer C-1042",
        }
    args = {"payee_vpa": intent.args["payee_vpa"], "amount_paise": intent.args["amount_paise"]}
    st = getattr(backend, "demo_state", None)
    if not isinstance(st, dict):
        st = {}
        backend.demo_state = st
    last = st.get(_STATE)
    if not (isinstance(last, dict) and last.get("args") == args):
        # same request again (e.g. after an approval) keeps its task; anything else binds anew
        task_id, pin = bot._bind(
            purpose="payment_processing", category="PAYMENT", text=text, params=args, pinnable=True
        )
        last = {"args": args, "task_id": task_id, "pin": pin}
        st[_STATE] = last
    res = await bot.call("upi_pay_upi", args, task_id=last["task_id"], task_pin=last["pin"])
    return {
        "decision": res.get("decision"),
        "rules": res.get("rules", []),
        "payee_vpa": args["payee_vpa"],
        "amount_paise": args["amount_paise"],
        "approval_id": res.get("approval_id"),
        "event_ids": res.get("event_ids", []),
    }
