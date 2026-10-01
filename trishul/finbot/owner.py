# SPDX-License-Identifier: Apache-2.0
"""Owner requests: a typed payment instruction from the account owner (the trusted user channel).

Unlike a red-team submission (text the agent *reads*, labelled UNTRUSTED), the owner's sentence is
bound as the task itself, so the payee and amount carry TRUSTED_USER labels. The gateway still
decides on its own: ALLOW inside the signed mandate, STEP_UP over a cap, DENY for a payee the
mandate does not cover. Nothing here approves anything.
"""

from typing import Any

from trishul.finbot.agent import _AMOUNT, FinBot, parse_intent

MAX_CHARS = 500
_STATE = "owner_last"  # key in backend.demo_state: re-sending the same request reuses its task


def _has_amount(text: str) -> bool:
    return any(p.search(text) for p in _AMOUNT)


async def owner_request(backend: Any, bot: FinBot, text: str) -> dict[str, Any]:
    intent = parse_intent(text)
    if intent.kind != "pay" or not _has_amount(text):
        return {
            "decision": "NO_ACTION",
            "rules": [],
            "note": "Write a payment like: Pay ₹2,000 to acme@okaxis",
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
