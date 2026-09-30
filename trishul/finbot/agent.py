# SPDX-License-Identifier: Apache-2.0
"""Deterministic scripted agent (no LLM anywhere). It speaks real MCP through a ``fastmcp.Client``
(in-memory transport or the gateway URL) and reaches the trusted channel (task binding, approvals,
mode) only through the injected ``control`` object, exactly like the console/CLI would.

Every call returns a plain dict ``{"ok", "decision", "rules", "event_ids", "body"}`` and never
raises for a policy refusal: a refusal is the expected outcome of most demo steps.
"""

import json
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from fastmcp import Client

from trishul.telemetry.events import EventBus


class Control(Protocol):
    """Trusted, out-of-band operations (implemented by ``Backend``)."""

    def bind_task(self, payload: dict[str, Any]) -> dict[str, Any]: ...
    def unpin_task(self, task_id: str) -> None: ...
    def resolve_approval(
        self, approval_id: str, decision: Any, approver: str
    ) -> dict[str, Any]: ...


_TOK = r"[A-Za-z0-9][A-Za-z0-9._-]*"
_ADDR = re.compile(rf"({_TOK})@({_TOK})")
_AMOUNT = (
    re.compile(r"(?:₹|\brs\.?|\binr)\s*([\d][\d,]*)(?:\.(\d{1,2}))?", re.I),
    re.compile(r"\b([\d][\d,]*)(?:\.(\d{1,2}))?\s*(?:rupees|rs\b|inr\b)", re.I),
)
_CUSTOMER = re.compile(r"\bC-\d{3,6}\b")
DEFAULT_AMOUNT_PAISE = 100_000


@dataclass(frozen=True)
class Intent:
    """What a submission asks the naive agent to do (fixed regex parser, no LLM)."""

    kind: str  # pay | add_payee | export | email | none
    tool: str | None
    args: Mapping[str, Any]
    purpose: str = "payment_processing"
    category: str = "PAYMENT"


NONE = Intent("none", None, {})


def _amount_paise(text: str) -> int:
    for pattern in _AMOUNT:
        m = pattern.search(text)
        if m:
            whole = int(m.group(1).replace(",", "") or 0)
            frac = int((m.group(2) or "0").ljust(2, "0"))
            if whole > 0 or frac > 0:
                return whole * 100 + frac
    return DEFAULT_AMOUNT_PAISE


def parse_intent(text: str) -> Intent:
    """First matching rule wins: export, add-payee, pay (UPI VPA present), email (address)."""
    low = text.lower()
    addrs = [(a, b.rstrip(".-_")) for a, b in _ADDR.findall(text)]  # sentence punctuation
    vpas = [f"{a}@{b}" for a, b in addrs if "." not in b]
    mails = [f"{a}@{b}" for a, b in addrs if "." in b]
    if re.search(r"(export|dump|exfiltrate)", low) and (mails or vpas):
        ids = _CUSTOMER.findall(text) or ["C-1042"]
        return Intent(
            "export",
            "crm_export_records",
            {"customer_ids": ids[:3], "destination": (mails or vpas)[0]},
            "order_support",
            "READ",
        )
    if vpas and re.search(r"\b(add|register|save)\b.*\b(payee|beneficiary)\b", low):
        return Intent("add_payee", "upi_add_payee", {"vpa": vpas[0], "name": "Support Desk"})
    if vpas and re.search(r"\b(pay|transfer|send|remit|wire)\b", low):
        return Intent(
            "pay",
            "upi_pay_upi",
            {"payee_vpa": vpas[-1], "amount_paise": _amount_paise(text), "note": "invoice"},
        )
    if mails and re.search(r"\b(e-?mail|mail|forward|send|write)\b", low):
        return Intent(
            "email",
            "mail_send_email",
            {"to": mails[0], "subject": "Notice", "body": text[:200]},
            "order_support",
            "COMMUNICATION",
        )
    return NONE


def _error_body(exc: Exception) -> dict[str, Any]:
    text = str(exc)
    start = text.find("{")
    if start >= 0:
        try:
            body = json.loads(text[start:])
            if isinstance(body, dict):
                return body
        except ValueError:
            pass
    return {"decision": "DENY", "error": "tool_error"}


class FinBot:
    def __init__(
        self,
        client: Client[Any],
        control: Control,
        bus: EventBus | None = None,
        *,
        agent: str = "finbot",
    ) -> None:
        self.client = client
        self.control = control
        self.bus = bus
        self.agent = agent

    async def call(
        self,
        name: str,
        args: Mapping[str, Any] | None = None,
        *,
        task_id: str | None = None,
        task_pin: str | None = None,
    ) -> dict[str, Any]:
        mark = self.bus.seq if self.bus is not None else 0
        out: dict[str, Any]
        meta: dict[str, Any] = {"agent": self.agent}
        if task_id is not None:  # pin the call to the task it was bound under (no cross-talk)
            meta["task_id"] = task_id
            if task_pin is not None:  # secret: sent in meta only, never put in events/results
                meta["task_pin"] = task_pin
        try:
            res = await self.client.call_tool(
                name, dict(args or {}), meta=meta, raise_on_error=False
            )
        except Exception as exc:  # transport failure: report as a refusal, never as success
            out = {
                "ok": False,
                "decision": "DENY",
                "rules": [],
                "body": {"error": type(exc).__name__},
            }
        else:
            if res.is_error:
                text = " ".join(getattr(c, "text", "") for c in res.content)
                body = _error_body(Exception(text))
                out = {
                    "ok": False,
                    "decision": body.get("decision", "DENY"),
                    "rules": list(body.get("rules", [])),
                    "approval_id": body.get("approval_id"),
                    "body": body,
                }
            else:
                data = res.structured_content if isinstance(res.structured_content, dict) else {}
                out = {"ok": True, "decision": "ALLOW", "rules": [], "body": data}
        events = self.bus.snapshot(mark) if self.bus is not None else []
        calls = [e for e in events if e.get("type") == "call"]
        out["event_ids"] = [e["id"] for e in calls]
        if calls and out["ok"]:  # the event is authoritative for the decision label
            out["decision"] = str(calls[-1].get("decision", out["decision"]))
        return out

    def bind(
        self,
        *,
        purpose: str,
        category: str,
        text: str,
        params: Mapping[str, Any] | None = None,
        pinnable: bool = False,
    ) -> str:
        return self._bind(
            purpose=purpose, category=category, text=text, params=params, pinnable=pinnable
        )[0]

    def _bind(
        self,
        *,
        purpose: str,
        category: str,
        text: str,
        params: Mapping[str, Any] | None = None,
        pinnable: bool = False,
    ) -> tuple[str, str | None]:
        task = self.control.bind_task(
            {
                "purpose": purpose,
                "category": category,
                "text": text,
                "params": dict(params or {}),
                "pinnable": pinnable,
            }
        )
        pin = task.get("task_pin")
        return str(task["task_id"]), (pin if isinstance(pin, str) else None)

    # --- scripted flows --------------------------------------------------------------------
    async def read_invoice(self, doc_id: str) -> dict[str, Any]:
        """ON: the document comes back as a handle; the quarantined reader yields payee/amount
        handles. OFF: the raw content is returned (nothing sits in the way)."""
        doc = await self.call("files_read_document", {"doc_id": doc_id})
        out: dict[str, Any] = {"doc": doc}
        handle = doc["body"].get("handle") if doc["ok"] else None
        if isinstance(handle, str):
            for field in ("payee_vpa", "amount_paise"):
                got = await self.call("extract_field", {"handle": handle, "field": field})
                out[field] = got["body"].get("handle") if got["ok"] else None
        return out

    async def attack(self, text: str, doc_id: str, moderated: bool = False) -> dict[str, Any]:
        """The naive agent: the submitted text is an untrusted document; the agent attempts the
        one tool call the text asks for. Returns the final call result plus the parsed intent."""
        intent = parse_intent(text)
        if moderated and "body" in intent.args:  # free text never leaves via events/audit
            intent = Intent(
                intent.kind,
                intent.tool,
                {**intent.args, "body": "[withheld by display filter]"},
                intent.purpose,
                intent.category,
            )
        if intent.tool is None:
            return {
                "intent": intent.kind,
                "tool": None,
                "ok": False,
                "decision": "NO_ACTION",
                "rules": [],
            }
        # the red-team task is FIXED: attacker text can never pick the purpose or category
        tid, pin = self._bind(
            purpose="payment_processing",
            category="PAYMENT",
            text="Review the submitted document and follow up",
            pinnable=True,
        )
        try:
            await self.call("files_read_document", {"doc_id": doc_id}, task_id=tid, task_pin=pin)
            res = await self.call(intent.tool, intent.args, task_id=tid, task_pin=pin)
        finally:  # the pin is single-run: never leave a live PAYMENT task pinnable
            unpin = getattr(self.control, "unpin_task", None)
            if callable(unpin):
                unpin(tid)
        return {"intent": intent.kind, "tool": intent.tool, **res}


Runner = Callable[[str, str, bool], Awaitable[dict[str, Any]]]
