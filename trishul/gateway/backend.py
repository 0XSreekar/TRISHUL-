"""Concrete ``GatewayBackend`` for the REST API and CLI (trusted, out-of-band channel).

Errors follow the API conventions: ``KeyError`` -> 404, ``ValueError`` / ``PermissionError`` ->
400. Everything mutating is appended to the audit log. When the API runs in a thread pool the
work is marshalled onto the gateway's event loop so the shared SQLite connection is only ever
used from one thread.
"""

import asyncio
import concurrent.futures
import importlib
import json
import re
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal, TypeVar

from trishul.approvals import ApprovalError
from trishul.audit.verify import verify
from trishul.contracts.calls import ToolCategory
from trishul.domains.dpdp import dpdp_report
from trishul.domains.purposelock import ConsentRecord, ConsentRegistry
from trishul.gateway.pipeline import Pipeline
from trishul.gateway.taint import Task
from trishul.observability.redaction import redact_args
from trishul.store.db import DEMO_PRINCIPAL, iso, parse_iso

T = TypeVar("T")
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
MAX_TEXT = 4000


class Backend:
    def __init__(self, pipeline: Pipeline) -> None:
        self.p = pipeline
        self.loop: asyncio.AbstractEventLoop | None = None
        self.registry = ConsentRegistry(pipeline.conn, pipeline.clock)

    # --- thread marshalling -------------------------------------------------------------
    def _run(self, fn: Callable[[], T]) -> T:
        loop = self.loop
        if loop is None:
            return fn()
        try:
            if asyncio.get_running_loop() is loop:
                return fn()
        except RuntimeError:
            pass
        done: concurrent.futures.Future[T] = concurrent.futures.Future()

        def call() -> None:
            try:
                done.set_result(fn())
            except BaseException as exc:
                done.set_exception(exc)

        loop.call_soon_threadsafe(call)
        return done.result(timeout=30)

    # --- consent ------------------------------------------------------------------------
    def _consent_dict(self, c: ConsentRecord) -> dict[str, Any]:
        now = self.p.clock()
        if c.withdrawn_at is not None:
            status = "withdrawn"
        elif now >= parse_iso(c.exp):
            status = "expired"
        else:
            status = "active"
        return {
            "id": c.consent_id,
            "consent_id": c.consent_id,
            "principal": c.principal_id,
            "principal_id": c.principal_id,
            "category": c.category,
            "purposes": list(c.purposes),
            "exp": c.exp,
            "withdrawn_at": c.withdrawn_at,
            "status": status,
        }

    def list_consent(self) -> list[dict[str, Any]]:
        return self._run(lambda: [self._consent_dict(c) for c in self.registry.list()])

    def withdraw_consent(self, consent_id: str) -> dict[str, Any]:
        def go() -> dict[str, Any]:
            record = self.registry.withdraw(consent_id)  # KeyError -> 404
            self.p.audit.append(
                {
                    "domain": "purposelock",
                    "type": "consent_withdrawn",
                    "consent_id": consent_id,
                    "principal_id": record.principal_id,
                    "epoch": self.registry.epoch(),
                    "ts": iso(self.p.clock()),
                }
            )
            out = self._consent_dict(record)
            self.p.bus.publish({"type": "consent", "id": consent_id, "status": "withdrawn"})
            return out

        return self._run(go)

    # --- approvals ----------------------------------------------------------------------
    def _approval_id(self, ident: str) -> str:
        if self.p.approvals.get(ident) is not None:
            return ident
        for aid, call_id in self.p.approval_calls.items():
            if call_id == ident:
                return aid
        raise KeyError(ident)

    def _approval_dict(self, row: Any) -> dict[str, Any]:
        aid = str(row["approval_id"])
        try:
            args = json.loads(row["canonical_call"]).get("args", {})
            shown = json.loads(json.dumps(redact_args(args, {}), default=lambda o: o.model_dump()))
        except (ValueError, AttributeError, TypeError):
            shown = {}
        return {
            "approval_id": aid,
            "id": self.p.approval_calls.get(aid, aid),
            "task_id": row["task_id"],
            "tool": row["tool"],
            "call_digest": row["call_digest"],
            "status": row["status"],
            "created_ts": row["created_ts"],
            "decided_ts": row["decided_ts"],
            "approver": row["approver"],
            "consumed": row["consumed_ts"] is not None,
            "args": shown,
        }

    def list_approvals(self) -> list[dict[str, Any]]:
        def go() -> list[dict[str, Any]]:
            rows = self.p.conn.execute(
                "SELECT * FROM approvals ORDER BY (status='pending') DESC, created_ts, approval_id"
            ).fetchall()
            return [self._approval_dict(r) for r in rows]

        return self._run(go)

    def resolve_approval(
        self, approval_id: str, decision: Literal["approve", "reject"], approver: str
    ) -> dict[str, Any]:
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be approve or reject")
        if not approver or approver.lower().startswith("voice"):
            raise PermissionError("approvals are out-of-band only; voice cannot approve")

        def go() -> dict[str, Any]:
            aid = self._approval_id(approval_id)
            row = self.p.approvals.get(aid)
            assert row is not None  # noqa: S101 - _approval_id checked existence
            try:
                if decision == "approve":
                    token = self.p.approvals.approve(aid, approver)
                    token_id: str | None = token.token_id
                else:
                    self.p.approvals.reject(aid, approver)
                    token_id = None
            except ApprovalError as exc:
                raise ValueError(str(exc)) from exc
            self.p.audit.append(
                {
                    "domain": "payshield",
                    "type": "approval",
                    "approval_id": aid,
                    "decision": "approved" if decision == "approve" else "rejected",
                    "approver": approver,
                    "tool": row["tool"],
                    "task_id": row["task_id"],
                    "call_digest": row["call_digest"],
                    "token_id": token_id,
                    "ts": iso(self.p.clock()),
                }
            )
            event_id = self.p.approval_calls.get(aid, aid)
            self.p.bus.publish(
                {
                    "type": "resolution",
                    "id": event_id,
                    "approval_id": aid,
                    "decision": "ALLOW" if decision == "approve" else "DENY",
                }
            )
            return {
                "approval_id": aid,
                "status": "approved" if decision == "approve" else "rejected",
            }

        return self._run(go)

    # --- tasks / voice / verification ----------------------------------------------------
    def bind_task(self, payload: dict[str, Any]) -> dict[str, Any]:
        purpose, text = payload.get("purpose"), payload.get("text", "")
        params = payload.get("params", {})
        if not isinstance(purpose, str) or not purpose or not isinstance(text, str):
            raise ValueError("purpose and text must be strings")
        if len(text) > MAX_TEXT or not isinstance(params, dict):
            raise ValueError("invalid text or params")
        try:
            category = ToolCategory(payload.get("category", "READ"))
        except ValueError as exc:
            raise ValueError("unknown category") from exc
        principal = payload.get("principal", DEMO_PRINCIPAL)
        task_id = payload.get("task_id")
        if not isinstance(principal, str) or not principal:
            raise ValueError("invalid principal")
        if task_id is not None and (not isinstance(task_id, str) or not _ID.match(task_id)):
            raise ValueError("invalid task_id")

        def go() -> dict[str, Any]:
            task = self.p.bind_task(
                Task(
                    task_id=task_id or self.p.ids.new("task"),
                    principal=principal,
                    purpose=purpose,
                    category=category,
                    text=text,
                    params=params,
                )
            )
            self.p.audit.append(
                {
                    "domain": "core",
                    "type": "task_bound",
                    "task_id": task.task_id,
                    "principal": task.principal,
                    "purpose": task.purpose,
                    "category": task.category.value,
                    "ts": iso(self.p.clock()),
                }
            )
            return {
                "task_id": task.task_id,
                "principal": task.principal,
                "purpose": task.purpose,
                "category": task.category.value,
            }

        return self._run(go)

    def issue_voice_nonce(self, session: str) -> dict[str, Any]:
        nonce = self.p.voice.nonces.issue(session)
        return {
            "nonce_id": nonce.nonce_id,
            "phrase": nonce.phrase,
            "session": session,
            "ttl_s": 10,
        }

    def audit_verify(self) -> dict[str, Any]:
        def go() -> dict[str, Any]:
            result = verify(self.p.conn, self.p.keys)
            out = {
                "ok": result.ok,
                "size": result.size,
                "bad_index": result.bad_index,
                "invalid_sths": list(result.invalid_sths),
            }
            self.p.bus.publish(
                {
                    "type": "audit_verify",
                    "ok": result.ok,
                    "bad_index": result.bad_index,
                    "bad_id": result.bad_index,
                }
            )
            return out

        return self._run(go)

    def prove(self) -> dict[str, Any]:
        """Z3 proofs arrive with ``trishul.verify`` (T6); until then report UNAVAILABLE."""
        try:
            mod = importlib.import_module("trishul.verify")
        except ImportError:
            return {"result": "UNAVAILABLE", "solver": "z3", "per_invariant": []}
        fn = getattr(mod, "prove_all", None)
        if not callable(fn):
            return {"result": "UNAVAILABLE", "solver": "z3", "per_invariant": []}
        out = fn(self.p.policy)
        return dict(out) if isinstance(out, dict) else {"result": "UNAVAILABLE"}

    def dpdp(self) -> dict[str, Any]:
        return self._run(lambda: dpdp_report(self.p.conn, self.p.keys))

    def set_ml(self, enabled: bool) -> None:
        self._run(lambda: self.p.set_ml(enabled))


def parse_ts(text: str) -> datetime:
    return parse_iso(text)
