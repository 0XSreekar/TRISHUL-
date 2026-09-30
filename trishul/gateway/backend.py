# SPDX-License-Identifier: Apache-2.0
"""Concrete ``GatewayBackend`` for the REST API and CLI (trusted, out-of-band channel).

Errors follow the API conventions: ``KeyError`` -> 404, ``ValueError`` / ``PermissionError`` ->
400. Everything mutating is appended to the audit log. When the API runs in a thread pool the
work is marshalled onto the gateway's event loop so the shared SQLite connection is only ever
used from one thread.
"""

import asyncio
import concurrent.futures
import json
import os
import re
import secrets
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal, TypeVar

from fastmcp import Client

from trishul.approvals import ApprovalError
from trishul.audit.verify import verify
from trishul.contracts.calls import ToolCategory
from trishul.domains.dpdp import dpdp_report
from trishul.domains.purposelock import ConsentRecord, ConsentRegistry
from trishul.finbot import FinBot
from trishul.finbot.moments import run_moment
from trishul.gateway.pipeline import Pipeline
from trishul.gateway.showcase import ShowcaseMixin
from trishul.gateway.taint import Task
from trishul.observability.redaction import redact_args
from trishul.redteam.service import RedTeam
from trishul.store.db import DEMO_PRINCIPAL, iso, parse_iso

T = TypeVar("T")
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
MAX_TEXT = 4000


class Backend(ShowcaseMixin):
    def __init__(self, pipeline: Pipeline) -> None:
        self.p = pipeline
        self.loop: asyncio.AbstractEventLoop | None = None
        self.mcp: Any = None  # the gateway's FastMCP (set by build_gateway)
        self.registry = ConsentRegistry(pipeline.conn, pipeline.clock)
        self.redteam = RedTeam(pipeline, self._attack)
        self.control_baseline()

    # --- scripted agent plumbing --------------------------------------------------------
    def finbot_client(self) -> Client[Any]:
        """In-memory MCP transport; ``TRISHUL_FINBOT_URL`` targets the real gateway URL."""
        url = os.environ.get("TRISHUL_FINBOT_URL")
        if self.mcp is None and not url:
            raise RuntimeError("gateway MCP not attached")
        return Client(url or self.mcp)

    async def _attack(self, text: str, doc_id: str, moderated: bool) -> dict[str, Any]:
        async with self.finbot_client() as client:
            return await FinBot(client, self, self.p.bus, agent="redteam").attack(
                text, doc_id, moderated
            )

    async def demo_moment(self, n: int, step: int | None = None) -> dict[str, Any]:
        if isinstance(n, bool) or not 1 <= n <= 6:
            raise ValueError("moment must be 1..6")
        async with self.finbot_client() as client:
            bot = FinBot(client, self, self.p.bus, agent="finbot")
            out: dict[str, Any] = await run_moment(self, bot, n, step)
            return out

    async def redteam_submit(self, text: object, client_ip: str) -> dict[str, Any]:
        res: dict[str, Any] = await self.redteam.submit(text, client_ip)
        return res

    async def redteam_fallback(self, count: int | None = None) -> list[dict[str, Any]]:
        done: list[dict[str, Any]] = await self.redteam.fallback(count)
        return done

    def redteam_stats(self) -> dict[str, Any]:
        return self._run(self.redteam.stats)

    def redteam_kill(self, on: bool) -> dict[str, Any]:
        return self._run(lambda: self.redteam.set_killed(on))

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
                return str(aid)
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
            pin: str | None = None
            if payload.get("pinnable") is True:  # harness tasks: a call may pin this id in meta
                pin = secrets.token_urlsafe(16)  # bearer secret: returned once, never logged
                self.p.pinnable[task.task_id] = pin
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
            out = {
                "task_id": task.task_id,
                "principal": task.principal,
                "purpose": task.purpose,
                "category": task.category.value,
            }
            if pin is not None:
                out["task_pin"] = pin
            return out

        return self._run(go)

    def unpin_task(self, task_id: str) -> None:
        """Drop a harness task's pin once its run is over (pins are single-run secrets)."""
        self.p.pinnable.pop(task_id, None)

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
                "tree_head": {
                    "size": self.p.audit.size(),
                    "root": self.p.audit.root().hex(),
                },
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

    def dpdp(self) -> dict[str, Any]:
        return self._run(lambda: dpdp_report(self.p.conn, self.p.keys))

    def set_ml(self, enabled: bool) -> None:
        self._run(lambda: self.p.set_ml(enabled))


def parse_ts(text: str) -> datetime:
    return parse_iso(text)
