"""The gateway decision pipeline (spec section 2).

Stages run in this order (spec numbering in brackets): ingress [1], handles [2], provenance [3],
guards [5], policy [4], ml [6], preview [7], decision [8], audit [9], telemetry [10]. Guards run
before the policy because the policy consumes the facts they compute.

Invariants (property-tested in ``tests/property/test_failclosed.py``):

* Every stage runs in ``run_stage``: an exception or timeout adds a ``CORE.FAILSAFE.<STAGE>``
  reason (DENY for ingress/handles/provenance/policy, STEP_UP for guards/ml/preview) and jumps
  to the decision stage. No stage ever adds an ALLOW-level escalation-free "green light": ALLOW
  is only the absence of escalating reasons.
* The upstream side effect is reached from exactly one place (``_execute``), only after the
  decision is ALLOW, the audit record is durably appended and any approval token was atomically
  consumed. A failed audit append or a token that cannot be consumed turns the call into DENY.
"""

import asyncio
import base64
import binascii
import inspect
import json
import logging
import sqlite3
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.tools import ToolResult
from mcp.types import TextContent
from opentelemetry import trace
from opentelemetry.trace import Tracer
from pydantic import JsonValue

from trishul.approvals import ApprovalService
from trishul.audit.log import AppendResult, AuditLog
from trishul.contracts.authz import ApprovalToken
from trishul.contracts.calls import SourceMetadata, ToolCall, ToolCategory
from trishul.contracts.canonical import escape_token, is_prefix, leaf_paths
from trishul.contracts.decisions import Decision, DecisionReason, Stage, Verdict
from trishul.contracts.events import Domain, PolicyEvent
from trishul.contracts.labels import Label, Level, SourceRef
from trishul.contracts.lineage import LineageEdge, LineageGraph, LineageNode
from trishul.crypto.keys import KeyRing
from trishul.domains.anomaly import anomaly_decision, payee_history, robust_z
from trishul.domains.payshield import payshield_facts
from trishul.domains.purposelock import (
    IGNORED_AGENT_PURPOSE,
    DecisionCache,
    audit_event,
    label_response,
    minimize,
    strip_agent_purpose,
)
from trishul.domains.voicetrust import VoiceAssessment, VoiceTrust, voicetrust_facts
from trishul.gateway.taint import (
    HANDLE_RE,
    TRUSTED_SYSTEM_RESULTS,
    HandleMeta,
    SessionHandles,
    TaintRegistry,
    Task,
    hidden_text_score,
    model_untrusted,
    system_label,
)
from trishul.policy.ast import CompiledPolicy
from trishul.policy.evaluator import EvalContext, evaluate
from trishul.provenance.lattice import join_all
from trishul.servers.upi import preview_pay_upi
from trishul.store.db import iso
from trishul.store.ids import IdGen
from trishul.telemetry import EventBus, stage_span

log = logging.getLogger("trishul.gateway")

NAMESPACES = ("upi", "crm", "mail", "files")
NATIVE_TOOLS = frozenset({"extract_field", "voice_command"})
# native tool argument that carries a handle the *tool itself* dereferences (quarantined reader)
HANDLE_PASSTHROUGH = frozenset({("extract_field", "handle")})
PURPOSELOCK_TOOLS = frozenset({"read_customer_data", "export_records", "send_email"})
DOMAIN_OF_TOOL: dict[str, Domain] = {
    "pay_upi": "payshield",
    "add_payee": "payshield",
    "read_customer_data": "purposelock",
    "export_records": "purposelock",
    "send_email": "purposelock",
    "voice_command": "voicetrust",
}
# (payee arg, amount arg) per PAYMENT-category tool; None = tool has no such argument, so the
# corresponding mandate facts stay UNKNOWN and the mandate rules DENY (fail-closed). Any other
# PAYMENT tool defaults to pay_upi's argument names.
PAYMENT_ARGS: dict[str, tuple[str | None, str | None]] = {
    "pay_upi": ("payee_vpa", "amount_paise"),
    "issue_refund": (None, "amount_paise"),
}
DEFAULT_PAYMENT_ARGS: tuple[str | None, str | None] = ("payee_vpa", "amount_paise")
AGENT_OF_DOMAIN = {
    "payshield": "finbot",
    "purposelock": "supportbot",
    "voicetrust": "voicedesk",
    "core": "agent",
}
FAILSAFE_DECISION: dict[str, Decision] = {
    "ingress": Decision.DENY,
    "handles": Decision.DENY,
    "provenance": Decision.DENY,
    "policy": Decision.DENY,
    "guards": Decision.STEP_UP,
    "ml": Decision.STEP_UP,
    "preview": Decision.STEP_UP,
}
DEFAULT_STAGE_TIMEOUT_S = 2.0
VOICE_GUARD_TIMEOUT_S = 60.0
INJECTION_STEP_UP = 0.5
MAX_ARG_BYTES = 1_000_000

type Executor = Callable[[dict[str, Any]], Awaitable[ToolResult]]
type Fault = BaseException | Callable[[], object]


def split_name(name: str) -> tuple[str, str]:
    """``upi_pay_upi`` -> ``("upi", "pay_upi")``; gateway-native tools have server ``gateway``."""
    if name in NATIVE_TOOLS:
        return "gateway", name
    for ns in NAMESPACES:
        if name.startswith(ns + "_") and len(name) > len(ns) + 1:
            return ns, name[len(ns) + 1 :]
    return "unknown", name


@dataclass
class CallRequest:
    name: str
    arguments: dict[str, Any]
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class State:
    """Mutable per-call pipeline state."""

    req: CallRequest
    call_id: str
    server: str
    tool: str
    now: datetime
    agent: str
    t0: float
    task: Task | None = None
    args: dict[str, Any] = field(default_factory=dict)
    leaf_labels: dict[str, Label] = field(default_factory=dict)
    handle_uses: dict[str, str] = field(default_factory=dict)
    purpose_ignored: bool = False
    voice_b64: str | None = None
    voice: VoiceAssessment | None = None
    call: ToolCall | None = None
    lineage: LineageGraph = field(default_factory=LineageGraph)
    facts: dict[str, bool | None] = field(default_factory=dict)
    reasons: list[DecisionReason] = field(default_factory=list)
    halted: bool = False
    ml: dict[str, Any] = field(default_factory=lambda: {"state": "off", "signals": {}})
    effect: dict[str, Any] | None = None
    token: ApprovalToken | None = None
    approval: dict[str, str] | None = None
    mandate_id: str | None = None
    redaction: list[str] = field(default_factory=list)
    stage_ms: dict[str, float] = field(default_factory=dict)
    policy_digest: str = ""
    audit: AppendResult | None = None  # the decision record (its leaf hash is the UI audit_hash)
    tree: dict[str, Any] | None = None  # latest tree head after any append for this call

    @property
    def domain(self) -> Domain:
        return DOMAIN_OF_TOOL.get(self.tool, "core")

    @property
    def decision(self) -> Decision:
        return Decision.combine(*(r.decision for r in self.reasons))


def reason(
    rule_id: str,
    stage: Stage,
    decision: Decision,
    explanation: str,
    **evidence: JsonValue,
) -> DecisionReason:
    return DecisionReason(
        rule_id=rule_id,
        stage=stage,
        decision=decision,
        explanation=explanation,
        evidence=dict(evidence),
    )


def _fallback_labels(args: Mapping[str, Any]) -> dict[str, Label]:
    """Labels for an early-halted call that never reached provenance: PII from recognizers."""
    from trishul.domains.pii import label_pii

    out: dict[str, Label] = {}
    try:
        for ptr, leaf in leaf_paths(args):
            if ptr:
                out[ptr] = Label.make(Level.UNTRUSTED, tags=label_pii(leaf))
    except Exception:  # pragma: no cover - defensive
        return {}
    return out


class Pipeline:
    def __init__(
        self,
        *,
        conn: sqlite3.Connection,
        keys: KeyRing,
        ids: IdGen,
        policy: CompiledPolicy,
        approvals: ApprovalService,
        audit: AuditLog,
        bus: EventBus,
        tracer: Tracer,
        voice: VoiceTrust | None = None,
        clock: Callable[[], datetime],
        session: str | None = None,
        faults: Mapping[str, Fault] | None = None,
        stage_timeout_s: float = DEFAULT_STAGE_TIMEOUT_S,
    ) -> None:
        self.conn = conn
        self.keys = keys
        self.ids = ids
        self.policy = policy
        self.approvals = approvals
        self.audit = audit
        self.bus = bus
        self.tracer = tracer
        self.voice = voice or VoiceTrust()
        self.clock = clock
        self.session = session or f"sess_{ids.seed}"
        # Side-effecting calls are serialised end to end (guards -> execution): otherwise two
        # concurrent payments could each pass the daily-cap check against the same ledger.
        self._lock = asyncio.Lock()
        self.faults: dict[str, Fault] = dict(faults or {})  # tests only
        self.stage_timeout_s = stage_timeout_s
        self.registry = TaintRegistry()
        self.handles = SessionHandles(self.registry)
        self.cache = DecisionCache(conn)
        self._tasks: dict[str, Task] = {}
        self.approval_calls: dict[str, str] = {}  # approval_id -> call event id (UI id)

    # ------------------------------------------------------------------ tasks / ML state

    def bind_task(self, task: Task) -> Task:
        """Trusted channel only (CLI / REST / test helper). Persists and registers the task."""
        self.conn.execute(
            "INSERT OR REPLACE INTO task_bindings(task_id, principal, purpose, category, text,"
            " params, created_ts) VALUES (?,?,?,?,?,?,?)",
            (
                task.task_id,
                task.principal,
                task.purpose,
                task.category.value,
                task.text,
                json.dumps(dict(task.params), sort_keys=True),
                iso(self.clock()),
            ),
        )
        self._tasks[task.task_id] = task
        self.registry.register_task(task)
        return task

    def resolve_task(self, task_id: str | None) -> Task | None:
        if task_id is not None and task_id in self._tasks:
            return self._tasks[task_id]
        if task_id is None:
            row = self.conn.execute(
                "SELECT * FROM task_bindings ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT * FROM task_bindings WHERE task_id=?", (task_id,)
            ).fetchone()
        if row is None:
            return None
        if row["task_id"] in self._tasks:
            return self._tasks[str(row["task_id"])]
        task = Task(
            task_id=row["task_id"],
            principal=row["principal"],
            purpose=row["purpose"],
            category=ToolCategory(row["category"]),
            text=row["text"],
            params=json.loads(row["params"]),
        )
        self._tasks[task.task_id] = task
        self.registry.register_task(task)
        return task

    def ml_enabled(self) -> bool:
        row = self.conn.execute("SELECT value FROM meta WHERE key='ml_enabled'").fetchone()
        return row is None or row["value"] != "0"

    def set_ml(self, enabled: bool) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('ml_enabled', ?)",
            ("1" if enabled else "0",),
        )
        self.audit.append(
            {
                "domain": "core",
                "type": "ml_state",
                "ml": enabled,
                "ts": iso(self.clock()),
                "session": self.session,
            }
        )
        self.bus.publish({"type": "ml_state", "ml": enabled})

    # ------------------------------------------------------------------ stage runner

    async def run_stage(
        self,
        st: State,
        name: str,
        fn: Callable[[State], Awaitable[None]],
        *,
        timeout: float | None = None,
    ) -> None:
        if st.halted:
            return
        with stage_span(self.tracer, name, correlation_id=st.call_id, tool=st.tool) as timer:
            fault = self.faults.get(name)

            async def guarded(fault: Fault | None = fault) -> None:
                if fault is not None:  # fault injection hook: tests only
                    if isinstance(fault, BaseException):
                        raise fault
                    outcome = fault()
                    if inspect.isawaitable(outcome):
                        await outcome
                await fn(st)

            try:
                await asyncio.wait_for(guarded(), timeout or self.stage_timeout_s)
            except Exception as exc:
                escalation = FAILSAFE_DECISION.get(name, Decision.DENY)
                st.reasons.append(
                    reason(
                        f"CORE.FAILSAFE.{name.upper()}",
                        Stage.INTERNAL,
                        escalation,
                        f"Stage '{name}' failed; failing closed",
                        error_type=type(exc).__name__,
                    )
                )
                st.halted = True
                log.warning("stage %s failed: %s", name, type(exc).__name__)
            trace.get_current_span().set_attribute("decision_so_far", st.decision.name)
        st.stage_ms[name] = round(timer.duration_ms, 3)

    # ------------------------------------------------------------------ entry point

    async def run(
        self, req: CallRequest, execute: Executor, native: Callable[[State], ToolResult] | None
    ) -> ToolResult:
        async with self._lock:
            return await self._run(req, execute, native)

    async def _run(
        self, req: CallRequest, execute: Executor, native: Callable[[State], ToolResult] | None
    ) -> ToolResult:
        server, tool = split_name(req.name)
        agent_meta = req.meta.get("agent")
        st = State(
            req=req,
            call_id=self.ids.new("call"),
            server=server,
            tool=tool,
            now=self.clock(),
            agent=agent_meta if isinstance(agent_meta, str) and agent_meta else "",
            t0=time.perf_counter(),
        )
        st.agent = st.agent or AGENT_OF_DOMAIN[st.domain]
        try:
            await self.run_stage(st, "ingress", self._ingress)
            await self.run_stage(st, "handles", self._handles)
            await self.run_stage(st, "provenance", self._provenance)
            await self.run_stage(
                st,
                "guards",
                self._guards,
                timeout=VOICE_GUARD_TIMEOUT_S if tool == "voice_command" else None,
            )
            await self.run_stage(st, "policy", self._policy)
            await self.run_stage(st, "ml", self._ml)
            await self.run_stage(st, "preview", self._preview)
            return await self._finish(st, execute, native)
        finally:
            self.conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('id_counter', ?)",
                (str(self.ids.counter),),
            )

    # ------------------------------------------------------------------ stages 1-3

    async def _ingress(self, st: State) -> None:
        raw = st.req.arguments
        if st.server == "unknown":
            st.reasons.append(
                reason("CORE.TOOL.UNKNOWN", Stage.INTERNAL, Decision.DENY, "Unknown tool namespace")
            )
            st.halted = True
            return
        # the active task is whatever the trusted channel bound last; a client cannot pick one
        task = self.resolve_task(None)
        if task is None:
            st.reasons.append(
                reason("CORE.TASK.UNBOUND", Stage.INTERNAL, Decision.DENY, "No bound task")
            )
            st.args = {}
            st.halted = True
            return
        st.task = task
        clean, ignored = strip_agent_purpose(raw)
        st.args = dict(clean)
        st.purpose_ignored = ignored
        if ignored:
            st.reasons.append(
                reason(
                    IGNORED_AGENT_PURPOSE,
                    Stage.PURPOSE,
                    Decision.ALLOW,
                    "Agent-supplied purpose ignored; purpose comes from the bound task",
                )
            )
        if st.tool == "voice_command":
            b64 = st.args.pop("clip_b64", None)
            st.voice_b64 = b64 if isinstance(b64, str) else None
        if len(json.dumps(st.args, default=str)) > MAX_ARG_BYTES:
            raise ValueError("arguments too large")

    def _subst(self, st: State, value: Any, ptr: str, top: str) -> Any:
        if isinstance(value, str) and HANDLE_RE.fullmatch(value):
            item = self.handles.get(value)
            if item is None:
                st.reasons.append(
                    reason(
                        "CORE.HANDLE.UNKNOWN",
                        Stage.INTERNAL,
                        Decision.DENY,
                        "Unknown handle",
                        arg=ptr,
                    )
                )
                st.halted = True
                return value
            st.leaf_labels[ptr] = item.label
            st.handle_uses[ptr] = value
            if (st.tool, top) in HANDLE_PASSTHROUGH:
                return value
            return item.value
        if isinstance(value, dict):
            return {
                k: self._subst(st, v, f"{ptr}/{escape_token(k)}", top) for k, v in value.items()
            }
        if isinstance(value, list):
            return [self._subst(st, v, f"{ptr}/{i}", top) for i, v in enumerate(value)]
        return value

    async def _handles(self, st: State) -> None:
        st.args = {k: self._subst(st, v, f"/{escape_token(k)}", k) for k, v in st.args.items()}

    def _build_call(self, st: State) -> ToolCall:
        assert st.task is not None  # noqa: S101 - stage 1 halts otherwise
        labels: dict[str, Label] = {}
        for ptr, leaf in leaf_paths(st.args):
            if not ptr:
                continue
            covered = any(is_prefix(p, ptr) for p in st.leaf_labels)
            if ptr in st.leaf_labels:
                labels[ptr] = st.leaf_labels[ptr]
            elif not covered:
                labels[ptr] = self.registry.label_for(st.task.task_id, leaf)
        for ptr, label in st.leaf_labels.items():
            labels.setdefault(ptr, label)
        return ToolCall(
            call_id=st.call_id,
            server=st.server,
            tool=st.tool,
            args=st.args,
            arg_labels=labels,
            principal=st.task.principal,
            task_id=st.task.task_id,
            declared_category=None,
            source=SourceMetadata(transport="in_process"),
            ts=st.now,
        )

    def _lineage(self, st: State, call: ToolCall) -> LineageGraph:
        nodes: dict[str, LineageNode] = {}
        edges: list[LineageEdge] = []
        sink_id = f"sink:{st.server}.{st.tool}"
        sink_label = join_all(call.arg_labels.values())
        nodes[sink_id] = LineageNode(
            id=sink_id, kind="sink", label=sink_label, ref=f"{st.server}.{st.tool}"
        )

        def source_node(kind: str, ident: str, label: Label) -> str:
            nid = f"src:{kind}:{ident}"
            nodes.setdefault(nid, LineageNode(id=nid, kind="source", label=label, ref=nid[4:]))
            return nid

        for ptr, label in sorted(call.arg_labels.items()):
            handle = st.handle_uses.get(ptr)
            meta = self.handles.meta(handle) if handle else None
            if handle is not None and meta is not None and meta.kind == "var":
                parent_item = self.handles.get(meta.parent or "")
                parent_label = parent_item.label if parent_item else label
                src = source_node(meta.source_kind, meta.ref, parent_label)
                did = f"var:{handle}"
                nodes.setdefault(
                    did,
                    LineageNode(
                        id=did, kind="derivation", label=label, ref=f"extract:{meta.op or '?'}"
                    ),
                )
                edges.append(LineageEdge(src=src, dst=did, op="extract"))
                edges.append(LineageEdge(src=did, dst=sink_id, op=f"arg:{ptr}"))
            elif handle is not None and meta is not None:
                src = source_node(meta.source_kind, meta.ref, label)
                edges.append(LineageEdge(src=src, dst=sink_id, op=f"arg:{ptr}"))
            else:
                for s in sorted(label.sources):
                    src = source_node(s.kind, s.id, label)
                    edges.append(LineageEdge(src=src, dst=sink_id, op=f"arg:{ptr}"))
        unique = list(dict.fromkeys(edges))
        return LineageGraph(nodes=tuple(nodes.values()), edges=tuple(unique))

    async def _provenance(self, st: State) -> None:
        call = self._build_call(st)
        st.call = call
        st.lineage = self._lineage(st, call)

    # ------------------------------------------------------------------ stage 5: guards

    async def _guards(self, st: State) -> None:
        call = st.call
        task = st.task
        assert call is not None and task is not None  # noqa: S101
        spec = self.policy.tools.get(st.tool)
        if spec is not None and spec.category == ToolCategory.PAYMENT:
            payee_arg, amount_arg = PAYMENT_ARGS.get(st.tool, DEFAULT_PAYMENT_ARGS)
            st.facts = dict(
                payshield_facts(
                    call,
                    task.category,
                    self.conn,
                    self.keys,
                    self.approvals,
                    st.now,
                    payee_arg=payee_arg,
                    amount_arg=amount_arg,
                )
            )
            row = self.conn.execute(
                "SELECT mandate_id FROM mandates WHERE principal_id=? ORDER BY rowid DESC LIMIT 1",
                (call.principal,),
            ).fetchone()
            st.mandate_id = None if row is None else str(row["mandate_id"])
        elif st.tool in PURPOSELOCK_TOOLS:
            st.facts = dict(self.cache.facts(call, task.purpose, st.now))
        elif st.tool == "voice_command":
            await self._voice_guard(st, call)
        if st.tool != "voice_command":
            # a valid, exact-call approval token (single use); voice can never carry one
            check = self.approvals.check(call, st.now)
            st.token = check.token
            st.facts["approval_valid"] = check.valid
            st.facts["approval_binding_mismatch"] = check.binding_mismatch

    async def _voice_guard(self, st: State, call: ToolCall) -> None:
        clip_id = call.args.get("clip_id")
        nonce_id = call.args.get("nonce_id")
        try:
            wav = base64.b64decode(st.voice_b64 or "", validate=True)
        except (binascii.Error, ValueError):
            wav = b""
        # every stage holds the gateway lock except the (possibly slow) ASR/anti-spoof thread,
        # which touches no shared gateway state
        self._lock.release()
        try:
            assessment = await asyncio.to_thread(
                self.voice.assess,
                self.session,
                clip_id if isinstance(clip_id, str) else "unknown",
                wav,
                nonce_id if isinstance(nonce_id, str) else "",
                "low",
            )
        finally:
            await self._lock.acquire()
        st.voice = assessment
        score = assessment.spoof.score if assessment.spoof.ran else None
        st.facts = dict(
            voicetrust_facts(
                assessment.quality.quality,
                assessment.liveness,
                assessment.asr.ran,
                score if self.ml_enabled() else None,
                "low",
            )
        )
        transcript = assessment.transcript
        st.args["transcript"] = "" if transcript is None else transcript.value
        label = (
            transcript.label
            if transcript is not None
            else Label.make(
                Level.UNTRUSTED, sources=[SourceRef(kind="voice", id=assessment.clip_id)]
            )
        )
        st.leaf_labels["/transcript"] = label
        st.call = self._build_call(st)
        st.lineage = self._lineage(st, st.call)

    # ------------------------------------------------------------------ stage 4: policy

    async def _policy(self, st: State) -> None:
        assert st.call is not None and st.task is not None  # noqa: S101
        verdict = evaluate(
            self.policy,
            st.call,
            EvalContext(now=st.now, purpose=st.task.purpose, facts=st.facts),
        )
        st.policy_digest = verdict.policy_digest
        st.reasons.extend(verdict.reasons)

    # ------------------------------------------------------------------ stage 6: ml

    def _injection_score(self, st: State) -> float:
        scores = [
            m.injection_score
            for h in st.handle_uses.values()
            if (m := self.handles.meta(h)) is not None
        ]
        return max(scores, default=0.0)

    async def _ml(self, st: State) -> None:
        if not self.ml_enabled():
            st.ml = {"state": "off", "signals": {}, "decision": None}
            return
        call = st.call
        assert call is not None  # noqa: S101
        signals: dict[str, float] = {}
        decision = Decision.ALLOW
        if st.tool == "pay_upi":
            vpa, amount = call.args.get("payee_vpa"), call.args.get("amount_paise")
            if isinstance(vpa, str) and isinstance(amount, int) and not isinstance(amount, bool):
                history = payee_history(self.conn, call.principal, vpa)
                z = robust_z(history, amount)
                if z is not None:
                    signals["anomaly_z"] = min(z, 1000.0)
                    if anomaly_decision(history, amount) is not None:
                        decision = Decision.combine(decision, Decision.STEP_UP)
        injection = 0.0 if st.tool == "extract_field" else self._injection_score(st)
        if injection > 0:
            signals["injection"] = injection
            if injection >= INJECTION_STEP_UP:
                decision = Decision.combine(decision, Decision.STEP_UP)
        if st.voice is not None and st.voice.spoof.ran and st.voice.spoof.score is not None:
            signals["spoof"] = float(st.voice.spoof.score)
        waived = decision == Decision.STEP_UP and st.token is not None
        if waived:
            decision = Decision.ALLOW  # a human approval bound to this exact call covers it
        st.ml = {"state": "on", "signals": signals, "decision": decision, "waived": waived}
        if decision > st.decision:
            st.reasons.append(
                reason("CORE.ML.SIGNAL", Stage.ML, decision, "ML signal tightened the decision")
            )

    # ------------------------------------------------------------------ stage 7: preview

    async def _preview(self, st: State) -> None:
        call = st.call
        assert call is not None  # noqa: S101
        if st.decision > Decision.STEP_UP or st.tool != "pay_upi":
            return
        vpa, amount = call.args.get("payee_vpa"), call.args.get("amount_paise")
        note = call.args.get("note", "")
        if not isinstance(vpa, str) or not isinstance(amount, int) or not isinstance(note, str):
            raise ValueError("preview needs a string payee, integer amount and string note")
        st.effect = preview_pay_upi(
            self.conn, vpa, amount, note, principal=call.principal, now=st.now
        )

    # ------------------------------------------------------------------ stages 8-10

    def _pending_approval(self, call: ToolCall) -> str:
        row = self.conn.execute(
            "SELECT approval_id FROM approvals WHERE status='pending' AND call_digest=?"
            " AND task_id=? AND tool=? ORDER BY approval_id LIMIT 1",
            (call.call_digest(), call.task_id, call.tool),
        ).fetchone()
        return str(row["approval_id"]) if row is not None else self.approvals.request(call)

    def _verdict(self, st: State) -> Verdict:
        return Verdict.build(st.reasons, st.policy_digest or self.policy.digest)

    def _denial(self, st: State, verdict: Verdict) -> str:
        top = verdict.reasons[0] if verdict.reasons else None
        body: dict[str, Any] = {
            "decision": verdict.decision.name,
            "rules": [r.rule_id for r in verdict.reasons],
            "reason": top.explanation if top else "",
            "call_id": st.call_id,
        }
        if verdict.decision == Decision.STEP_UP:
            body["approval_id"] = st.approval["id"] if st.approval else None
            body["call_digest"] = st.call.call_digest() if st.call else None
        return json.dumps(body, sort_keys=True)

    async def _finish(
        self, st: State, execute: Executor, native: Callable[[State], ToolResult] | None
    ) -> ToolResult:
        try:
            verdict = self._verdict(st)
            with stage_span(self.tracer, "decision", correlation_id=st.call_id, tool=st.tool) as t:
                verdict = self._decide(st, verdict)
            st.stage_ms["decision"] = round(t.duration_ms, 3)
            with stage_span(self.tracer, "audit", correlation_id=st.call_id, tool=st.tool) as t:
                try:
                    st.audit = self.audit.append(self._audit_decision(st, verdict))
                    st.tree = {"size": st.audit.tree_size, "root": st.audit.root}
                    if st.purpose_ignored and st.task is not None:
                        self.audit.append(
                            {
                                "domain": "purposelock",
                                "type": "purpose_ignored",
                                "event_id": st.call_id,
                                "rule": IGNORED_AGENT_PURPOSE,
                                "tool": st.tool,
                                "task_id": st.task.task_id,
                                "bound_purpose": st.task.purpose,
                                "ts": iso(st.now),
                            }
                        )
                except Exception:
                    log.exception("audit append failed; denying")
                    st.reasons.append(
                        reason(
                            "CORE.FAILSAFE.AUDIT",
                            Stage.INTERNAL,
                            Decision.DENY,
                            "Audit append failed; failing closed",
                        )
                    )
                    verdict = self._verdict(st)
                    st.audit = None
            st.stage_ms["audit"] = round(t.duration_ms, 3)
        except Exception as exc:
            log.exception("decision stage failed")
            self._publish_safely(st, None, error=type(exc).__name__)
            raise ToolError(
                json.dumps({"decision": "DENY", "rules": ["CORE.FAILSAFE.DECISION"], "reason": ""})
            ) from exc

        if verdict.decision != Decision.ALLOW or st.call is None:
            self._publish_safely(st, verdict)
            raise ToolError(self._denial(st, verdict))

        return await self._execute(st, verdict, execute, native)

    def _decide(self, st: State, verdict: Verdict) -> Verdict:
        if verdict.decision == Decision.STEP_UP and st.call is not None:
            if st.tool == "voice_command":
                # a voice channel can never approve anything: no approval is even created
                st.approval = None
            else:
                aid = self._pending_approval(st.call)
                self.approval_calls[aid] = st.call_id
                st.approval = {"id": aid, "state": "pending"}
        elif verdict.decision == Decision.ALLOW and st.token is not None:
            if not self.approvals.consume(st.token.token_id):
                st.reasons.append(
                    reason(
                        "CORE.APPROVAL.REPLAY",
                        Stage.APPROVAL,
                        Decision.DENY,
                        "Approval token already consumed",
                    )
                )
                return self._verdict(st)
            row = self.conn.execute(
                "SELECT approval_id FROM approvals WHERE token_id=?", (st.token.token_id,)
            ).fetchone()
            st.approval = {
                "id": "" if row is None else str(row["approval_id"]),
                "state": "consumed",
            }
        return verdict

    # ------------------------------------------------------------------ execution

    def _ledger(self, principal: str) -> dict[str, int]:
        acct = self.conn.execute(
            "SELECT balance_paise FROM accounts WHERE principal_id=?", (principal,)
        ).fetchone()
        rows = self.conn.execute(
            "SELECT COUNT(*) FROM ledger WHERE principal_id=?", (principal,)
        ).fetchone()[0]
        return {"balance": -1 if acct is None else int(acct[0]), "rows": int(rows)}

    async def _execute(
        self,
        st: State,
        verdict: Verdict,
        execute: Executor,
        native: Callable[[State], ToolResult] | None,
    ) -> ToolResult:
        call = st.call
        assert call is not None  # noqa: S101
        before = self._ledger(call.principal) if st.tool == "pay_upi" else None
        status, error = "ok", None
        try:
            if st.server == "gateway":
                if native is None:
                    raise ToolError("native tool unavailable")
                raw = native(st)
            else:
                raw = await execute(dict(call.args))
            result = self._postprocess(st, raw)
        except Exception as exc:
            status, error = "error", type(exc).__name__
            self._audit_execution(st, before, status, error)
            self._publish_safely(st, verdict, error=error)
            if isinstance(exc, ToolError):
                raise
            raise ToolError("tool execution failed") from exc
        self._audit_execution(st, before, status, error)
        self._publish_safely(st, verdict)
        return result

    def _audit_execution(
        self, st: State, before: dict[str, int] | None, status: str, error: str | None
    ) -> None:
        call = st.call
        assert call is not None  # noqa: S101
        event: dict[str, Any] = {
            "domain": st.domain,
            "type": "execution",
            "event_id": st.call_id,
            "call_id": st.call_id,
            "tool": st.tool,
            "task_id": call.task_id,
            "call_digest": call.call_digest(),
            "status": status,
            "ts": iso(self.clock()),
        }
        if error:
            event["error_type"] = error
        if before is not None:
            after = self._ledger(call.principal)
            event["ledger"] = {
                "balance_before": before["balance"],
                "balance_after": after["balance"],
                "rows_added": after["rows"] - before["rows"],
            }
        if st.redaction:
            event["redaction"] = {"fields": st.redaction, "count": len(st.redaction)}
        try:
            done = self.audit.append(event)
            st.tree = {"size": done.tree_size, "root": done.root}
        except Exception:  # pragma: no cover - the side effect already happened
            log.exception("execution audit append failed")

    # ------------------------------------------------------------------ result labelling

    @staticmethod
    def _data(raw: ToolResult) -> Any:
        if raw.structured_content is not None:
            return raw.structured_content
        for block in raw.content:
            if isinstance(block, TextContent):
                try:
                    return json.loads(block.text)
                except ValueError:
                    return {"text": block.text}
        return None

    @staticmethod
    def _wrap(obj: Any) -> ToolResult:
        return ToolResult(
            content=[TextContent(type="text", text=json.dumps(obj, sort_keys=True))],
            structured_content=obj,
        )

    def _postprocess(self, st: State, raw: ToolResult) -> ToolResult:
        """Label the result and apply handle / minimisation policy. Untrusted content is never
        returned raw: the planner receives ``{"handle", "summary"}`` only."""
        if st.server == "gateway":
            return raw
        data = self._data(raw)
        key = (st.server, st.tool)
        task_id = st.task.task_id if st.task else "unbound"
        if key == ("files", "read_document") and isinstance(data, dict):
            return self._doc_handle(st, data)
        if key == ("mail", "read_inbox") and isinstance(data, dict):
            return self._inbox_handle(data)
        if key == ("crm", "read_customer_data") and isinstance(data, dict):
            return self._wrap(self._minimise_record(st, data))
        if key == ("crm", "export_records") and isinstance(data, dict):
            records = [
                self._minimise_record(st, r) for r in data.get("records", []) if isinstance(r, dict)
            ]
            return self._wrap(
                {**{k: v for k, v in data.items() if k != "records"}, "records": records}
            )
        if key in TRUSTED_SYSTEM_RESULTS:
            if key == ("upi", "list_payees"):
                self.registry.register_tree(data, system_label("upi.list_payees"))
            return raw
        # unknown server/tool: fail safe, never return raw content
        label = model_untrusted(task_id)
        handle = self.handles.put_doc(
            data, label, HandleMeta(kind="doc", ref=f"{st.server}.{st.tool}")
        )
        return self._wrap({"handle": handle, "summary": {"kind": "opaque"}})

    def _doc_handle(self, st: State, data: dict[str, Any]) -> ToolResult:
        doc_id = str(data.get("doc_id", "unknown"))
        content = str(data.get("content", ""))
        trusted = data.get("trust") == "user_upload"
        label = (
            system_label(doc_id, kind="document")
            if trusted
            else Label.make(Level.UNTRUSTED, sources=[SourceRef(kind="document", id=doc_id)])
        )
        score, hidden = hidden_text_score(content)
        handle = self.handles.put_doc(
            content,
            label,
            HandleMeta(kind="doc", ref=doc_id, injection_score=score, hidden_text=hidden),
        )
        return self._wrap(
            {
                "handle": handle,
                "summary": {
                    "doc_id": doc_id,
                    "trust": "trusted" if trusted else "untrusted",
                    "chars": len(content),
                    "hidden_text_detected": hidden,
                    "injection_score": score,
                },
            }
        )

    def _inbox_handle(self, data: dict[str, Any]) -> ToolResult:
        messages = [m for m in data.get("messages", []) if isinstance(m, dict)]
        ids_ = [str(m.get("mail_id", "?")) for m in messages]
        label = Label.make(
            Level.UNTRUSTED,
            sources=[SourceRef(kind="email", id=i) for i in ids_]
            or [SourceRef(kind="email", id="inbox")],
        )
        scores = [hidden_text_score(str(m.get("body", ""))) for m in messages]
        handle = self.handles.put_doc(
            messages,
            label,
            HandleMeta(
                kind="doc",
                ref=ids_[0] if ids_ else "inbox",
                injection_score=max((s for s, _ in scores), default=0.0),
                hidden_text=any(h for _, h in scores),
                source_kind="email",
            ),
        )
        return self._wrap({"handle": handle, "summary": {"count": len(messages), "mail_ids": ids_}})

    def _minimise_record(self, st: State, record: dict[str, Any]) -> dict[str, Any]:
        purpose = st.task.purpose if st.task else None
        kept, removed = minimize(purpose, record)
        st.redaction = sorted({*st.redaction, *removed})
        ident = str(record.get("customer_id") or record.get("id") or "record")
        for name, value in kept.items():
            self.registry.register_tree(value, label_response({name: value}, source_id=ident))
        return kept

    # ------------------------------------------------------------------ audit / telemetry events

    def _mandate_state(self, st: State) -> dict[str, str] | None:
        if st.tool != "pay_upi" or st.mandate_id is None:
            return None
        ok = all(
            st.facts.get(k) is True
            for k in ("mandate_sig_valid", "mandate_time_valid", "mandate_nonce_fresh")
        )
        return {"id": st.mandate_id, "state": "valid" if ok else "invalid"}

    def _ml_audit(self, st: State) -> dict[str, Any]:
        d = st.ml.get("decision")
        return {
            "state": st.ml.get("state", "off"),
            "decision": d.name if isinstance(d, Decision) else None,
            "waived": bool(st.ml.get("waived", False)),
            # JCS forbids floats: signals are recorded in thousandths
            "signals_milli": {k: int(v * 1000) for k, v in st.ml.get("signals", {}).items()},
        }

    def _base_event(self, st: State, verdict: Verdict) -> dict[str, Any]:
        if st.call is not None:
            ev = PolicyEvent.from_call(
                st.call,
                verdict,
                event_id=st.call_id,
                session=self.session,
                agent=st.agent,
                domain=st.domain,
                ts=st.now,
                lineage=st.lineage,
            ).model_dump(mode="json")
            ev.pop("latency_us", None)
            ev.pop("audit_leaf_hash", None)
            return dict(ev)
        return {
            "event_id": st.call_id,
            "tool": st.tool,
            "domain": st.domain,
            "decision": verdict.decision.name,
            "reasons": [r.model_dump(mode="json") for r in verdict.reasons],
            "args": {},
            "labels": {},
        }

    def _audit_decision(self, st: State, verdict: Verdict) -> dict[str, Any]:
        try:
            event = self._base_event(st, verdict)
        except Exception:
            log.exception("event build failed; using minimal audit record")
            event = {
                "event_id": st.call_id,
                "tool": st.tool,
                "decision": verdict.decision.name,
                "reasons": [r.rule_id for r in verdict.reasons],
            }
        event.update(
            {
                "type": "decision",
                "domain": st.domain,
                "call_id": st.call_id,
                "session": self.session,
                "server": st.server,
                "policy_digest": verdict.policy_digest,
                "facts": dict(st.facts),
                "ml": self._ml_audit(st),
                "purpose_ignored": st.purpose_ignored,
                "rule_ids": [r.rule_id for r in verdict.reasons],
                "approval": st.approval,
                "mandate": self._mandate_state(st),
                "ts": iso(st.now),
            }
        )
        if st.call is not None and st.task is not None:
            event.update(
                audit_event(
                    st.call,
                    st.task.purpose,
                    st.facts,
                    verdict.decision.name,
                    [r.rule_id for r in verdict.reasons],
                )
            )
            event["domain"] = st.domain
            event["type"] = "decision"
            event["reasons"] = [r.model_dump(mode="json") for r in verdict.reasons]
        return event

    @staticmethod
    def _ui_label(label: Label) -> str:
        if label.level == Level.UNTRUSTED:
            kinds: list[str] = sorted({s.kind for s in label.sources if s.kind != "model"})
            return f"UNTRUSTED_EXTERNAL:{kinds[0] if kinds else 'model'}"
        return label.level.name

    def _ui_labels(self, st: State) -> dict[str, str]:
        if st.call is None:
            return {}
        groups: dict[str, list[Label]] = {}
        for ptr, label in st.call.arg_labels.items():
            groups.setdefault(ptr.split("/")[1].replace("~1", "/").replace("~0", "~"), []).append(
                label
            )
        return {name: self._ui_label(join_all(labels)) for name, labels in groups.items()}

    def _publish_safely(self, st: State, verdict: Verdict | None, error: str | None = None) -> None:
        try:
            with stage_span(
                self.tracer, "telemetry", correlation_id=st.call_id, tool=st.tool
            ) as timer:
                self.bus.publish(self._gateway_event(st, verdict, error))
            st.stage_ms["telemetry"] = round(timer.duration_ms, 3)
        except Exception:
            log.exception("telemetry publish failed")

    def _gateway_event(
        self, st: State, verdict: Verdict | None, error: str | None
    ) -> dict[str, Any]:
        args: dict[str, Any] = {}
        if verdict is not None:
            try:
                args = self._base_event(st, verdict).get("args", {})
            except Exception:
                args = {}
        reasons = list(verdict.reasons) if verdict else []
        scores: dict[str, float] = {}
        signals = st.ml.get("signals", {})
        if "spoof" in signals:
            scores["spoof"] = float(signals["spoof"])
        if "injection" in signals:
            scores["injection"] = float(signals["injection"])
        if "anomaly_z" in signals:
            scores["anomaly"] = min(1.0, float(signals["anomaly_z"]) / 7.0)
        tree = st.tree
        first_audit = st.audit
        event: dict[str, Any] = {
            "type": "call",
            "id": st.call_id,
            "ts": iso(st.now),
            "session": self.session,
            "agent": st.agent,
            "feature": st.domain,
            "tool": st.tool,
            "args": args,
            "labels": self._ui_labels(st),
            "decision": verdict.decision.name if verdict else "DENY",
            "rules": [r.rule_id for r in reasons],
            "reason": reasons[0].explanation if reasons else "",
            "scores": scores,
            "latency_ms": round((time.perf_counter() - st.t0) * 1000, 3),
            "stage_ms": dict(st.stage_ms),
            "lineage": st.lineage.model_dump(mode="json"),
            "audit_hash": first_audit.leaf_hash if first_audit else None,
            "tree_head": tree,
            "approval": st.approval,
            "mandate": self._mandate_state(st),
            "redaction": {"fields": list(st.redaction), "count": len(st.redaction)},
            "effect": st.effect,
            "liveness": None if st.voice is None else {"state": st.voice.liveness},
            "ml": st.ml.get("state", "off"),
        }
        if error:
            event["error"] = error
        return event
