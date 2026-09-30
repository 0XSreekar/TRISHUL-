"""Pure, total, three-valued policy evaluator (A7, A8, A10, A11).

No I/O, no clock, no randomness: everything comes in through ``ToolCall`` and ``EvalContext``.
A rule fires when its predicate is TRUE *or UNKNOWN*; rules can only escalate; the outermost
wrapper converts any exception into ``DENY`` with ``TRISHUL.INTERNAL.ERROR``.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from trishul.contracts.authz import ApprovalToken, Consent, Mandate, UtcDatetime
from trishul.contracts.calls import ToolCall, ToolCategory
from trishul.contracts.canonical import (
    is_prefix,
    leaf_paths,
    resolve_pointer,
)
from trishul.contracts.decisions import Decision, DecisionName, DecisionReason, Stage, Verdict
from trishul.contracts.labels import Label, Level
from trishul.contracts.values import ABSENT
from trishul.policy import ast
from trishul.provenance.lattice import join_all

INTERNAL_ERROR_ID = "TRISHUL.INTERNAL.ERROR"
MISSING_LABEL = Label(level=Level.UNTRUSTED)


class EvalContext(BaseModel):
    """Everything the evaluator may read besides the call. ``now`` is caller-supplied (A10)."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    now: UtcDatetime
    purpose: str | None = None
    consents: tuple[Consent, ...] = ()
    mandates: tuple[Mandate, ...] = ()
    approvals: tuple[ApprovalToken, ...] = ()
    ml_decision: DecisionName | None = Field(
        default=None, description="Combined with the rule result via max: ML can only tighten."
    )


class Tri(Enum):
    FALSE = 0
    UNKNOWN = 1
    TRUE = 2


def _tri(value: bool) -> Tri:
    return Tri.TRUE if value else Tri.FALSE


def _reason(
    rule_id: str,
    stage: Stage,
    decision: Decision,
    explanation: str,
    evidence: dict[str, object] | None = None,
    *,
    unknown: bool = False,
) -> DecisionReason:
    return DecisionReason(
        rule_id=rule_id,
        stage=stage,
        decision=decision,
        explanation=explanation,
        evidence=evidence or {},  # type: ignore[arg-type]
        unknown=unknown,
    )


# --- environment ------------------------------------------------------------------------


@dataclass(frozen=True)
class _Env:
    call: ToolCall
    ctx: EvalContext
    category: ToolCategory
    leaf_labels: dict[str, Label]  # effective label per leaf pointer of args
    missing: tuple[str, ...]  # leaves that had no label at all


def _build_env(call: ToolCall, ctx: EvalContext, category: ToolCategory) -> _Env:
    leaf_labels: dict[str, Label] = {}
    missing: list[str] = []
    for leaf, _ in leaf_paths(call.args):
        covering = [lab for p, lab in call.arg_labels.items() if is_prefix(p, leaf)]
        if covering:
            leaf_labels[leaf] = join_all(covering)
        else:
            leaf_labels[leaf] = MISSING_LABEL
            missing.append(leaf)
    return _Env(call, ctx, category, leaf_labels, tuple(sorted(missing)))


def _label_of(env: _Env, path: str) -> Label | None:
    """Join of the effective labels of every leaf under ``path``; ``None`` if arg is absent."""
    if resolve_pointer(env.call.args, path) is ABSENT:
        return None
    return join_all(lab for leaf, lab in env.leaf_labels.items() if is_prefix(path, leaf))


def _arg(env: _Env, path: str) -> object:
    return resolve_pointer(env.call.args, path)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# --- predicates (each returns Tri) ------------------------------------------------------


def _eval_arg_compare(env: _Env, node: ast.ArgCompare) -> Tri:
    actual = _arg(env, node.path)
    if actual is ABSENT:
        return Tri.UNKNOWN
    expected = node.value
    if node.op in ("eq", "ne"):
        same = type(actual) is type(expected) and actual == expected
        return _tri(same if node.op == "eq" else not same)
    both_int = _is_int(actual) and _is_int(expected)
    both_str = isinstance(actual, str) and isinstance(expected, str)
    if not (both_int or both_str):
        return Tri.UNKNOWN
    a, e = actual, expected
    result = {
        "lt": a < e,  # type: ignore[operator]
        "le": a <= e,  # type: ignore[operator]
        "gt": a > e,  # type: ignore[operator]
        "ge": a >= e,  # type: ignore[operator]
    }[node.op]
    return _tri(result)


def _label_at_least(env: _Env, node: ast.LabelAtLeast) -> Tri:
    label = _label_of(env, node.path)
    return Tri.FALSE if label is None else _tri(label.level >= node.level)


def _label_has_tag(env: _Env, node: ast.LabelHasTag) -> Tri:
    label = _label_of(env, node.path)
    return Tri.FALSE if label is None else _tri(node.tag in label.tags)


def _source_kind_in(env: _Env, node: ast.SourceKindIn) -> Tri:
    label = _label_of(env, node.path)
    if label is None:
        return Tri.FALSE
    return _tri(any(s.kind in node.kinds for s in label.sources))


def _valid_at(env: _Env, start: object, end: object) -> bool:
    return bool(start <= env.ctx.now <= end)  # type: ignore[operator]


def _consent_covers(env: _Env, node: ast.ConsentCovers) -> Tri:
    requested = _arg(env, node.fields_path)
    if not isinstance(requested, list) or not all(isinstance(f, str) for f in requested):
        return Tri.UNKNOWN
    wanted = set(requested)
    now = env.ctx.now
    for c in env.ctx.consents:
        active = (
            c.status == "active"
            and c.principal == env.call.principal
            and c.purpose == node.purpose
            and c.granted_at <= now
            and (c.withdrawn_at is None or c.withdrawn_at > now)
        )
        if active and wanted <= c.fields:
            return Tri.TRUE
    return Tri.FALSE


def _mandate_present(env: _Env, node: ast.MandatePresent) -> Tri:
    return _tri(
        any(
            m.principal == env.call.principal and _valid_at(env, m.valid_from, m.valid_until)
            for m in env.ctx.mandates
        )
    )


def _mandate_covers(env: _Env, node: ast.MandateCovers) -> Tri:
    amount = _arg(env, node.amount_path)
    payee = _arg(env, node.payee_path)
    if not _is_int(amount) or not isinstance(payee, str):
        return Tri.UNKNOWN
    return _tri(
        any(
            m.principal == env.call.principal
            and m.payee_vpa == payee
            and amount <= m.max_amount_paise  # type: ignore[operator]
            and _valid_at(env, m.valid_from, m.valid_until)
            for m in env.ctx.mandates
        )
    )


def _approval_present(env: _Env, node: ast.ApprovalPresent) -> Tri:
    call_digest = env.call.call_digest()
    now = env.ctx.now
    return _tri(
        any(
            a.scope == node.scope
            and a.call_digest == call_digest
            and a.issued_at <= now < a.expires_at
            for a in env.ctx.approvals
        )
    )


def _amount_exceeds(env: _Env, node: ast.AmountExceeds) -> Tri:
    amount = _arg(env, node.path)
    if not _is_int(amount):
        return Tri.UNKNOWN
    return _tri(amount > node.cap_paise)  # type: ignore[operator]


def _all(values: list[Tri]) -> Tri:
    if Tri.FALSE in values:
        return Tri.FALSE
    return Tri.UNKNOWN if Tri.UNKNOWN in values else Tri.TRUE


def _any(values: list[Tri]) -> Tri:
    if Tri.TRUE in values:
        return Tri.TRUE
    return Tri.UNKNOWN if Tri.UNKNOWN in values else Tri.FALSE


def eval_predicate(env: _Env, node: ast.Predicate) -> Tri:
    """Kleene evaluation. Children are always all evaluated (no hidden short-circuit)."""
    match node:
        case ast.Const():
            return _tri(node.value)
        case ast.All():
            return _all([eval_predicate(env, n) for n in node.items])
        case ast.Any():
            return _any([eval_predicate(env, n) for n in node.items])
        case ast.Not():
            inner = eval_predicate(env, node.item)
            return {Tri.TRUE: Tri.FALSE, Tri.FALSE: Tri.TRUE, Tri.UNKNOWN: Tri.UNKNOWN}[inner]
        case ast.ToolIs():
            return _tri(env.call.tool == node.tool)
        case ast.ToolCategoryIn():
            return _tri(env.category in node.categories)
        case ast.ArgExists():
            return _tri(_arg(env, node.path) is not ABSENT)
        case ast.ArgCompare():
            return _eval_arg_compare(env, node)
        case ast.LabelAtLeast():
            return _label_at_least(env, node)
        case ast.LabelHasTag():
            return _label_has_tag(env, node)
        case ast.SourceKindIn():
            return _source_kind_in(env, node)
        case ast.PurposeIs():
            purpose = env.ctx.purpose
            return Tri.UNKNOWN if purpose is None else _tri(purpose == node.purpose)
        case ast.ConsentCovers():
            return _consent_covers(env, node)
        case ast.MandatePresent():
            return _mandate_present(env, node)
        case ast.MandateCovers():
            return _mandate_covers(env, node)
        case ast.ApprovalPresent():
            return _approval_present(env, node)
        case ast.AmountExceeds():
            return _amount_exceeds(env, node)
    raise TypeError(f"unhandled predicate node {type(node).__name__}")  # pragma: no cover


# --- pipeline ---------------------------------------------------------------------------

_TYPE_CHECKS: dict[str, Callable[[object], bool]] = {
    "string": lambda v: isinstance(v, str),
    "integer": _is_int,
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
}


def _schema_reasons(spec: ast.ToolSpec, call: ToolCall) -> list[DecisionReason]:
    reasons: list[DecisionReason] = []

    def deny(rule_id: str, text: str, **evidence: object) -> None:
        reasons.append(_reason(rule_id, Stage.SCHEMA, Decision.DENY, text, evidence))

    if call.declared_category is not None and call.declared_category != spec.category:
        deny(
            "CORE.SCHEMA.CATEGORY_MISMATCH",
            "Declared category differs from policy",
            declared=call.declared_category.value,
            expected=spec.category.value,
        )
    for name in sorted(call.args):
        arg = spec.args.get(name)
        if arg is None:
            deny("CORE.SCHEMA.UNKNOWN_ARG", "Argument is not declared for this tool", arg=name)
        elif not _TYPE_CHECKS[arg.type](call.args[name]):
            deny(
                "CORE.SCHEMA.WRONG_TYPE", "Argument has the wrong type", arg=name, expected=arg.type
            )
    for name, arg in sorted(spec.args.items()):
        if arg.required and name not in call.args:
            deny("CORE.SCHEMA.MISSING_ARG", "Required argument is missing", arg=name)
    return reasons


def _evaluate(policy: ast.CompiledPolicy, call: ToolCall, ctx: EvalContext) -> Verdict:
    spec = policy.tools.get(call.tool)
    if spec is None:
        reason = _reason(
            "CORE.SCHEMA.UNKNOWN_TOOL",
            Stage.SCHEMA,
            Decision.DENY,
            "Tool is not declared in the policy",
            {"tool": call.tool},
        )
        return Verdict.build([reason], policy.digest)
    schema = _schema_reasons(spec, call)
    if schema:
        return Verdict.build(schema, policy.digest)

    env = _build_env(call, ctx, spec.category)
    reasons: list[DecisionReason] = []
    if env.missing:
        reasons.append(
            _reason(
                "CORE.LABEL.MISSING",
                Stage.LABEL,
                Decision.ALLOW,
                "Argument had no label; treated as UNTRUSTED",
                {"paths": list(env.missing)},
            )
        )
    for rule in policy.rules:
        outcome = eval_predicate(env, rule.when)
        if outcome is not Tri.FALSE:
            reasons.append(
                _reason(
                    rule.id, rule.stage, rule.then, rule.explain, unknown=outcome is Tri.UNKNOWN
                )
            )
    result = Decision.combine(*(r.decision for r in reasons))
    if ctx.ml_decision is not None and ctx.ml_decision > result:
        reasons.append(
            _reason("CORE.ML.SIGNAL", Stage.ML, ctx.ml_decision, "ML signal tightened the decision")
        )
    return Verdict.build(reasons, policy.digest)


def _internal_error(policy_digest: str, exc: BaseException) -> Verdict:
    reason = _reason(
        INTERNAL_ERROR_ID,
        Stage.INTERNAL,
        Decision.DENY,
        "Internal evaluation error; failing closed",
        {"error_type": type(exc).__name__},
    )
    return Verdict.build([reason], policy_digest)


def evaluate(policy: ast.CompiledPolicy, call: ToolCall, ctx: EvalContext) -> Verdict:
    """Total: always returns a ``Verdict``; any internal failure becomes DENY."""
    try:
        return _evaluate(policy, call, ctx)
    except Exception as exc:
        return _internal_error(getattr(policy, "digest", ""), exc)


_KNOWN_FIELDS = frozenset(
    name
    for model in (ToolCall, EvalContext, Label, Consent, Mandate, ApprovalToken)
    for name in model.model_fields
) | {"call", "context"}


def _safe_loc(loc: tuple[int | str, ...]) -> str:
    """Error locations may contain attacker-chosen keys: keep only schema field names."""
    return "/".join(p if isinstance(p, str) and p in _KNOWN_FIELDS else "*" for p in loc)


def _malformed(policy_digest: str, exc: Exception) -> Verdict:
    evidence: dict[str, object] = {"error_type": type(exc).__name__}
    if isinstance(exc, ValidationError):
        evidence["errors"] = sorted(
            {f"{_safe_loc(e['loc'])}: {e['type']}" for e in exc.errors(include_input=False)}
        )[:20]
    reason = _reason(
        "CORE.SCHEMA.MALFORMED_INPUT",
        Stage.PARSE,
        Decision.DENY,
        "Input could not be validated as a tool call and context",
        evidence,
    )
    return Verdict.build([reason], policy_digest)


def evaluate_raw(policy: ast.CompiledPolicy, obj: object) -> Verdict:
    """Totality entry point for untyped input: ``{"call": {...}, "context": {...}}``."""
    digest = getattr(policy, "digest", "")
    try:
        data = json.loads(json.dumps(obj, allow_nan=False))
        if not isinstance(data, dict) or "call" not in data or "context" not in data:
            raise ValueError("expected an object with 'call' and 'context'")
        if set(data) - {"call", "context"}:
            raise ValueError("unexpected top-level keys")
        call = ToolCall.model_validate_json(json.dumps(data["call"]))
        ctx = EvalContext.model_validate_json(json.dumps(data["context"]))
    except Exception as exc:
        return _malformed(digest, exc)
    return evaluate(policy, call, ctx)
