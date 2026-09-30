from datetime import timedelta

import pytest

from tests.conftest import NOW, TRUSTED, UNTRUSTED, make_call, make_ctx
from trishul.contracts.authz import ApprovalToken, Consent
from trishul.contracts.calls import ToolCategory
from trishul.contracts.decisions import Decision, Verdict
from trishul.contracts.labels import Label, Level, Tag
from trishul.policy import evaluator
from trishul.policy.ast import CompiledPolicy
from trishul.policy.compiler import compile_sources
from trishul.policy.evaluator import evaluate, evaluate_raw


def ids(v: Verdict) -> list[str]:
    return [r.rule_id for r in v.reasons]


# --- the four example policies ----------------------------------------------------------


def test_untrusted_payee_is_denied(policy: CompiledPolicy) -> None:
    call = make_call(
        "pay_upi",
        {"payee_vpa": "x@upi", "amount_paise": 100},
        {"/payee_vpa": UNTRUSTED, "/amount_paise": TRUSTED},
    )
    v = evaluate(policy, call, make_ctx())
    assert v.decision == Decision.DENY
    assert ids(v) == ["PAYSHIELD.TAINT.UNTRUSTED_PAYEE"]
    assert v.policy_digest == policy.digest


def test_trusted_payment_is_allowed(policy: CompiledPolicy) -> None:
    v = evaluate(
        policy, make_call("pay_upi", {"payee_vpa": "x@upi", "amount_paise": 100}), make_ctx()
    )
    assert v.decision == Decision.ALLOW and v.reasons == ()


def _email(body_label: Label) -> object:
    return make_call(
        "send_email",
        {"to": "a@b.example", "body": "hello", "fields": ["email"]},
        {"/to": TRUSTED, "/body": body_label, "/fields": TRUSTED},
    )


def test_pii_to_communication_sink_denied_without_consent(policy: CompiledPolicy) -> None:
    pii = Label.make(Level.TRUSTED_USER, tags=[Tag.PII_EMAIL])
    v = evaluate(policy, _email(pii), make_ctx())  # type: ignore[arg-type]
    assert v.decision == Decision.DENY
    assert ids(v) == ["PURPOSELOCK.EGRESS.PII_WITHOUT_CONSENT"]


def test_pii_allowed_with_covering_consent_and_not_otherwise(policy: CompiledPolicy) -> None:
    pii = Label.make(Level.TRUSTED_USER, tags=[Tag.PII_EMAIL])

    def consent(**kw: object) -> Consent:
        base: dict[str, object] = {
            "consent_id": "c", "principal": "alice", "purpose": "customer_support",
            "fields": frozenset({"email", "phone"}), "granted_at": NOW - timedelta(days=1),
            "status": "active",
        }  # fmt: skip
        return Consent(**{**base, **kw})  # type: ignore[arg-type]

    call = _email(pii)
    ok = make_ctx(consents=(consent(),))
    assert evaluate(policy, call, ok).decision == Decision.ALLOW  # type: ignore[arg-type]
    for bad in (
        consent(status="withdrawn"),
        consent(purpose="marketing"),
        consent(fields=frozenset({"phone"})),
        consent(principal="mallory"),
        consent(withdrawn_at=NOW - timedelta(hours=1)),
    ):
        v = evaluate(policy, call, make_ctx(consents=(bad,)))  # type: ignore[arg-type]
        assert v.decision == Decision.DENY, bad


def test_non_pii_email_allowed(policy: CompiledPolicy) -> None:
    assert evaluate(policy, _email(TRUSTED), make_ctx()).decision == Decision.ALLOW  # type: ignore[arg-type]


def _approval(call: object, **kw: object) -> ApprovalToken:
    base: dict[str, object] = {
        "token_id": "t", "call_digest": call.call_digest(),  # type: ignore[attr-defined]
        "scope": "close_account", "approver": "bob", "issued_at": NOW - timedelta(minutes=5),
        "expires_at": NOW + timedelta(minutes=5), "nonce": "n",
    }  # fmt: skip
    return ApprovalToken(**{**base, **kw})  # type: ignore[arg-type]


def test_high_risk_without_approval_steps_up_then_allows_with_bound_approval(
    policy: CompiledPolicy,
) -> None:
    call = make_call("close_account", {"account_id": "A1"})
    v = evaluate(policy, call, make_ctx())
    assert v.decision == Decision.STEP_UP and ids(v) == ["CORE.APPROVAL.CLOSE_ACCOUNT"]
    assert evaluate(policy, call, make_ctx(approvals=(_approval(call),))).decision == Decision.ALLOW


def test_approval_must_be_bound_scoped_and_unexpired(policy: CompiledPolicy) -> None:
    call = make_call("close_account", {"account_id": "A1"})
    other = make_call("close_account", {"account_id": "A2"})
    bad = [
        _approval(other),
        _approval(call, scope="other"),
        _approval(call, expires_at=NOW, issued_at=NOW - timedelta(minutes=1)),
        _approval(call, issued_at=NOW + timedelta(minutes=1), expires_at=NOW + timedelta(hours=1)),
    ]
    for token in bad:
        assert evaluate(policy, call, make_ctx(approvals=(token,))).decision == Decision.STEP_UP


def test_refund_cap(policy: CompiledPolicy) -> None:
    small = make_call("issue_refund", {"order_id": "o", "amount_paise": 500000})
    big = make_call("issue_refund", {"order_id": "o", "amount_paise": 500001})
    assert evaluate(policy, small, make_ctx()).decision == Decision.ALLOW
    assert evaluate(policy, big, make_ctx()).decision == Decision.STEP_UP


def test_trusted_operation_allows_and_untrusted_steps_up(policy: CompiledPolicy) -> None:
    v = evaluate(policy, make_call("get_balance", {"account_id": "A1"}), make_ctx())
    assert v.decision == Decision.ALLOW
    v = evaluate(
        policy,
        make_call("get_balance", {"account_id": "A1"}, {"/account_id": UNTRUSTED}),
        make_ctx(),
    )
    assert v.decision == Decision.STEP_UP


# --- schema stage -----------------------------------------------------------------------


def test_unknown_tool_denied(policy: CompiledPolicy) -> None:
    v = evaluate(policy, make_call("rm_rf", {}), make_ctx())
    assert v.decision == Decision.DENY and ids(v) == ["CORE.SCHEMA.UNKNOWN_TOOL"]


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ({"payee_vpa": "a@b"}, "CORE.SCHEMA.MISSING_ARG"),
        ({"payee_vpa": "a@b", "amount_paise": "100"}, "CORE.SCHEMA.WRONG_TYPE"),
        ({"payee_vpa": "a@b", "amount_paise": True}, "CORE.SCHEMA.WRONG_TYPE"),
        ({"payee_vpa": None, "amount_paise": 1}, "CORE.SCHEMA.WRONG_TYPE"),
        ({"payee_vpa": "a@b", "amount_paise": 1, "extra": 1}, "CORE.SCHEMA.UNKNOWN_ARG"),
    ],
)
def test_schema_violations_denied(
    policy: CompiledPolicy, args: dict[str, object], expected: str
) -> None:
    v = evaluate(policy, make_call("pay_upi", args), make_ctx())
    assert v.decision == Decision.DENY and expected in ids(v)


def test_declared_category_mismatch_denied(policy: CompiledPolicy) -> None:
    call = make_call("pay_upi", {"payee_vpa": "a@b", "amount_paise": 1}, category=ToolCategory.READ)
    assert "CORE.SCHEMA.CATEGORY_MISMATCH" in ids(evaluate(policy, call, make_ctx()))


def test_missing_label_is_untrusted_with_reason(policy: CompiledPolicy) -> None:
    call = make_call("pay_upi", {"payee_vpa": "a@b", "amount_paise": 1}, {"/amount_paise": TRUSTED})
    v = evaluate(policy, call, make_ctx())
    assert v.decision == Decision.DENY
    assert set(ids(v)) == {"PAYSHIELD.TAINT.UNTRUSTED_PAYEE", "CORE.LABEL.MISSING"}
    missing = next(r for r in v.reasons if r.rule_id == "CORE.LABEL.MISSING")
    assert missing.evidence == {"paths": ["/payee_vpa"]}


def test_ancestor_label_covers_nested_leaves_and_sibling_gap_is_untrusted() -> None:
    src = """
version: 1
id: t.nested
tools:
  t: {category: WRITE, args: {payee: {type: object, required: true}}}
rules:
  - id: T.TAINT.PAYEE
    stage: LABEL
    then: DENY
    explain: e
    when: {label_at_least: {arg: /payee, level: UNTRUSTED}}
"""
    p = compile_sources([("t.yaml", src)])
    args = {"payee": {"vpa": "a", "name": "b"}}
    covered = make_call("t", args, {"/payee": TRUSTED})
    assert evaluate(p, covered, make_ctx()).decision == Decision.ALLOW
    gap = make_call("t", args, {"/payee/vpa": TRUSTED})  # /payee/name has no label
    v = evaluate(p, gap, make_ctx())
    assert v.decision == Decision.DENY and "CORE.LABEL.MISSING" in ids(v)


# --- three-valued logic -----------------------------------------------------------------

KLEENE = """
version: 1
id: t.kleene
tools:
  t: {category: READ, args: {x: {type: integer}, y: {type: integer}}}
rules:
  - id: K.UNKNOWN.FIRES
    stage: CAP
    then: STEP_UP
    explain: e
    when: {arg_compare: {arg: /x, op: gt, value: 5}}
  - id: K.NOT.UNKNOWN
    stage: CAP
    then: STEP_UP
    explain: e
    when: {not: {arg_compare: {arg: /x, op: gt, value: 5}}}
  - id: K.FALSE.DOMINATES
    stage: CAP
    then: DENY
    explain: e
    when: {all: [{arg_compare: {arg: /x, op: gt, value: 5}}, {const: false}]}
  - id: K.TRUE.DOMINATES
    stage: CAP
    then: DENY
    explain: e
    when: {any: [{arg_compare: {arg: /x, op: gt, value: 5}}, {const: true}]}
"""


def test_unknown_fires_and_is_flagged() -> None:
    p = compile_sources([("k.yaml", KLEENE)])
    v = evaluate(p, make_call("t", {"y": 1}), make_ctx())  # x absent -> UNKNOWN
    by_id = {r.rule_id: r for r in v.reasons}
    assert by_id["K.UNKNOWN.FIRES"].unknown and by_id["K.NOT.UNKNOWN"].unknown
    assert "K.FALSE.DOMINATES" not in by_id  # FALSE and UNKNOWN -> FALSE
    assert (
        by_id["K.TRUE.DOMINATES"].decision == Decision.DENY
        and not by_id["K.TRUE.DOMINATES"].unknown
    )


def test_known_values_do_not_flag_unknown() -> None:
    p = compile_sources([("k.yaml", KLEENE)])
    v = evaluate(p, make_call("t", {"x": 10}), make_ctx())
    assert {r.rule_id for r in v.reasons} == {"K.UNKNOWN.FIRES", "K.TRUE.DOMINATES"}
    assert not any(r.unknown for r in v.reasons)


# --- ML, purity, fault injection --------------------------------------------------------


@pytest.mark.parametrize("base_call_ok", [True, False])
@pytest.mark.parametrize("ml", [None, *Decision])
def test_ml_can_only_tighten(
    policy: CompiledPolicy, base_call_ok: bool, ml: Decision | None
) -> None:
    label = TRUSTED if base_call_ok else UNTRUSTED
    call = make_call(
        "pay_upi",
        {"payee_vpa": "a@b", "amount_paise": 1},
        {"/payee_vpa": label, "/amount_paise": TRUSTED},
    )
    base = evaluate(policy, call, make_ctx()).decision
    result = evaluate(policy, call, make_ctx(ml_decision=ml))
    assert result.decision >= base
    assert result.decision == max(base, ml if ml is not None else Decision.ALLOW)
    if ml == Decision.ALLOW and base == Decision.DENY:
        assert result.decision == Decision.DENY


def test_ml_tightening_is_explained(policy: CompiledPolicy) -> None:
    call = make_call("get_balance", {"account_id": "A1"})
    v = evaluate(policy, call, make_ctx(ml_decision=Decision.STEP_UP))
    assert v.decision == Decision.STEP_UP and ids(v) == ["CORE.ML.SIGNAL"]


def test_evaluation_is_deterministic(policy: CompiledPolicy) -> None:
    call = make_call("close_account", {"account_id": "A1"})
    assert evaluate(policy, call, make_ctx()) == evaluate(policy, call, make_ctx())


def test_predicate_fault_becomes_internal_deny(
    policy: CompiledPolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object) -> object:
        raise RuntimeError("secret detail ABCDE1234F")

    monkeypatch.setattr(evaluator, "_label_at_least", boom)
    call = make_call("get_balance", {"account_id": "A1"})
    v = evaluate(policy, call, make_ctx())
    assert v.decision == Decision.DENY
    assert ids(v) == ["TRISHUL.INTERNAL.ERROR"]
    assert "ABCDE1234F" not in v.model_dump_json()  # exception text never leaks


def test_fault_in_raw_path_also_denies(
    policy: CompiledPolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evaluator, "_evaluate", lambda *_: 1 / 0)
    call = make_call("get_balance", {"account_id": "A1"})
    raw = {"call": call.model_dump(mode="json"), "context": make_ctx().model_dump(mode="json")}
    assert ids(evaluate_raw(policy, raw)) == ["TRISHUL.INTERNAL.ERROR"]


def test_evaluate_raw_accepts_wellformed_and_denies_malformed(policy: CompiledPolicy) -> None:
    call = make_call("get_balance", {"account_id": "A1"})
    raw = {"call": call.model_dump(mode="json"), "context": make_ctx().model_dump(mode="json")}
    assert evaluate_raw(policy, raw).decision == Decision.ALLOW
    for garbage in (None, 5, "x", [], {}, {"call": {}}, {"call": raw["call"]}, object(), {1: 2}):
        v = evaluate_raw(policy, garbage)
        assert v.decision == Decision.DENY and ids(v) == ["CORE.SCHEMA.MALFORMED_INPUT"]
    floaty = {"call": {**raw["call"], "args": {"account_id": 1.5}}, "context": raw["context"]}
    assert evaluate_raw(policy, floaty).decision == Decision.DENY
