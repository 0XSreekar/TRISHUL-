from datetime import timedelta

import pytest

from tests.conftest import NOW, TRUSTED, UNTRUSTED, make_call, make_ctx
from trishul.contracts.authz import ApprovalToken
from trishul.contracts.calls import ToolCategory
from trishul.contracts.decisions import Decision, Verdict
from trishul.contracts.labels import Label, Level, Tag
from trishul.policy import evaluator
from trishul.policy.ast import CompiledPolicy
from trishul.policy.compiler import compile_sources
from trishul.policy.evaluator import EvalContext, evaluate, evaluate_raw

GOOD_MANDATE_FACTS: dict[str, bool | None] = {
    "mandate_sig_valid": True,
    "mandate_time_valid": True,
    "mandate_nonce_fresh": True,
    "payee_in_mandate": True,
    "category_matches": True,
    "amount_within_payee_cap": True,
    "amount_within_per_txn_cap": True,
    "amount_within_daily_cap": True,
    "approval_valid": False,
    "approval_binding_mismatch": False,
}


def ids(v: Verdict) -> list[str]:
    return [r.rule_id for r in v.reasons]


# --- the four example policies ----------------------------------------------------------


def test_untrusted_payee_is_denied(policy: CompiledPolicy) -> None:
    call = make_call(
        "pay_upi",
        {"payee_vpa": "x@upi", "amount_paise": 100},
        {"/payee_vpa": UNTRUSTED, "/amount_paise": TRUSTED},
    )
    v = evaluate(policy, call, make_ctx(facts=GOOD_MANDATE_FACTS))
    assert v.decision == Decision.DENY
    assert ids(v) == ["PAYSHIELD.TAINT.UNTRUSTED_PAYEE"]
    assert v.policy_digest == policy.digest


def test_trusted_payment_is_allowed(policy: CompiledPolicy) -> None:
    v = evaluate(
        policy,
        make_call("pay_upi", {"payee_vpa": "x@upi", "amount_paise": 100}),
        make_ctx(facts=GOOD_MANDATE_FACTS),
    )
    assert v.decision == Decision.ALLOW and v.reasons == ()


def _email(body_label: Label) -> object:
    return make_call(
        "send_email",
        {"to": "a@b.example", "subject": "hi", "body": "hello"},
        {"/to": TRUSTED, "/subject": TRUSTED, "/body": body_label},
    )


def test_pii_to_communication_sink_denied_without_consent(policy: CompiledPolicy) -> None:
    pii = Label.make(Level.TRUSTED_USER, tags=[Tag.PII_EMAIL])
    v = evaluate(policy, _email(pii), make_ctx())  # type: ignore[arg-type]
    assert v.decision == Decision.DENY
    assert ids(v) == ["PURPOSELOCK.EGRESS.PII_WITHOUT_CONSENT"]


def test_pii_allowed_only_with_both_purposelock_facts(policy: CompiledPolicy) -> None:
    pii = Label.make(Level.TRUSTED_USER, tags=[Tag.PII_EMAIL])
    call = _email(pii)
    both = {"consent_active": True, "sink_allowed_for_purpose": True}
    assert evaluate(policy, call, make_ctx(facts=both)).decision == Decision.ALLOW  # type: ignore[arg-type]
    for bad in (
        {"consent_active": False, "sink_allowed_for_purpose": True},
        {"consent_active": True, "sink_allowed_for_purpose": False},
        {"consent_active": True, "sink_allowed_for_purpose": None},
        {"consent_active": None},
        {},
    ):
        assert evaluate(policy, call, make_ctx(facts=bad)).decision == Decision.DENY, bad  # type: ignore[arg-type]


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
    approved = make_ctx(facts={"approval_valid": True})  # gateway: exact-call approval verified
    assert evaluate(policy, call, approved).decision == Decision.ALLOW


def test_approval_binding_mismatch_denies_every_non_voice_tool(policy: CompiledPolicy) -> None:
    call = make_call("close_account", {"account_id": "A1"})
    ctx = make_ctx(facts={"approval_binding_mismatch": True})
    v = evaluate(policy, call, ctx)
    assert v.decision == Decision.DENY and "PAYSHIELD.APPROVAL.BINDING_MISMATCH" in ids(v)
    # missing approval facts fail closed
    bare = EvalContext(now=NOW)
    assert evaluate(policy, call, bare).decision == Decision.DENY


def test_refund_cap(policy: CompiledPolicy) -> None:
    small = make_call("issue_refund", {"order_id": "o", "amount_paise": 500000})
    big = make_call("issue_refund", {"order_id": "o", "amount_paise": 500001})
    good = make_ctx(facts=GOOD_MANDATE_FACTS)
    assert evaluate(policy, small, good).decision == Decision.ALLOW
    assert evaluate(policy, big, good).decision == Decision.STEP_UP
    # PAYMENT tools are mandate-gated too: no mandate facts (e.g. no payee) => DENY
    assert evaluate(policy, small, make_ctx()).decision == Decision.DENY


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
    v = evaluate(policy, call, make_ctx(facts=GOOD_MANDATE_FACTS))
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
