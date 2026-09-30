"""Property tests for invariants I2 and I6 (see ``trishul.verify.invariants`` for the full
invariant -> test map; I3 is ``test_failclosed.py``, I7 is ``test_audit_mutation.py``)."""

from datetime import UTC, datetime

from hypothesis import given, settings
from hypothesis import strategies as st

from tests.conftest import NOW, POLICY_DIR, make_call
from trishul.approvals import ApprovalService
from trishul.contracts.calls import ToolCall
from trishul.contracts.decisions import Decision
from trishul.contracts.labels import Label, Level, Tag
from trishul.crypto.keys import KeyRing
from trishul.policy.compiler import compile_files
from trishul.policy.evaluator import EvalContext, evaluate
from trishul.store.db import connect
from trishul.store.ids import IdGen

POLICY = compile_files([POLICY_DIR])
_SAMPLE = {"string": "x", "integer": 100, "boolean": True, "array": ["x"], "object": {"k": "v"}}
_LABELS = st.builds(
    Label,
    level=st.sampled_from(list(Level)),
    tags=st.frozensets(st.sampled_from(list(Tag)), max_size=3),
)
_FACT_NAMES = [
    "mandate_sig_valid",
    "mandate_time_valid",
    "mandate_nonce_fresh",
    "payee_in_mandate",
    "category_matches",
    "approval_valid",
    "consent_active",
    "sink_allowed_for_purpose",
    "voice_liveness_mismatch",
    "voice_quality_ok",
]


@settings(max_examples=200, deadline=None)
@given(data=st.data())
def test_i2_ml_decision_never_lowers(data: st.DataObject) -> None:
    tool = data.draw(st.sampled_from(sorted(POLICY.tools)))
    args = {n: _SAMPLE[a.type] for n, a in POLICY.tools[tool].args.items()}
    labels = {f"/{n}": data.draw(_LABELS) for n in args}
    facts = {n: data.draw(st.sampled_from([True, False, None])) for n in _FACT_NAMES}
    call = make_call(tool, args, labels)
    base = evaluate(POLICY, call, EvalContext(now=NOW, facts=facts)).decision
    ml = data.draw(st.sampled_from(list(Decision)))
    with_ml = evaluate(POLICY, call, EvalContext(now=NOW, facts=facts, ml_decision=ml)).decision
    assert with_ml >= base
    assert with_ml == max(base, ml)


T0 = datetime(2026, 9, 30, 9, 0, tzinfo=UTC)


def _mutate(call: ToolCall, which: str) -> ToolCall:
    if which == "amount":
        return make_call("pay_upi", {**call.args, "amount_paise": 101})
    if which == "payee":
        return make_call("pay_upi", {**call.args, "payee_vpa": "evil@upi"})
    if which == "extra_arg":
        return make_call("pay_upi", {**call.args, "note": "n"})
    if which == "tool":
        return call.model_copy(update={"tool": "issue_refund"})
    if which == "principal":
        return call.model_copy(update={"principal": "eve"})
    return call.model_copy(update={"task_id": "t2"})


@settings(max_examples=60, deadline=None)
@given(
    amount=st.integers(1, 10**6),
    payee=st.text(alphabet="abcxyz", min_size=1, max_size=6).map(lambda s: f"{s}@upi"),
    which=st.sampled_from(["amount", "payee", "extra_arg", "tool", "principal", "task"]),
)
def test_i6_token_valid_only_for_exact_call(amount: int, payee: str, which: str) -> None:
    svc = ApprovalService(connect(":memory:"), KeyRing.from_seed(42), IdGen(42), clock=lambda: T0)
    call = make_call("pay_upi", {"payee_vpa": payee, "amount_paise": amount})
    token = svc.approve(svc.request(call), "sreekar")
    assert svc.check(call, T0).valid
    assert token.call_digest == call.call_digest()
    mutated = _mutate(call, which)
    assert mutated.call_digest() != call.call_digest()
    assert not svc.check(mutated, T0).valid
