from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.conftest import POLICY_DIR, make_call, make_ctx
from tests.property.strategies import labels
from trishul.contracts.decisions import Decision, Verdict
from trishul.contracts.labels import Label
from trishul.policy.compiler import compile_files
from trishul.policy.evaluator import evaluate, evaluate_raw

POLICY = compile_files([POLICY_DIR])

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(),
    lambda inner: (
        st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=8), inner, max_size=4)
    ),
    max_leaves=25,
)
garbage = json_values | st.binary() | st.sets(st.integers()) | st.just(object())
call_keys = [
    "call_id",
    "server",
    "tool",
    "args",
    "arg_labels",
    "principal",
    "task_id",
    "ts",
    "source",
]
structured = st.fixed_dictionaries(
    {},
    optional={
        "call": st.dictionaries(st.sampled_from(call_keys), json_values, max_size=9) | json_values,
        "context": st.dictionaries(st.sampled_from(["now", "purpose", "ml_decision"]), json_values)
        | json_values,
    },
)


@settings(suppress_health_check=[HealthCheck.too_slow], max_examples=300)
@given(st.one_of(garbage, structured))
def test_evaluate_raw_is_total(obj: Any) -> None:
    verdict = evaluate_raw(POLICY, obj)
    assert isinstance(verdict, Verdict)
    assert verdict.decision == Decision.DENY  # arbitrary input is never a valid call+context


def test_evaluate_raw_survives_cycles_and_depth() -> None:
    cyc: list[object] = []
    cyc.append(cyc)
    deep: object = "x"
    for _ in range(5000):
        deep = [deep]
    for obj in (cyc, {"call": cyc}, deep, {"call": {"args": deep}}, 10**5000):
        assert evaluate_raw(POLICY, obj).decision == Decision.DENY


tools = st.sampled_from(
    ["pay_upi", "send_email", "close_account", "issue_refund", "get_balance", "x"]
)
args_st = st.dictionaries(
    st.sampled_from(
        ["payee_vpa", "amount_paise", "to", "body", "fields", "account_id", "order_id", "z"]
    ),
    st.one_of(
        st.text(max_size=6),
        st.integers(),
        st.booleans(),
        st.none(),
        st.lists(st.text(max_size=3), max_size=3),
    ),
    max_size=5,
)
label_maps = st.dictionaries(
    st.sampled_from(
        ["/payee_vpa", "/amount_paise", "/to", "/body", "/fields", "/account_id", "/order_id"]
    ),
    labels,
    max_size=6,
)


@settings(max_examples=300)
@given(tools, args_st, label_maps, st.sampled_from([None, *Decision]))
def test_evaluate_typed_is_total_and_ml_never_loosens(
    tool: str, args: dict[str, Any], lab: dict[str, Label], ml: Decision | None
) -> None:
    call = make_call(tool, args, lab)
    base = evaluate(POLICY, call, make_ctx())
    with_ml = evaluate(POLICY, call, make_ctx(ml_decision=ml))
    assert isinstance(base, Verdict)
    assert with_ml.decision >= base.decision
    assert with_ml.decision == max(base.decision, ml if ml is not None else Decision.ALLOW)
    assert list(base.reasons) == sorted(base.reasons, key=lambda r: (-int(r.decision), r.rule_id))
