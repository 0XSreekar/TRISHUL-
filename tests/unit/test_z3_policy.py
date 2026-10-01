"""Z3 translation: proofs on the real policies, the unsafe fixture, and agreement with the
runtime evaluator (I1, I2, I4, I5)."""

from pathlib import Path
from typing import Any

import pytest
import z3  # type: ignore[import-untyped]
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.conftest import NOW, POLICY_DIR
from trishul.contracts.calls import SourceMetadata, ToolCall
from trishul.contracts.decisions import Decision
from trishul.contracts.labels import Label, Level, Tag
from trishul.policy import ast
from trishul.policy.compiler import compile_files
from trishul.policy.evaluator import EvalContext, _build_env, eval_predicate, evaluate
from trishul.verify import prove_all, translate
from trishul.verify.z3_policy import path_var_name

UNSAFE_DIR = Path(__file__).resolve().parents[2] / "trishul" / "fixtures" / "unsafe_policy"


@pytest.mark.acceptance(15)
def test_real_policies_proofs(policy: ast.CompiledPolicy) -> None:
    out = prove_all(policy)
    assert out["solver"] == "z3" and out["property"]
    sat = {(r["id"], r["tool"]) for r in out["per_invariant"] if r["result"] == "SAT"}
    assert sat == set()
    assert out["result"] == "UNSAT"
    unsat = {(r["id"], r["tool"]) for r in out["per_invariant"] if r["result"] == "UNSAT"}
    assert {
        ("I1", "pay_upi"),
        ("I1", "add_payee"),
        ("I1", "export_records"),
        ("I1", "send_email"),
        ("I4", "pay_upi"),
        ("I4", "issue_refund"),
        ("I5", "read_customer_data"),
    } <= unsat
    assert all(r["counterexample"] is None for r in out["per_invariant"] if r["result"] != "SAT")
    assert all(r["result"] == "UNSAT" for r in out["per_invariant"] if r["id"] == "I2")


@pytest.mark.acceptance(15)
def test_unsafe_fixture_gives_pay_upi_counterexample() -> None:
    out = prove_all(compile_files([UNSAFE_DIR]))
    row = next(r for r in out["per_invariant"] if (r["id"], r["tool"]) == ("I1", "pay_upi"))
    assert row["result"] == "SAT"
    assert row["counterexample"][path_var_name("pay_upi", "/payee_vpa")] == 2
    assert out["result"] == "SAT"


def test_timeout_is_unknown_never_unsat(
    policy: ast.CompiledPolicy, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(z3.Solver, "check", lambda self, *a: z3.unknown)  # solver gave up
    out = prove_all(policy)
    assert out["result"] == "UNKNOWN"
    assert all(r["result"] == "UNKNOWN" for r in out["per_invariant"])


def test_unknown_node_kind_raises(policy: ast.CompiledPolicy) -> None:
    class Bogus:
        pass

    from trishul.verify.z3_policy import _Translator

    with pytest.raises(TypeError):
        _Translator(policy, "pay_upi").pred(Bogus())  # type: ignore[arg-type]


# --- translation vs evaluator -----------------------------------------------------------

_POLICY = compile_files([POLICY_DIR])
_SAMPLE = {"string": "x", "integer": 100, "boolean": True, "array": ["x"], "object": {"k": "v"}}


def _collect_facts(node: Any, out: set[str]) -> None:
    if isinstance(node, ast.Fact):
        out.add(node.name)
    for attr in ("items",):
        for child in getattr(node, attr, ()):
            _collect_facts(child, out)
    if isinstance(node, ast.Not):
        _collect_facts(node.item, out)


def _all_facts() -> list[str]:
    names: set[str] = set()
    for r in _POLICY.rules:
        _collect_facts(r.when, names)
    return sorted(names)


_LABELS = st.builds(
    Label,
    level=st.sampled_from(list(Level)),
    tags=st.frozensets(st.sampled_from(list(Tag)), max_size=3),
)


@settings(max_examples=150, deadline=None)
@given(data=st.data())
def test_translation_agrees_with_evaluator(data: st.DataObject) -> None:
    tool = data.draw(st.sampled_from(sorted(_POLICY.tools)))
    spec = _POLICY.tools[tool]
    args = {n: _SAMPLE[a.type] for n, a in spec.args.items()}
    labels = {f"/{n}": data.draw(_LABELS) for n in args}
    facts = {n: data.draw(st.sampled_from([True, False, None])) for n in _all_facts()}
    ml = data.draw(st.sampled_from([None, *Decision]))
    call = ToolCall(
        call_id="c1",
        server="srv",
        tool=tool,
        args=args,
        arg_labels=labels,
        principal="alice",
        task_id="t1",
        source=SourceMetadata(),
        ts=NOW,
    )
    ctx = EvalContext(now=NOW, facts=facts, ml_decision=ml)
    expected = evaluate(_POLICY, call, ctx).decision

    model = translate(_POLICY)[tool]
    env = _build_env(call, ctx, spec.category)
    fixed: list[z3.BoolRef] = []
    for path, var in model.labels.items():
        fixed.append(var == int(labels[path].level))
    for pvar in model.present.values():
        if pvar is not None:
            fixed.append(pvar == 1)
    for name, var in model.facts.items():
        val = facts[name]
        fixed.append(var == (1 if val is None else (2 if val else 0)))
    for node, var in model.atoms.values():
        fixed.append(var == eval_predicate(env, node).value)
    fixed.append(model.ml == int(ml if ml is not None else Decision.ALLOW))
    solver = z3.Solver()
    solver.add(*model.constraints, *fixed)
    assert solver.check() == z3.sat
    got = solver.model().eval(model.final, model_completion=True).as_long()
    assert got == int(expected)
