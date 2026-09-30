"""Invariant checks over the Z3 encoding (spec section 9) and the invariant -> test map.

Each check asserts the *negation* of an invariant for one tool; UNSAT means the invariant holds
for every label/fact/ML assignment. A solver timeout is UNKNOWN and never reported as UNSAT.

Invariant -> test map (property tests live in ``tests/property``):

* I1 no untrusted sink argument reaches ALLOW      -> ``tests/unit/test_z3_policy.py``
* I2 ML/combination never lowers a decision        -> ``tests/unit/test_z3_policy.py`` (proof),
  ``tests/property/test_invariants.py`` (evaluator)
* I3 any stage 2-6 fault never ALLOWs (fail-closed) -> ``tests/property/test_failclosed.py``
* I4 payment ALLOW implies a valid mandate          -> ``tests/unit/test_z3_policy.py``
* I5 PII purpose sinks ALLOW only with consent      -> ``tests/unit/test_z3_policy.py``
* I6 approval token valid only for the exact call   -> ``tests/property/test_invariants.py``
* I7 audit byte flip gives exact ``bad_index``      -> ``tests/property/test_audit_mutation.py``
"""

from typing import Any

import z3  # type: ignore[import-untyped]

from trishul.contracts.decisions import Decision
from trishul.policy import ast
from trishul.verify.z3_policy import ToolModel, translate

PROPERTY = (
    "I1 untrusted sink never ALLOW; I2 combination never lowers; "
    "I4 payment ALLOW needs valid mandate; I5 PII sinks need active consent"
)

MANDATE_FACTS = (
    "mandate_sig_valid",
    "mandate_time_valid",
    "mandate_nonce_fresh",
    "payee_in_mandate",
    "category_matches",
)
CAP_FACTS = ("amount_within_payee_cap", "amount_within_per_txn_cap", "amount_within_daily_cap")


def _sink_paths(policy: ast.CompiledPolicy, tool: str) -> list[str]:
    return [f"/{n}" for n, a in policy.tools[tool].args.items() if a.sink]


def _i1(policy: ast.CompiledPolicy, m: ToolModel) -> z3.BoolRef | None:
    paths = _sink_paths(policy, m.tool)
    if not paths:
        return None
    terms: list[z3.BoolRef] = []
    for path in paths:
        present = m.present[path]
        term = m.labels[path] == 2
        terms.append(term if present is None else z3.And(term, present == 1))
    return z3.And(z3.Or(*terms), m.final == int(Decision.ALLOW))


def _i2(_: ast.CompiledPolicy, m: ToolModel) -> z3.BoolRef:
    return m.final < m.decision


def _i4(policy: ast.CompiledPolicy, m: ToolModel) -> z3.BoolRef | None:
    if m.category != "PAYMENT":
        return None
    valid = z3.And(
        *[m.fact(f) == 2 for f in MANDATE_FACTS],
        z3.Or(z3.And(*[m.fact(f) == 2 for f in CAP_FACTS]), m.fact("approval_valid") == 2),
    )
    return z3.And(m.final == int(Decision.ALLOW), z3.Not(valid))


def _purpose_rules(policy: ast.CompiledPolicy, tool: str) -> list[ast.Rule]:
    out = []
    for rule in policy.rules:
        if rule.stage.value == "PURPOSE" and tool in _tools_named(rule.when):
            out.append(rule)
    return out


def _tools_named(node: ast.Predicate) -> set[str]:
    match node:
        case ast.ToolIs():
            return {node.tool}
        case ast.All() | ast.Any():
            return set().union(*(_tools_named(n) for n in node.items)) if node.items else set()
        case ast.Not():
            return _tools_named(node.item)
    return set()


def _pii_atoms(node: ast.Predicate) -> list[ast.LabelHasTag]:
    match node:
        case ast.LabelHasTag():
            return [node] if node.tag.name == "PII" else []
        case ast.All() | ast.Any():
            return [a for n in node.items for a in _pii_atoms(n)]
        case ast.Not():
            return _pii_atoms(node.item)
    return []


def _i5(policy: ast.CompiledPolicy, m: ToolModel) -> z3.BoolRef | None:
    rules = _purpose_rules(policy, m.tool)
    if not rules:
        return None
    # Premise: PII actually flows to the sink (some PII-tag atom TRUE), when the rules speak of it.
    pii = [a for r in rules for a in _pii_atoms(r.when)]
    premise: list[z3.BoolRef] = []
    if pii:
        premise.append(z3.Or(*[m.atoms["A:" + a.model_dump_json()][1] == 2 for a in pii]))
    return z3.And(m.final == int(Decision.ALLOW), m.fact("consent_active") != 2, *premise)


def _model_dict(model: z3.ModelRef) -> dict[str, int]:
    return {str(d.name()): model.eval(d(), model_completion=True).as_long() for d in model.decls()}


def _check(
    m: ToolModel, negation: z3.BoolRef, timeout_ms: int
) -> tuple[str, dict[str, int] | None]:
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    solver.add(*m.constraints)
    solver.add(negation)
    res = solver.check()
    if res == z3.unsat:
        return "UNSAT", None
    if res == z3.sat:
        return "SAT", _model_dict(solver.model())
    return "UNKNOWN", None


def prove_all(policy: ast.CompiledPolicy, timeout_ms: int = 10000) -> dict[str, Any]:
    """Run I1, I2, I4, I5 for every applicable tool. Overall UNSAT only if all are UNSAT."""
    models = translate(policy)
    rows: list[dict[str, Any]] = []
    for tool, m in models.items():
        for inv_id, build in (("I1", _i1), ("I2", _i2), ("I4", _i4), ("I5", _i5)):
            negation = build(policy, m)
            if negation is None:
                continue
            result, cex = _check(m, negation, timeout_ms)
            rows.append({"id": inv_id, "tool": tool, "result": result, "counterexample": cex})
    results = {r["result"] for r in rows}
    overall = "UNSAT" if results <= {"UNSAT"} else ("SAT" if "SAT" in results else "UNKNOWN")
    return {"result": overall, "solver": "z3", "property": PROPERTY, "per_invariant": rows}
