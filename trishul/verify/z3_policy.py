# SPDX-License-Identifier: Apache-2.0
"""Translate a ``CompiledPolicy`` to Z3 (spec section 9).

The constraints are derived by walking the *same* AST the runtime evaluator uses; there are no
hand-written copies of rules. Three-valued truth is an Int in {0,1,2} (FALSE, UNKNOWN, TRUE);
``All`` is min, ``Any`` is max, ``Not`` is 2-x. A rule fires iff its value is not 0 (TRUE or
UNKNOWN), the rule decision is the max of the fired ``then`` values (0 = ALLOW when none fire),
and ``final = max(decision, ml)`` with ``ml`` free in {0,1,2}.

Atoms the model cannot reason about precisely (tags, source kinds, purposes, argument values,
mandates, approvals ...) are free Tri variables, one per distinct atom: a sound over-approximation
because the solver may pick any value, UNKNOWN included. ``Fact`` atoms are free Tri shared by name.
Label levels are one Int per (tool, path); ``LabelAtLeast`` is ``L >= level`` (and the argument
must be present). ``ToolIs``/``ToolCategoryIn`` are evaluated concretely per tool.
"""

from dataclasses import dataclass, field

import z3  # type: ignore[import-untyped]

from trishul.contracts.decisions import Decision
from trishul.policy import ast


def _min(values: list[z3.ArithRef]) -> z3.ArithRef:
    out = values[0]
    for v in values[1:]:
        out = z3.If(v < out, v, out)
    return out


def _max(values: list[z3.ArithRef | int]) -> z3.ArithRef | int:
    out = values[0]
    for v in values[1:]:
        out = z3.If(v > out, v, out)
    return out


def path_var_name(tool: str, path: str) -> str:
    return f"L_{tool}_{path.strip('/').replace('/', '_')}"


@dataclass
class ToolModel:
    """Z3 encoding of the policy for one tool."""

    tool: str
    category: str
    labels: dict[str, z3.ArithRef] = field(default_factory=dict)  # path -> level var
    present: dict[str, z3.ArithRef | None] = field(default_factory=dict)  # None = required
    facts: dict[str, z3.ArithRef] = field(default_factory=dict)
    atoms: dict[str, tuple[ast.Predicate, z3.ArithRef]] = field(default_factory=dict)
    constraints: list[z3.BoolRef] = field(default_factory=list)
    rule_values: dict[str, z3.ArithRef | int] = field(default_factory=dict)
    ml: z3.ArithRef = None
    decision: z3.ArithRef | int = 0
    final: z3.ArithRef | int = 0

    def fact(self, name: str) -> z3.ArithRef:
        if name not in self.facts:
            var = z3.Int(f"F_{name}")
            self.facts[name] = var
            self.constraints.append(z3.And(var >= 0, var <= 2))
        return self.facts[name]


class _Translator:
    def __init__(self, policy: ast.CompiledPolicy, tool: str) -> None:
        self.spec = policy.tools[tool]
        self.m = ToolModel(tool, self.spec.category.value)

    def label_var(self, path: str) -> z3.ArithRef:
        m = self.m
        if path not in m.labels:
            var = z3.Int(path_var_name(m.tool, path))
            m.labels[path] = var
            m.constraints.append(z3.And(var >= 0, var <= 2))
            parts = path.split("/")
            arg = self.spec.args.get(parts[1]) if len(parts) > 1 else None
            if arg is not None and arg.required and len(parts) == 2:
                m.present[path] = None
            else:
                p = z3.Int(f"P_{m.tool}_{path.strip('/').replace('/', '_')}")
                m.present[path] = p
                m.constraints.append(z3.And(p >= 0, p <= 1))
        return m.labels[path]

    def _has_arg(self, path: str) -> z3.BoolRef:
        parts = path.split("/")
        if len(parts) > 1 and parts[1] not in self.spec.args:
            return z3.BoolVal(False)  # undeclared arg: schema stage denies, never present
        self.label_var(path)
        p = self.m.present[path]
        return z3.BoolVal(True) if p is None else p == 1

    def free(self, node: ast.Predicate) -> z3.ArithRef:
        key = "A:" + node.model_dump_json()
        if key not in self.m.atoms:
            var = z3.Int(key)
            self.m.atoms[key] = (node, var)
            self.m.constraints.append(z3.And(var >= 0, var <= 2))
        return self.m.atoms[key][1]

    def pred(self, node: ast.Predicate) -> z3.ArithRef | int:
        match node:
            case ast.Const():
                return 2 if node.value else 0
            case ast.All():
                return _min([self.pred(n) for n in node.items]) if node.items else 2
            case ast.Any():
                return _max([self.pred(n) for n in node.items]) if node.items else 0
            case ast.Not():
                return 2 - self.pred(node.item)
            case ast.ToolIs():
                return 2 if node.tool == self.m.tool else 0
            case ast.ToolCategoryIn():
                return 2 if self.spec.category in node.categories else 0
            case ast.LabelAtLeast():
                present = self._has_arg(node.path)
                if z3.is_false(present):
                    return 0
                return z3.If(z3.And(present, self.label_var(node.path) >= int(node.level)), 2, 0)
            case ast.Fact():
                return self.m.fact(node.name)
            case (
                ast.ArgExists()
                | ast.ArgCompare()
                | ast.LabelHasTag()
                | ast.SourceKindIn()
                | ast.PurposeIs()
                | ast.ConsentCovers()
                | ast.MandatePresent()
                | ast.MandateCovers()
                | ast.ApprovalPresent()
                | ast.AmountExceeds()
            ):
                return self.free(node)
        raise TypeError(f"z3 translation: unhandled predicate node {type(node).__name__}")

    def build(self, policy: ast.CompiledPolicy) -> ToolModel:
        m = self.m
        for name, arg in self.spec.args.items():
            if arg.sink:
                self.label_var(f"/{name}")
        fired: list[z3.ArithRef | int] = [0]
        for rule in policy.rules:
            value = self.pred(rule.when)
            m.rule_values[rule.id] = value
            fired.append(z3.If(value != 0, int(rule.then), 0))
        m.decision = _max(fired)
        m.ml = z3.Int(f"ML_{m.tool}")
        m.constraints.append(z3.And(m.ml >= 0, m.ml <= int(Decision.DENY)))
        m.final = _max([m.decision, m.ml])
        return m


def translate_tool(policy: ast.CompiledPolicy, tool: str) -> ToolModel:
    return _Translator(policy, tool).build(policy)


def translate(policy: ast.CompiledPolicy) -> dict[str, ToolModel]:
    """Z3 encoding of every declared tool of ``policy``."""
    return {tool: translate_tool(policy, tool) for tool in policy.tools}
