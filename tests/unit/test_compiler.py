import random
from pathlib import Path

import pytest
import yaml

from tests.conftest import POLICY_DIR
from trishul.policy.ast import CompiledPolicy
from trishul.policy.compiler import PolicyCompileFailure, compile_files, compile_sources

BASE = """\
version: 1
id: test.policy
tools:
  pay:
    category: PAYMENT
    args:
      payee: {type: string, required: true}
      amount: {type: integer}
rules:
  - id: TEST.RULE.ONE
    stage: LABEL
    then: DENY
    explain: "one"
    when:
      label_at_least: {arg: /payee, level: UNTRUSTED}
"""


def errors_of(*texts: str) -> list[tuple[str, int, int, str]]:
    sources = [(f"f{i}.yaml", t) for i, t in enumerate(texts)]
    with pytest.raises(PolicyCompileFailure) as info:
        compile_sources(sources)
    return [(e.path, e.line, e.col, e.message) for e in info.value.errors]


def test_valid_policy_compiles_with_digest() -> None:
    policy = compile_sources([("a.yaml", BASE)])
    assert isinstance(policy, CompiledPolicy)
    assert len(policy.digest) == 64
    assert CompiledPolicy.model_validate_json(policy.canonical()) == policy


def test_example_policies_compile() -> None:
    policy = compile_files([POLICY_DIR])
    assert {r.id for r in policy.rules} >= {"PAYSHIELD.TAINT.UNTRUSTED_PAYEE"}


def test_compile_is_deterministic() -> None:
    assert (
        compile_sources([("a.yaml", BASE)]).canonical()
        == compile_sources([("a.yaml", BASE)]).canonical()
    )


def _shuffle(node: object, rng: random.Random) -> object:
    if isinstance(node, dict):
        items = [(k, _shuffle(v, rng)) for k, v in node.items()]
        rng.shuffle(items)
        return dict(items)
    if isinstance(node, list):
        return [_shuffle(v, rng) for v in node]
    return node


def test_digest_independent_of_key_rule_and_file_order() -> None:
    files = {p.name: yaml.safe_load(p.read_text()) for p in sorted(POLICY_DIR.glob("*.yaml"))}
    reference = compile_sources([(n, yaml.safe_dump(d)) for n, d in files.items()]).digest
    for seed in range(15):
        rng = random.Random(seed)
        shuffled = []
        for name, doc in files.items():
            doc = _shuffle(doc, rng)
            assert isinstance(doc, dict)
            rules = list(doc["rules"])
            rng.shuffle(rules)
            doc["rules"] = rules
            shuffled.append((name, yaml.safe_dump(doc, sort_keys=False)))
        rng.shuffle(shuffled)
        assert compile_sources(shuffled).digest == reference


def test_content_change_changes_digest() -> None:
    changed = BASE.replace('explain: "one"', 'explain: "two"')
    assert compile_sources([("a", BASE)]).digest != compile_sources([("a", changed)]).digest


def test_then_allow_is_error_with_location() -> None:
    errs = errors_of(BASE.replace("then: DENY", "then: ALLOW"))
    assert errs == [("f0.yaml", 12, 5, "rules may only escalate: 'then' must be STEP_UP or DENY")]


def test_duplicate_rule_ids_across_files_and_within() -> None:
    dup = BASE + BASE.split("rules:\n")[1]
    errs = errors_of(dup)
    assert any("duplicate rule id 'TEST.RULE.ONE'" in m and line == 16 for _, line, _, m in errs)
    other = BASE.replace("id: test.policy", "id: test.other")
    errs = errors_of(BASE, other)
    assert any(path == "f1.yaml" and "duplicate rule id" in m for path, _, _, m in errs)


def test_undeclared_arg_path_is_error_at_path_location() -> None:
    errs = errors_of(BASE.replace("/payee", "/nope"))
    assert len(errs) == 1
    _, line, col, msg = errs[0]
    assert (line, col) == (15, 24) and "'/nope'" in msg


def test_undeclared_tool_reference_is_error() -> None:
    text = BASE.replace(
        "label_at_least: {arg: /payee, level: UNTRUSTED}",
        "all:\n        - tool: ghost\n        - arg_exists: /payee",
    )
    errs = errors_of(text)
    assert any("undeclared tool 'ghost'" in m for *_, m in errs)


def test_errors_are_collected_not_first_only() -> None:
    bad_rule = BASE.replace("then: DENY", "then: ALLOW").replace("stage: LABEL", "stage: BOGUS")
    second = BASE.split("rules:\n")[1].replace("TEST.RULE.ONE", "TEST.RULE.TWO")
    errs = errors_of(bad_rule + second.replace("/payee", "/nope"))
    assert len(errs) == 3


def test_yaml_syntax_error_located() -> None:
    errs = errors_of("version: 1\nid: [unclosed\n")
    assert len(errs) == 1 and errs[0][1] >= 2


def test_schema_errors_located_unknown_key_and_type() -> None:
    errs = errors_of(BASE.replace("stage: LABEL", "stage: LABEL\n    bogus: 1"))
    assert any((line == 14 and "bogus" in m) or "bogus" in m for _, line, _, m in errs)
    errs = errors_of(BASE.replace("version: 1", "version: 2"))
    assert errs[0][1] == 1


def test_duplicate_yaml_keys_and_float_values_rejected() -> None:
    assert any("duplicate key" in m for *_, m in errors_of(BASE + "id: again\n"))
    text = BASE.replace(
        "label_at_least: {arg: /payee, level: UNTRUSTED}",
        "arg_compare: {arg: /amount, op: gt, value: 1.5}",
    )
    assert any("floats are not allowed" in m for *_, m in errors_of(text))


def test_unknown_predicate_and_multi_key_predicate() -> None:
    text = BASE.replace("label_at_least: {arg: /payee, level: UNTRUSTED}", "frobnicate: 1")
    assert any("unknown predicate 'frobnicate'" in m for *_, m in errors_of(text))
    text = BASE.replace(
        "label_at_least: {arg: /payee, level: UNTRUSTED}",
        "tool: pay\n      arg_exists: /payee",
    )
    assert any("exactly one key" in m for *_, m in errors_of(text))


def test_conflicting_tool_definitions_across_files() -> None:
    other = (
        BASE.replace("id: test.policy", "id: test.other")
        .replace("TEST.RULE.ONE", "TEST.RULE.TWO")
        .replace("amount: {type: integer}", "amount: {type: string}")
    )
    assert any("conflicts" in m for *_, m in errors_of(BASE, other))


def test_identical_tool_in_two_files_merges() -> None:
    other = BASE.replace("id: test.policy", "id: test.other").replace(
        "TEST.RULE.ONE", "TEST.RULE.TWO"
    )
    assert len(compile_sources([("a", BASE), ("b", other)]).rules) == 2


def test_missing_file_and_no_input_are_errors(tmp_path: Path) -> None:
    with pytest.raises(PolicyCompileFailure):
        compile_files([tmp_path / "missing.yaml"])
    with pytest.raises(PolicyCompileFailure):
        compile_sources([])
