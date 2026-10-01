# SPDX-License-Identifier: Apache-2.0
"""The acceptance runner never reports PASS for a missing, skipped or failing test."""

import ast
from pathlib import Path

from tests.acceptance import CRITERIA, FAIL, NOT_RUN, PASS, Criterion, evaluate, label

CRIT = Criterion("3", "t", ("tests/x.py::test_a", "tests/x.py::test_b"))
COLLECTED = {"tests/x.py::test_a", "tests/x.py::test_b[p1]"}


def test_all_passed_is_pass() -> None:
    out = evaluate(
        CRIT,
        COLLECTED,
        lambda n: {"tests/x.py::test_a": "PASSED", "tests/x.py::test_b[p1]": "PASSED"},
    )
    assert out.status == PASS


def test_missing_test_is_not_run_never_pass() -> None:
    out = evaluate(CRIT, {"tests/x.py::test_a"}, lambda n: {"tests/x.py::test_a": "PASSED"})
    assert out.status == NOT_RUN
    assert "test not present: tests/x.py::test_b" in out.text


def test_skipped_is_not_run() -> None:
    res = {"tests/x.py::test_a": "PASSED", "tests/x.py::test_b[p1]": "SKIPPED: no models"}
    out = evaluate(CRIT, COLLECTED, lambda n: res)
    assert out.status == NOT_RUN
    assert "no models" in out.text


def test_failure_wins_and_empty_results_fail() -> None:
    res = {"tests/x.py::test_a": "FAILED", "tests/x.py::test_b[p1]": "PASSED"}
    assert evaluate(CRIT, COLLECTED, lambda n: res).status == FAIL
    assert evaluate(CRIT, COLLECTED, lambda n: {}).status == FAIL


def test_registry_covers_1_to_17_and_supplementary() -> None:
    keys = [c.key for c in CRITERIA]
    assert keys[:17] == [str(i) for i in range(1, 18)]
    assert keys[17:] == ["S-OFF", "S-RT", "S-WS"]
    assert label("3") == "AT-03"


def test_every_registered_function_node_carries_its_marker() -> None:
    root = Path(__file__).resolve().parents[2]
    for crit in CRITERIA:
        for node in crit.nodes:
            if "::" not in node:
                continue
            path, func = node.split("::")
            if not (root / path).is_file():
                continue
            tree = ast.parse((root / path).read_text())
            fn = next(
                n
                for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == func
            )
            marks = {
                ast.literal_eval(d.args[0])
                for d in fn.decorator_list
                if isinstance(d, ast.Call)
                and ast.unparse(d.func) == "pytest.mark.acceptance"
                and d.args
            }
            want = int(crit.key) if crit.key.isdigit() else crit.key
            assert want in marks, f"{node} lacks @pytest.mark.acceptance({want!r})"
