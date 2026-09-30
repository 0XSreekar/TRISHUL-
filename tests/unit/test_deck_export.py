# SPDX-License-Identifier: Apache-2.0
"""`trishul bench --export-deck`: deterministic and traceable to bench/results.json."""

import json
import re
from pathlib import Path

from trishul.bench.deck import RESULTS, export_deck, render_deck

NUM = re.compile(r"-?\d+(?:\.\d+)?")


def _numbers(obj: object, acc: set[str]) -> set[str]:
    if isinstance(obj, dict):
        for v in obj.values():
            _numbers(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _numbers(v, acc)
    elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
        acc.add(json.dumps(obj))
    elif isinstance(obj, str):
        acc.update(NUM.findall(obj))
    return acc


def test_export_is_deterministic(tmp_path: Path) -> None:
    a = export_deck(RESULTS, tmp_path / "a.md").read_text()
    b = export_deck(RESULTS, tmp_path / "b.md").read_text()
    assert a == b
    assert a == render_deck(json.loads(RESULTS.read_text()))


def test_deck_contains_no_number_absent_from_json(tmp_path: Path) -> None:
    doc = json.loads(RESULTS.read_text())
    allowed = _numbers(doc, set())
    text = export_deck(RESULTS, tmp_path / "d.md").read_text()
    rows = [ln for ln in text.splitlines() if ln.startswith("| ") and "JSON path" not in ln]
    assert rows
    for ln in rows:
        _, value, path = (c.strip() for c in ln.strip("|").split("|"))
        assert path.startswith("`$")  # every row cites its JSON path
        if value.startswith("NOT RUN"):
            continue
        for n in NUM.findall(value):
            assert n in allowed, f"{n} not in results.json ({ln})"


def test_missing_path_is_not_run_not_invented() -> None:
    text = render_deck({"git_commit": "x", "generated_at": "y"})
    assert "NOT RUN" in text
    assert not re.search(r"\| \d", text)
