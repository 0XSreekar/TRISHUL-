"""AT-16: bench/results.json is schema-valid and honest; the UI has no metric literals."""

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

from trishul.bench.agentdojo_adapter import not_run

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "bench" / "schema.json"
RESULTS = ROOT / "bench" / "results.json"
UI = ROOT / "Landing page and dashboard implementation"
UI_FILES = ("Trishul-Console.dc.html", "Trishul-Landing.dc.html", "support.js")

METRIC_WORDS = re.compile(
    r"p99|p95|p50|latency|attack success|\basr\b|utility|\beer\b|blocked|accuracy|recall", re.I
)
# a numeric literal shaped like a measurement: "12 ms", "4%", or a decimal such as 0.0
METRIC_NUMBER = re.compile(
    r"(?<![\w.#-])\d+(?:\.\d+)?\s?(?:ms|%)(?!\w)|(?<![\w.#-])\d+\.\d+(?![\w.])"
)


def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _results() -> dict:
    assert RESULTS.exists(), "run `trishul bench --seed 42` to generate bench/results.json"
    return json.loads(RESULTS.read_text(encoding="utf-8"))


def test_schema_is_valid_json_schema() -> None:
    _validator()


def test_results_validate_against_schema() -> None:
    errors = sorted(_validator().iter_errors(_results()), key=lambda e: list(e.path))
    assert not errors, "; ".join(f"{list(e.path)}: {e.message}" for e in errors[:5])


def test_india_suite_size_and_categories() -> None:
    india = _results()["suites"]["india"]
    assert india["attacks"] >= 30 and india["benign"] >= 30
    required = {
        "upi_payee_swap", "invoice_injection", "pii_exfil_email", "purpose_spoofing",
        "approval_swap", "mandate_tampering", "replayed_voice", "cloned_voice",
    }  # fmt: skip
    assert required <= set(india["per_category"])


def test_not_run_is_honest() -> None:
    ag = _results()["suites"]["agentdojo"]
    if ag["status"] == "not_run":
        assert ag["reason"].strip() and ag["with_trishul"] is None and ag["without"] is None
    voice = _results()["voice"]
    if voice["status"] == "partial":
        assert voice["eer"] is None


def test_schema_rejects_bad_documents() -> None:
    doc = _results()
    v = _validator()
    bad = json.loads(json.dumps(doc))
    bad["suites"]["agentdojo"] = {**not_run(""), "reason": ""}
    assert list(v.iter_errors(bad))
    bad = json.loads(json.dumps(doc))
    bad["suites"]["india"]["attacks"] = 3
    assert list(v.iter_errors(bad))
    bad = json.loads(json.dumps(doc))
    del bad["latency"]["ml_off"]
    assert list(v.iter_errors(bad))


def _ui_violations() -> list[str]:
    hits: list[str] = []
    for name in UI_FILES:
        path = UI / name
        for no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            text = re.sub(r"style=\"[^\"]*\"|style=\{\{[^}]*\}\}", "", line)
            if METRIC_WORDS.search(text) and METRIC_NUMBER.search(text):
                hits.append(f"{name}:{no}")
    return hits


def test_ui_has_no_hardcoded_metric_literals() -> None:
    assert _ui_violations() == []


def test_metric_literal_detector_catches_a_literal() -> None:
    sample = "<span>p99 latency 12 ms</span>"
    assert METRIC_WORDS.search(sample) and METRIC_NUMBER.search(sample)
    layout = '<div style="width:50%;height:12px">latency</div>'
    stripped = re.sub(r"style=\"[^\"]*\"", "", layout)
    assert not METRIC_NUMBER.search(stripped)
