import json
from pathlib import Path

import pytest

from tests.conftest import POLICY_DIR, TRUSTED, UNTRUSTED, make_call, make_ctx
from trishul.cli.main import main


def test_compile_prints_json_and_digest(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["policy", "compile", str(POLICY_DIR)]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    doc = json.loads(lines[0])
    assert lines[1] == f"digest: {doc['digest']}"


def test_compile_error_exit_1_with_location(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 1\nid: x.y\nrules:\n  - id: A.B\n    stage: LABEL\n    then: ALLOW\n"
        "    explain: e\n    when: {const: true}\n"
    )
    assert main(["policy", "compile", str(bad)]) == 1
    err = capsys.readouterr().err
    assert f"{bad}:6:5:" in err and "escalate" in err


def test_eval_prints_verdict(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    call = make_call(
        "pay_upi",
        {"payee_vpa": "a@b", "amount_paise": 1},
        {"/payee_vpa": UNTRUSTED, "/amount_paise": TRUSTED},
    )
    bare = tmp_path / "bare.json"
    bare.write_text(call.model_dump_json())
    assert main(["policy", "eval", str(POLICY_DIR), str(bare)]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "DENY"

    full = tmp_path / "full.json"
    full.write_text(
        json.dumps(
            {"call": call.model_dump(mode="json"), "context": make_ctx().model_dump(mode="json")}
        )
    )
    assert main(["policy", "eval", str(POLICY_DIR), str(full)]) == 0
    assert json.loads(capsys.readouterr().out)["reasons"][0]["rule_id"] == (
        "PAYSHIELD.TAINT.UNTRUSTED_PAYEE"
    )


def test_eval_unreadable_call_exit_2(tmp_path: Path) -> None:
    junk = tmp_path / "junk.json"
    junk.write_text("{nope")
    assert main(["policy", "eval", str(POLICY_DIR), str(junk)]) == 2
