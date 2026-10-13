import pytest

from tests.conftest import make_call, make_ctx
from trishul.contracts.decisions import Decision
from trishul.policy.compiler import PolicyCompileFailure, compile_sources
from trishul.policy.evaluator import evaluate

SRC = """\
version: 1
id: t.facts
tools:
  pay:
    category: PAYMENT
    args:
      payee: {type: string, required: true, sink: true}
      note: {type: string}
rules:
  - id: T.FACT.SIG
    stage: MANDATE
    then: DENY
    explain: "signature must be valid"
    when:
      not: {fact: mandate_sig_valid}
"""


def policy():  # type: ignore[no-untyped-def]
    return compile_sources([("t.yaml", SRC)])


def call():  # type: ignore[no-untyped-def]
    return make_call("pay", {"payee": "a@upi"})


def test_sink_flag_compiles_and_changes_digest() -> None:
    p = policy()
    assert p.tools["pay"].args["payee"].sink is True
    assert p.tools["pay"].args["note"].sink is False
    other = compile_sources([("t.yaml", SRC.replace("sink: true", "sink: false"))])
    assert other.digest != p.digest


@pytest.mark.parametrize(
    ("facts", "decision", "unknown"),
    [
        ({"mandate_sig_valid": True}, Decision.ALLOW, None),
        ({"mandate_sig_valid": False}, Decision.DENY, False),
        ({"mandate_sig_valid": None}, Decision.DENY, True),
        ({}, Decision.DENY, True),
        ({"other_fact": True}, Decision.DENY, True),
    ],
)
def test_fact_tri_semantics(
    facts: dict[str, bool | None], decision: Decision, unknown: bool | None
) -> None:
    v = evaluate(policy(), call(), make_ctx(facts=facts))
    assert v.decision == decision
    if unknown is not None:
        assert v.reasons[-1].unknown is unknown


def test_bad_fact_names_rejected() -> None:
    for bad in ("Bad-Name", "", "1x", "[a]"):
        src = SRC.replace(
            "fact: mandate_sig_valid", f"fact: '{bad}'" if bad != "[a]" else "fact: [a]"
        )
        with pytest.raises(PolicyCompileFailure, match="fact must be"):
            compile_sources([("t.yaml", src)])


def test_sink_must_be_boolean() -> None:
    with pytest.raises(PolicyCompileFailure):
        compile_sources([("t.yaml", SRC.replace("sink: true", "sink: yes please"))])
