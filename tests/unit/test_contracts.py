import pytest
from pydantic import ValidationError

from tests.conftest import NOW, TRUSTED, UNTRUSTED, make_call
from trishul.contracts.audit import AuditLeaf, ProofResult, SignedTreeHead
from trishul.contracts.authz import ApprovalToken, Consent, Mandate
from trishul.contracts.calls import ToolCall, ToolResult
from trishul.contracts.canonical import CanonicalError, canonical_json, digest
from trishul.contracts.decisions import Decision, DecisionReason, Stage, Verdict
from trishul.contracts.labels import Label, Level, SourceRef, Tag
from trishul.contracts.lineage import LineageEdge, LineageGraph, LineageNode
from trishul.contracts.values import ABSENT, Redacted


def roundtrip[M: object](model: M) -> M:
    return type(model).model_validate_json(model.model_dump_json())  # type: ignore[attr-defined,no-any-return]


def test_canonical_json_is_sorted_compact_utf8() -> None:
    assert canonical_json({"b": 1, "a": [True, None, "é"]}) == '{"a":[true,null,"é"],"b":1}'
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})


@pytest.mark.parametrize("bad", [1.5, {"a": 0.0}, [float("nan")], {1: "x"}, object()])
def test_canonical_rejects_floats_and_non_json(bad: object) -> None:
    with pytest.raises(CanonicalError):
        canonical_json(bad)


def test_absent_null_empty_redacted_are_distinct() -> None:
    values = [ABSENT, None, "", [], {}, Redacted(reason="pii", digest=None)]
    for i, a in enumerate(values):
        for b in values[i + 1 :]:
            assert a != b
    assert canonical_json(Redacted(reason="x", digest=None).model_dump(mode="json")) == (
        '{"$redacted":true,"digest":null,"reason":"x"}'
    )


def test_label_roundtrip_sorted_and_pii_closure() -> None:
    label = Label.make(
        Level.UNTRUSTED,
        sources=[SourceRef(kind="web", id="b"), SourceRef(kind="email", id="a")],
        tags=[Tag.PII_AADHAAR],
    )
    assert Tag.PII in label.tags
    dumped = label.model_dump(mode="json")
    assert dumped["level"] == "UNTRUSTED"
    assert dumped["sources"] == [{"kind": "email", "id": "a"}, {"kind": "web", "id": "b"}]
    assert dumped["tags"] == ["PII", "PII_AADHAAR"]
    assert roundtrip(label) == label


def test_tool_call_roundtrip_and_digest_binds_semantics() -> None:
    call = make_call("pay_upi", {"payee_vpa": "a@b", "amount_paise": 100})
    assert roundtrip(call) == call
    other = make_call("pay_upi", {"payee_vpa": "a@b", "amount_paise": 101})
    assert call.call_digest() != other.call_digest()


def test_tool_call_rejects_floats() -> None:
    with pytest.raises((ValidationError, CanonicalError)):
        make_call("pay_upi", {"payee_vpa": "a@b", "amount_paise": 1.5})


def test_tool_call_rejects_naive_and_non_utc_timestamps_and_bad_pointers() -> None:
    good = make_call("t", {"a": 1}).model_dump(mode="json")
    for ts in ("2026-01-01T12:00:00", "2026-01-01T12:00:00+05:30"):
        with pytest.raises(ValidationError):
            ToolCall.model_validate_json(canonical_json({**good, "ts": ts}))
    with pytest.raises(ValidationError):
        make_call("t", {"a": 1}, {"a": TRUSTED})  # not a JSON pointer


def test_models_are_frozen_strict_and_forbid_extra() -> None:
    call = make_call("t", {"a": 1})
    with pytest.raises(ValidationError):
        call.tool = "x"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        ToolCall.model_validate_json(canonical_json({**call.model_dump(mode="json"), "x": 1}))
    with pytest.raises(ValidationError):
        Label(level=2)  # type: ignore[arg-type]  # strict: no int -> enum coercion


def test_tool_result_roundtrip() -> None:
    node = LineageNode(id="n1", kind="source", label=UNTRUSTED, ref="doc:1")
    result = ToolResult(call_id="c", value={"k": [1, None]}, label=UNTRUSTED, provenance=(node,))
    assert roundtrip(result) == result
    with pytest.raises((ValidationError, CanonicalError)):
        ToolResult(call_id="c", value={"k": 1.5}, label=UNTRUSTED)


def test_decision_ordering_and_combine() -> None:
    assert Decision.ALLOW < Decision.STEP_UP < Decision.DENY
    assert Decision.combine() == Decision.ALLOW
    assert Decision.combine(Decision.ALLOW, Decision.DENY, Decision.STEP_UP) == Decision.DENY


def _reason(rule_id: str, decision: Decision) -> DecisionReason:
    return DecisionReason(rule_id=rule_id, stage=Stage.LABEL, decision=decision, explanation="x")


def test_verdict_sorts_reasons_and_roundtrips() -> None:
    v = Verdict.build(
        [
            _reason("A.B", Decision.STEP_UP),
            _reason("Z.Z", Decision.DENY),
            _reason("A.A", Decision.DENY),
        ],
        "d" * 64,
    )
    assert [r.rule_id for r in v.reasons] == ["A.A", "Z.Z", "A.B"]
    assert v.decision == Decision.DENY
    assert roundtrip(v) == v
    with pytest.raises(ValidationError):
        Verdict(decision=Decision.ALLOW, reasons=v.reasons, policy_digest="x")


@pytest.mark.parametrize("rule_id", ["lower.case", "NODOT", "A..B", "A.b", ""])
def test_rule_id_regex_rejected(rule_id: str) -> None:
    with pytest.raises(ValidationError):
        _reason(rule_id, Decision.DENY)


def test_reason_evidence_must_not_contain_secrets() -> None:
    with pytest.raises(ValidationError):
        DecisionReason(
            rule_id="A.B", stage=Stage.LABEL, decision=Decision.DENY, explanation="x",
            evidence={"v": "ABCDE1234F"},
        )  # fmt: skip


def test_authz_and_audit_contracts_roundtrip_and_validate() -> None:
    later = NOW.replace(hour=13)
    token = ApprovalToken(
        token_id="t", call_digest="a" * 64, scope="s", approver="bob",
        issued_at=NOW, expires_at=later, nonce="n",
    )  # fmt: skip
    mandate = Mandate(
        mandate_id="m", principal="alice", payee_vpa="a@b", max_amount_paise=10, currency="INR",
        valid_from=NOW, valid_until=later, max_uses=1, nonce="n",
    )  # fmt: skip
    consent = Consent(
        consent_id="c", principal="alice", purpose="p", fields=frozenset({"b", "a"}),
        granted_at=NOW, status="active",
    )  # fmt: skip
    for model in (token, mandate, consent):
        assert roundtrip(model) == model
    assert consent.model_dump(mode="json")["fields"] == ["a", "b"]
    with pytest.raises(ValidationError):
        ApprovalToken(**{**token.model_dump(), "expires_at": NOW})
    with pytest.raises(ValidationError):
        Mandate(**{**mandate.model_dump(), "max_amount_paise": 0})
    with pytest.raises(ValidationError):
        Mandate(**{**mandate.model_dump(), "currency": "USD"})
    leaf = AuditLeaf(index=0, event_digest="a" * 64, ts=NOW)
    sth = SignedTreeHead(tree_size=1, root_hash="b" * 64, ts=NOW)
    proof = ProofResult(status="UNAVAILABLE", detail="no prover")
    for model2 in (leaf, sth, proof):
        assert roundtrip(model2) == model2
    with pytest.raises(ValidationError):
        ProofResult(status="UNSAT", detail="")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        AuditLeaf(index=-1, event_digest="a" * 64, ts=NOW)


def test_lineage_roundtrip() -> None:
    g = LineageGraph(
        nodes=(LineageNode(id="a", kind="sink", label=TRUSTED, ref="r"),),
        edges=(LineageEdge(src="a", dst="b", op="copy"),),
    )
    assert roundtrip(g) == g
