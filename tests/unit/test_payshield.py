"""PayShield: signed mandates, facts and the policy rules that consume them."""

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from tests.conftest import POLICY_DIR, TRUSTED, UNTRUSTED
from trishul.approvals import ApprovalService
from trishul.contracts.calls import SourceMetadata, ToolCall, ToolCategory
from trishul.contracts.decisions import Decision
from trishul.crypto.keys import KeyRing
from trishul.domains.payshield import (
    FACT_NAMES,
    MandatePayee,
    SignedMandate,
    issue_mandate,
    payshield_facts,
    spent_today,
    store_mandate,
)
from trishul.policy.compiler import compile_files
from trishul.policy.evaluator import EvalContext, evaluate
from trishul.servers.upi import preview_pay_upi
from trishul.store.db import DEMO_NOW, DEMO_PRINCIPAL, connect, iso, reset, transaction
from trishul.store.ids import IdGen

ACME = "acme.supplies@okbank"
EVIL = "acme.supp1ies@okbank"
POLICY = compile_files([POLICY_DIR])
NOW = DEMO_NOW


class Env:
    def __init__(self) -> None:
        self.conn: sqlite3.Connection = connect(":memory:")
        self.ids: IdGen = reset(self.conn)
        self.keys = KeyRing.from_seed(42)
        self.approvals = ApprovalService(self.conn, self.keys, self.ids, clock=lambda: NOW)

    def mandate(self, **kw: object) -> SignedMandate:
        args: dict[str, object] = {
            "principal": DEMO_PRINCIPAL,
            "payees": [MandatePayee(vpa=ACME, name="Acme", cap=1_000_000)],
            "per_txn_cap": 500_000,
            "daily_cap": 800_000,
            "categories": ["PAYMENT"],
            "nbf": NOW - timedelta(days=1),
            "exp": NOW + timedelta(days=30),
            "nonce": "n-1",
        }
        args.update(kw)
        return issue_mandate(self.keys, **args)  # type: ignore[arg-type]

    def store(self, m: SignedMandate) -> str:
        return store_mandate(self.conn, m, now=NOW)

    def call(self, payee: str = ACME, amount: int = 450_000, task: str = "t1") -> ToolCall:
        return ToolCall(
            call_id="c1",
            server="upi",
            tool="pay_upi",
            args={"payee_vpa": payee, "amount_paise": amount},
            arg_labels={"/payee_vpa": TRUSTED, "/amount_paise": TRUSTED},
            principal=DEMO_PRINCIPAL,
            task_id=task,
            source=SourceMetadata(),
            ts=NOW,
        )

    def facts(self, call: ToolCall, now: datetime = NOW) -> dict[str, bool | None]:
        return payshield_facts(
            call, ToolCategory.PAYMENT, self.conn, self.keys, self.approvals, now
        )

    def decide(self, call: ToolCall, now: datetime = NOW) -> tuple[Decision, list[str]]:
        v = evaluate(POLICY, call, EvalContext(now=now, facts=self.facts(call, now)))
        return v.decision, [r.rule_id for r in v.reasons]

    def spend(self, amount: int) -> None:
        with transaction(self.conn):
            self.conn.execute(
                "INSERT INTO ledger(txn_id, principal_id, account_id, payee_vpa, amount_paise,"
                " balance_after, ts) VALUES (?,?,?,?,?,?,?)",
                (self.ids.new("txn"), DEMO_PRINCIPAL, "acct_demo", ACME, amount, 0, iso(NOW)),
            )


@pytest.fixture
def env() -> Env:
    return Env()


def test_trusted_normal_payment_allowed(env: Env) -> None:
    env.store(env.mandate())
    call = env.call()
    facts = env.facts(call)
    assert set(facts) == set(FACT_NAMES)
    assert all(facts[k] is True for k in FACT_NAMES[:8])
    assert env.decide(call) == (Decision.ALLOW, [])


def test_no_mandate_denied(env: Env) -> None:
    decision, rules = env.decide(env.call())
    assert decision == Decision.DENY
    assert "PAYSHIELD.MANDATE.SIGNATURE" in rules


def test_signature_tamper_denied(env: Env) -> None:
    m = env.mandate()
    env.store(m.model_copy(update={"daily_cap": 99_000_000, "per_txn_cap": 99_000_000}))
    decision, rules = env.decide(env.call())
    assert decision == Decision.DENY
    assert env.facts(env.call())["mandate_sig_valid"] is False
    assert "PAYSHIELD.MANDATE.SIGNATURE" in rules


def test_wrong_key_denied(env: Env) -> None:
    env.store(env.mandate(key_id="approver"))
    assert env.facts(env.call())["mandate_sig_valid"] is False


def test_expired_mandate_denied(env: Env) -> None:
    env.store(env.mandate(nbf=NOW - timedelta(days=10), exp=NOW - timedelta(seconds=1)))
    decision, rules = env.decide(env.call())
    assert decision == Decision.DENY and "PAYSHIELD.MANDATE.TIME" in rules


def test_not_yet_valid_and_boundaries(env: Env) -> None:
    env.store(env.mandate(nbf=NOW + timedelta(seconds=1), exp=NOW + timedelta(days=1)))
    assert env.facts(env.call())["mandate_time_valid"] is False
    env2 = Env()
    env2.store(env2.mandate(nbf=NOW, exp=NOW + timedelta(seconds=1)))
    assert env2.facts(env2.call())["mandate_time_valid"] is True  # nbf <= now
    assert env2.facts(env2.call(), NOW + timedelta(seconds=1))["mandate_time_valid"] is False


def test_replayed_nonce_denied(env: Env) -> None:
    env.store(env.mandate(nonce="dup"))
    assert env.decide(env.call())[0] == Decision.ALLOW
    # a different (validly signed) mandate re-using the nonce
    env.store(env.mandate(nonce="dup", per_txn_cap=900_000))
    decision, rules = env.decide(env.call())
    assert decision == Decision.DENY and "PAYSHIELD.MANDATE.REPLAY" in rules


def test_storing_same_mandate_twice_is_not_replay(env: Env) -> None:
    m = env.mandate()
    env.store(m)
    env.store(m)
    assert env.facts(env.call())["mandate_nonce_fresh"] is True


def test_payee_swap_denied(env: Env) -> None:
    env.store(env.mandate())
    decision, rules = env.decide(env.call(payee=EVIL))
    assert decision == Decision.DENY and "PAYSHIELD.MANDATE.PAYEE" in rules


def test_category_mismatch_denied(env: Env) -> None:
    env.store(env.mandate(categories=["COMMUNICATION"]))
    decision, rules = env.decide(env.call())
    assert decision == Decision.DENY and "PAYSHIELD.MANDATE.CATEGORY" in rules


def test_per_txn_cap_step_up(env: Env) -> None:
    env.store(env.mandate(daily_cap=5_000_000))
    decision, rules = env.decide(env.call(amount=500_001))
    assert (decision, rules) == (Decision.STEP_UP, ["PAYSHIELD.CAP.PER_TXN"])
    assert env.decide(env.call(amount=500_000))[0] == Decision.ALLOW  # at the cap is fine


def test_payee_cap_step_up(env: Env) -> None:
    payee = MandatePayee(vpa=ACME, name="Acme", cap=100_000)
    env.store(env.mandate(payees=[payee]))
    assert env.decide(env.call(amount=100_001))[1] == ["PAYSHIELD.CAP.PAYEE"]


def test_daily_cap_uses_real_ledger(env: Env) -> None:
    env.store(env.mandate())
    env.spend(400_000)
    assert spent_today(env.conn, DEMO_PRINCIPAL, NOW) == 400_000
    assert env.decide(env.call(amount=400_000)) == (Decision.ALLOW, [])
    decision, rules = env.decide(env.call(amount=400_001))
    assert (decision, rules) == (Decision.STEP_UP, ["PAYSHIELD.CAP.DAILY"])
    # yesterday's spend does not count
    assert spent_today(env.conn, DEMO_PRINCIPAL, NOW + timedelta(days=1)) == 0


def test_approval_lifts_cap_but_arg_swap_denied(env: Env) -> None:
    env.store(env.mandate())
    big = env.call(amount=700_000)
    assert env.decide(big)[0] == Decision.STEP_UP
    token = env.approvals.approve(env.approvals.request(big), "sreekar")
    assert token.call_digest == big.call_digest()
    assert env.decide(big) == (Decision.ALLOW, [])
    swapped = env.call(amount=750_000)
    decision, rules = env.decide(swapped)
    assert decision == Decision.DENY and "PAYSHIELD.APPROVAL.BINDING_MISMATCH" in rules
    # same amount, different payee (also not in mandate)
    decision, rules = env.decide(env.call(payee=EVIL, amount=700_000))
    assert decision == Decision.DENY and "PAYSHIELD.APPROVAL.BINDING_MISMATCH" in rules


def test_approval_never_overrides_signature(env: Env) -> None:
    env.store(env.mandate().model_copy(update={"per_txn_cap": 9_999_999}))
    big = env.call(amount=700_000)
    env.approvals.approve(env.approvals.request(big), "sreekar")
    decision, rules = env.decide(big)
    assert decision == Decision.DENY and "PAYSHIELD.MANDATE.SIGNATURE" in rules


def test_untrusted_invoice_payee_blocked(env: Env) -> None:
    env.store(env.mandate())
    call = env.call().model_copy(
        update={"arg_labels": {"/payee_vpa": UNTRUSTED, "/amount_paise": TRUSTED}}
    )
    decision, rules = env.decide(call)
    assert decision == Decision.DENY and rules == ["PAYSHIELD.TAINT.UNTRUSTED_PAYEE"]


def test_untrusted_amount_blocked(env: Env) -> None:
    env.store(env.mandate())
    call = env.call().model_copy(
        update={"arg_labels": {"/payee_vpa": TRUSTED, "/amount_paise": UNTRUSTED}}
    )
    assert env.decide(call) == (Decision.DENY, ["PAYSHIELD.TAINT.UNTRUSTED_AMOUNT"])


def test_malformed_amount_is_unknown_not_allowed(env: Env) -> None:
    env.store(env.mandate())
    call = env.call().model_copy(update={"args": {"payee_vpa": ACME, "amount_paise": True}})
    facts = env.facts(call)
    assert facts["amount_within_per_txn_cap"] is None
    assert env.decide(call)[0] != Decision.ALLOW


def test_sink_flags_declared() -> None:
    args = POLICY.tools["pay_upi"].args
    assert args["payee_vpa"].sink and args["amount_paise"].sink


def test_preview_pay_upi_does_not_commit(env: Env) -> None:
    before = env.conn.execute("SELECT balance_paise FROM accounts").fetchone()[0]
    out = env.conn
    result = preview_pay_upi(out, ACME, 123_400)
    assert result["balance_after"] == before - 123_400
    assert "1234.00" in result["summary"] and ACME in result["summary"]
    assert env.conn.execute("SELECT balance_paise FROM accounts").fetchone()[0] == before
    assert env.conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0] == 0
    assert not env.conn.in_transaction


def test_preview_insufficient_funds_raises_and_cleans_up(env: Env) -> None:
    from trishul.servers.upi import PaymentError

    with pytest.raises(PaymentError):
        preview_pay_upi(env.conn, ACME, 10**12)
    assert not env.conn.in_transaction
    assert UTC  # keep import used
