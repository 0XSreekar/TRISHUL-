"""``POST /prove`` support: prove the live policy, or a separately compiled unsafe fixture.

The unsafe fixture (``trishul/fixtures/unsafe_policy``: the live policy minus its taint rules) is
compiled into its own ``CompiledPolicy``. It is used only for the proof and for one sandboxed
replay evaluation; the gateway's live policy object is never touched.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from trishul.contracts.calls import SourceMetadata, ToolCall, ToolCategory
from trishul.contracts.labels import Label, Level, SourceRef
from trishul.policy.ast import CompiledPolicy
from trishul.policy.compiler import compile_files
from trishul.policy.evaluator import EvalContext, evaluate
from trishul.verify.invariants import prove_all

UNSAFE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "unsafe_policy"
POLICIES = ("live", "unsafe_fixture")
_TRUE_FACTS = (
    "mandate_sig_valid",
    "mandate_time_valid",
    "mandate_nonce_fresh",
    "payee_in_mandate",
    "amount_within_payee_cap",
    "amount_within_per_txn_cap",
    "amount_within_daily_cap",
    "category_matches",
)


def replay(unsafe: CompiledPolicy, live: CompiledPolicy) -> dict[str, Any]:
    """One concrete injection attempt (payment to a payee scraped from an untrusted document,
    with a valid mandate and caps) evaluated under both policies."""
    now = datetime(2026, 9, 30, 9, 0, tzinfo=UTC)
    payee, amount = "refund.desk@ybl", 450_000
    call = ToolCall(
        call_id="replay_1",
        server="upi",
        tool="pay_upi",
        args={"payee_vpa": payee, "amount_paise": amount},
        arg_labels={
            "/payee_vpa": Label.make(
                Level.UNTRUSTED, sources=[SourceRef(kind="document", id="inv_injected")]
            ),
            "/amount_paise": Label.make(
                Level.TRUSTED_USER, sources=[SourceRef(kind="user", id="task")]
            ),
        },
        principal="user_demo",
        task_id="replay_task",
        declared_category=ToolCategory.PAYMENT,
        source=SourceMetadata(),
        ts=now,
    )
    facts: dict[str, bool | None] = dict.fromkeys(_TRUE_FACTS, True)
    facts.update(approval_valid=False, approval_binding_mismatch=False)
    ctx = EvalContext(now=now, facts=facts)
    return {
        "call": {
            "tool": "pay_upi",
            "args": {"payee_vpa": payee, "amount_paise": amount},
            "labels": {"payee_vpa": "UNTRUSTED", "amount_paise": "TRUSTED_USER"},
        },
        "decision_under_unsafe": evaluate(unsafe, call, ctx).decision.name,
        "decision_under_live": evaluate(live, call, ctx).decision.name,
    }


def prove_policy(which: str, live: CompiledPolicy) -> dict[str, Any]:
    if which not in POLICIES:
        raise ValueError("policy must be 'live' or 'unsafe_fixture'")
    target = live if which == "live" else compile_files([UNSAFE_DIR])
    if which == "unsafe_fixture" and target.digest == live.digest:
        raise RuntimeError("unsafe_fixture is identical to the live policy; refusing to prove")
    out = prove_all(target)
    return {
        "policy": which,
        "result": out["result"],
        "solver": "z3",
        "policy_digest": target.digest,
        "live_policy_digest": live.digest,
        "property": out.get("property"),
        "per_invariant": out["per_invariant"],
        "solve_ms": round(sum(float(r.get("solve_ms", 0)) for r in out["per_invariant"]), 3),
        "replay": replay(target, live) if which == "unsafe_fixture" else None,
    }
