# SPDX-License-Identifier: Apache-2.0
"""PayShield: signed mandates + facts for payment tools (spec section 4).

``payshield_facts`` is the guard: it verifies the mandate cryptographically, checks caps against
the real ledger and approval binding, and returns booleans for the policy ``fact:`` predicate.
A fact is ``None`` when it cannot be determined; the policy treats that as UNKNOWN (rule fires).
"""

import hashlib
import json
import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from trishul.approvals import ApprovalService
from trishul.contracts.calls import ToolCall, ToolCategory
from trishul.crypto.jcs import jcs
from trishul.crypto.keys import KeyRing, purpose_of
from trishul.store.db import iso, parse_iso

FACT_NAMES = (
    "mandate_sig_valid",
    "mandate_time_valid",
    "mandate_nonce_fresh",
    "payee_in_mandate",
    "amount_within_payee_cap",
    "amount_within_per_txn_cap",
    "amount_within_daily_cap",
    "category_matches",
    "approval_valid",
    "approval_binding_mismatch",
)


def _check_ts(value: str) -> str:
    parsed = parse_iso(value)
    if iso(parsed) != value:
        raise ValueError("timestamp must be RFC 3339 UTC with Z suffix, second precision")
    return value


class MandatePayee(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    vpa: str = Field(min_length=1)
    name: str
    cap: int = Field(gt=0)


class SignedMandate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    principal: str = Field(min_length=1)
    payees: tuple[MandatePayee, ...]
    per_txn_cap: int = Field(gt=0)
    daily_cap: int = Field(gt=0)
    categories: tuple[str, ...]
    nbf: str
    exp: str
    nonce: str = Field(min_length=1)
    key_id: str = Field(min_length=1)
    sig: str = Field(min_length=1)

    _ts = field_validator("nbf", "exp")(_check_ts)

    def signed_payload(self) -> dict[str, Any]:
        """The exact object the signature covers: the mandate without ``sig``."""
        return self.model_dump(mode="json", exclude={"sig"})

    def mandate_id(self) -> str:
        return "mnd_" + hashlib.sha256(jcs(self.model_dump(mode="json"))).hexdigest()[:16]


def issue_mandate(
    keys: KeyRing,
    *,
    principal: str,
    payees: Sequence[MandatePayee],
    per_txn_cap: int,
    daily_cap: int,
    categories: Sequence[str],
    nbf: datetime,
    exp: datetime,
    nonce: str,
    key_id: str | None = None,  # default: the active mandate-signer key
) -> SignedMandate:
    """Sign a mandate with Ed25519 over the JCS of its body (active ``mandate-signer`` key)."""
    key_id = key_id or keys.active_kid("mandate-signer")
    unsigned: dict[str, Any] = {
        "principal": principal,
        "payees": [p.model_dump(mode="json") for p in payees],
        "per_txn_cap": per_txn_cap,
        "daily_cap": daily_cap,
        "categories": list(categories),
        "nbf": iso(nbf),
        "exp": iso(exp),
        "nonce": nonce,
        "key_id": key_id,
    }
    signed = {**unsigned, "sig": keys.sign(key_id, unsigned)}
    return SignedMandate.model_validate_json(json.dumps(signed))


def store_mandate(conn: sqlite3.Connection, mandate: SignedMandate, *, now: datetime) -> str:
    """Persist a mandate (no verification here) and register its nonce. The first mandate to use
    a nonce owns it; a *different* mandate reusing it is a replay (``mandate_nonce_fresh``)."""
    mid = mandate.mandate_id()
    conn.execute(
        "INSERT OR IGNORE INTO mandates(mandate_id, principal_id, nonce, key_id, body, sig, nbf,"
        " exp, created_ts) VALUES (?,?,?,?,?,?,?,?,?)",
        (
            mid,
            mandate.principal,
            mandate.nonce,
            mandate.key_id,
            jcs(mandate.model_dump(mode="json")).decode("utf-8"),
            mandate.sig,
            mandate.nbf,
            mandate.exp,
            iso(now),
        ),
    )
    conn.execute(
        "INSERT OR IGNORE INTO mandate_nonces(nonce, mandate_id, ts) VALUES (?,?,?)",
        (mandate.nonce, mid, iso(now)),
    )
    return mid


def _load_latest(conn: sqlite3.Connection, principal: str) -> tuple[str, str] | None:
    row = conn.execute(
        "SELECT mandate_id, body FROM mandates WHERE principal_id=? ORDER BY rowid DESC LIMIT 1",
        (principal,),
    ).fetchone()
    return None if row is None else (str(row["mandate_id"]), str(row["body"]))


def spent_today(conn: sqlite3.Connection, principal: str, now: datetime) -> int:
    """Sum of ledger amounts for ``principal`` on the UTC calendar day of ``now``."""
    start = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    row = conn.execute(
        "SELECT COALESCE(SUM(amount_paise), 0) AS s FROM ledger WHERE principal_id=? AND ts>=?"
        " AND ts<?",
        (principal, iso(start), iso(start + timedelta(days=1))),
    ).fetchone()
    return int(row["s"])


def _int_arg(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def payshield_facts(
    call: ToolCall,
    task_category: ToolCategory | str,
    conn: sqlite3.Connection,
    keys: KeyRing,
    approvals: ApprovalService,
    now: datetime,
    *,
    payee_arg: str | None = "payee_vpa",
    amount_arg: str | None = "amount_paise",
) -> dict[str, bool | None]:
    """Compute the section 4 facts for a payment call. ``payee_arg``/``amount_arg`` name the
    tool's argument paths (``None`` = the tool has none, so the fact stays UNKNOWN => DENY).
    Never raises on malformed data: anything undeterminable is ``None`` (UNKNOWN => the policy
    rule fires)."""
    facts: dict[str, bool | None] = dict.fromkeys(FACT_NAMES)
    check = approvals.check(call, now)
    facts["approval_valid"] = check.valid
    facts["approval_binding_mismatch"] = check.binding_mismatch

    loaded = _load_latest(conn, call.principal)
    if loaded is None:
        return facts
    mandate_id, body = loaded
    try:
        mandate = SignedMandate.model_validate_json(body)
    except ValidationError:
        facts["mandate_sig_valid"] = False
        return facts

    facts["mandate_sig_valid"] = (
        purpose_of(mandate.key_id) == "mandate-signer"
        and mandate.principal == call.principal
        and keys.verify(mandate.key_id, mandate.signed_payload(), mandate.sig)
    )
    facts["mandate_time_valid"] = parse_iso(mandate.nbf) <= now < parse_iso(mandate.exp)
    owner = conn.execute(
        "SELECT mandate_id FROM mandate_nonces WHERE nonce=?", (mandate.nonce,)
    ).fetchone()
    facts["mandate_nonce_fresh"] = owner is not None and owner["mandate_id"] == mandate_id

    category = task_category.value if isinstance(task_category, ToolCategory) else task_category
    facts["category_matches"] = category in mandate.categories and (
        call.declared_category is None or call.declared_category == ToolCategory.PAYMENT
    )

    vpa = None if payee_arg is None else call.args.get(payee_arg)
    amount = None if amount_arg is None else _int_arg(call.args.get(amount_arg))
    payee = (
        next((p for p in mandate.payees if p.vpa == vpa), None) if isinstance(vpa, str) else None
    )
    if isinstance(vpa, str):
        facts["payee_in_mandate"] = payee is not None
    if amount is None or amount <= 0:
        return facts
    facts["amount_within_payee_cap"] = (
        None if not isinstance(vpa, str) else (payee is not None and amount <= payee.cap)
    )
    facts["amount_within_per_txn_cap"] = amount <= mandate.per_txn_cap
    facts["amount_within_daily_cap"] = (
        spent_today(conn, call.principal, now) + amount <= mandate.daily_cap
    )
    return facts
