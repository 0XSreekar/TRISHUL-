# SPDX-License-Identifier: Apache-2.0
"""PurposeLock: consent registry, purpose-bound facts, minimisation and response labelling.

Purpose comes only from the bound task (trusted channel). Anything an agent supplies as a
``purpose`` argument is stripped and ignored. Facts are ``True``/``False``/``None`` (unknown);
policy rules treat unknown like false.
"""

import json
import re
import sqlite3
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, JsonValue

from trishul.contracts.calls import ToolCall
from trishul.contracts.labels import Label, Level, SourceRef, Tag
from trishul.domains.pii import FIELD_TAGS, label_pii
from trishul.store.db import iso, parse_iso, transaction

DOMAIN = "purposelock"
CATEGORY = "customer_data"
IGNORED_AGENT_PURPOSE = "PURPOSELOCK.PURPOSE.IGNORED_AGENT_VALUE"

# Reviewed constants: purpose -> tools that may touch personal data. ``send_email`` is further
# restricted to the data subject's own address; ``export_records`` is allowed for no purpose.
PURPOSE_ALLOWED_TOOLS: Mapping[str, frozenset[str]] = {
    "order_support": frozenset({"read_customer_data", "send_email"}),
    "payment_processing": frozenset({"read_customer_data"}),
    "payment_reminders": frozenset({"read_customer_data", "send_email"}),
    "marketing": frozenset(),
}
# Response field allowlist per purpose (CRM records). Unknown purpose => nothing survives.
PURPOSE_FIELD_ALLOWLIST: Mapping[str, frozenset[str]] = {
    "order_support": frozenset({"id", "customer_id", "name", "order_status", "city", "email"}),
    "payment_processing": frozenset({"id", "customer_id", "name", "pan"}),
    "payment_reminders": frozenset({"id", "customer_id", "name", "email", "phone"}),
    "marketing": frozenset({"id", "customer_id", "city"}),
}
_STRING_ARGS = ("to", "subject", "body", "destination")


class ConsentRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    consent_id: str
    principal_id: str
    category: str
    purposes: tuple[str, ...]
    exp: str
    withdrawn_at: str | None = None

    def active_for(self, purpose: str | None, now: datetime) -> bool:
        if purpose is None or self.withdrawn_at is not None or purpose not in self.purposes:
            return False
        try:
            return now < parse_iso(self.exp)
        except ValueError:
            return False


def _record(row: sqlite3.Row) -> ConsentRecord:
    purposes = json.loads(row["purposes"])
    return ConsentRecord(
        consent_id=row["consent_id"],
        principal_id=row["principal_id"],
        category=row["category"],
        purposes=tuple(str(p) for p in purposes),
        exp=row["exp"],
        withdrawn_at=row["withdrawn_at"],
    )


def consent_epoch(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT epoch FROM consent_epoch WHERE id = 1").fetchone()
    return 0 if row is None else int(row["epoch"])


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ConsentRegistry:
    def __init__(self, conn: sqlite3.Connection, clock: Callable[[], datetime] = _utc_now) -> None:
        self.conn = conn
        self.clock = clock

    def get(self, consent_id: str) -> ConsentRecord | None:
        row = self.conn.execute(
            "SELECT * FROM consents WHERE consent_id = ?", (consent_id,)
        ).fetchone()
        return None if row is None else _record(row)

    def list(self, principal_id: str | None = None) -> list[ConsentRecord]:
        if principal_id is None:
            rows = self.conn.execute("SELECT * FROM consents ORDER BY consent_id").fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM consents WHERE principal_id = ? ORDER BY consent_id",
                (principal_id,),
            ).fetchall()
        return [_record(r) for r in rows]

    def epoch(self) -> int:
        return consent_epoch(self.conn)

    def withdraw(self, consent_id: str) -> ConsentRecord:
        """Set ``withdrawn_at`` (first withdrawal wins) and bump ``consent_epoch`` atomically."""
        with transaction(self.conn):
            row = self.conn.execute(
                "SELECT * FROM consents WHERE consent_id = ?", (consent_id,)
            ).fetchone()
            if row is None:
                raise KeyError(consent_id)
            if row["withdrawn_at"] is None:
                self.conn.execute(
                    "UPDATE consents SET withdrawn_at = ? WHERE consent_id = ?",
                    (iso(self.clock()), consent_id),
                )
            self.conn.execute("UPDATE consent_epoch SET epoch = epoch + 1 WHERE id = 1")
        record = self.get(consent_id)
        if record is None:  # pragma: no cover - row existed inside the transaction
            raise KeyError(consent_id)
        return record


def strip_agent_purpose(args: Mapping[str, JsonValue]) -> tuple[dict[str, JsonValue], bool]:
    """Drop any agent-supplied ``purpose`` argument. Returns ``(clean_args, ignored)``."""
    clean = {k: v for k, v in args.items() if k.lower() != "purpose"}
    return clean, len(clean) != len(args)


# --- facts ------------------------------------------------------------------------------


def _strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _strings(v)


def _norm(text: str) -> str:
    return text.strip().lower()


def _subjects(call: ToolCall, conn: sqlite3.Connection) -> list[str]:
    """Data-subject ids the call touches: explicit ids, else customers whose identifiers appear
    in the string args, else the call principal."""
    args = call.args
    if call.tool == "read_customer_data" and isinstance(args.get("customer_id"), str):
        return [str(args["customer_id"])]
    if call.tool == "export_records":
        ids = args.get("customer_ids")
        return [str(i) for i in ids] if isinstance(ids, list) else []
    haystack = " ".join(s for k in _STRING_ARGS for s in _strings(args.get(k))).lower()
    found: list[str] = []
    for row in conn.execute(
        "SELECT customer_id, principal_id, email, phone, pan, aadhaar FROM customers"
    ):
        idents = [row["email"], row["phone"], row["pan"], row["aadhaar"]]
        if any(i and _norm(str(i)) in haystack for i in idents):
            found.append(str(row["principal_id"] or row["customer_id"]))
    return found or [call.principal]


def _subject_email(conn: sqlite3.Connection, subject: str) -> str | None:
    row = conn.execute(
        "SELECT email FROM customers WHERE principal_id = ? OR customer_id = ?", (subject, subject)
    ).fetchone()
    return None if row is None or not row["email"] else _norm(str(row["email"]))


def _compute(
    call: ToolCall, purpose: str | None, conn: sqlite3.Connection, now: datetime
) -> tuple[dict[str, bool | None], datetime | None]:
    """Facts plus the earliest consent expiry they depend on (cache lifetime bound)."""
    if purpose is None:
        return {"consent_active": None, "sink_allowed_for_purpose": None}, None
    subjects = _subjects(call, conn)
    valid_until: datetime | None = None
    active = bool(subjects)
    registry = ConsentRegistry(conn)
    for subject in subjects:
        good = [
            c
            for c in registry.list(subject)
            if c.category == CATEGORY and c.active_for(purpose, now)
        ]
        if not good:
            active = False
            break
        exp = min(parse_iso(c.exp) for c in good)
        valid_until = exp if valid_until is None else min(valid_until, exp)
    allowed_tools = PURPOSE_ALLOWED_TOOLS.get(purpose, frozenset())
    sink_ok = call.tool in allowed_tools and bool(subjects)
    if sink_ok and call.tool == "send_email":
        to = call.args.get("to")
        sink_ok = isinstance(to, str) and all(
            _subject_email(conn, s) == _norm(to) for s in subjects
        )
    return {"consent_active": active, "sink_allowed_for_purpose": sink_ok}, valid_until


def purposelock_facts(
    call: ToolCall, task_purpose: str | None, conn: sqlite3.Connection, now: datetime
) -> dict[str, bool | None]:
    """``consent_active`` and ``sink_allowed_for_purpose`` (None if purpose is unknown)."""
    return _compute(call, task_purpose, conn, now)[0]


class DecisionCache:
    """Fact cache keyed by ``consent_epoch``: any withdrawal bumps the epoch, so the next lookup
    recomputes. Entries also expire at the earliest consent expiry they depend on."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self._epoch = consent_epoch(conn)
        self._entries: dict[
            tuple[str, str | None], tuple[dict[str, bool | None], datetime | None, datetime]
        ] = {}
        self.hits = 0
        self.misses = 0

    def facts(
        self, call: ToolCall, task_purpose: str | None, now: datetime
    ) -> dict[str, bool | None]:
        epoch = consent_epoch(self.conn)
        if epoch != self._epoch:
            self._entries.clear()
            self._epoch = epoch
        key = (call.call_digest(), task_purpose)
        hit = self._entries.get(key)
        if hit is not None:
            facts, until, computed_at = hit
            if computed_at <= now and (until is None or now < until):
                self.hits += 1
                return dict(facts)
        self.misses += 1
        facts, until = _compute(call, task_purpose, self.conn, now)
        self._entries[key] = (dict(facts), until, now)
        return facts


# --- minimisation, labelling, audit -----------------------------------------------------


def minimize(purpose: str | None, record: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Keep only the fields allowed for ``purpose``; returns ``(kept, sorted removed names)``."""
    allowed = PURPOSE_FIELD_ALLOWLIST.get(purpose or "", frozenset())
    kept = {k: v for k, v in record.items() if k in allowed}
    return kept, sorted(k for k in record if k not in allowed)


def response_tags(value: object) -> frozenset[Tag]:
    """PII tags from recognizers plus field-name mapping (a bare 'city' string is still PII)."""
    tags: set[Tag] = set(label_pii(value))

    def walk(v: object, depth: int = 0) -> None:
        if depth > 64:
            return
        if isinstance(v, Mapping):
            for key, item in v.items():
                tag = FIELD_TAGS.get(re.sub(r"[^a-z]", "", str(key).lower()))
                if tag is not None and item not in (None, "", [], {}):
                    tags.add(tag)
                walk(item, depth + 1)
        elif isinstance(v, list | tuple):
            for item in v:
                walk(item, depth + 1)

    walk(value)
    return frozenset(tags | ({Tag.PII} if tags else set()))


def label_response(
    value: object, *, source_id: str = "crm", extra_tags: Iterable[Tag] = ()
) -> Label:
    """Label for a CRM tool result: trusted-system, PII tags preserved from content and field
    names (plus any ``extra_tags`` the caller already carries)."""
    return Label.make(
        Level.TRUSTED_SYSTEM,
        sources=[SourceRef(kind="tool_result", id=source_id)],
        tags=[*response_tags(value), *extra_tags],
    )


def audit_event(
    call: ToolCall,
    purpose: str | None,
    facts: Mapping[str, bool | None],
    decision: str,
    reasons: Iterable[str],
) -> dict[str, object]:
    """Audit payload for a PurposeLock decision (no argument values, only the call digest)."""
    return {
        "domain": DOMAIN,
        "type": "decision",
        "call_id": call.call_id,
        "tool": call.tool,
        "principal": call.principal,
        "task_id": call.task_id,
        "purpose": purpose,
        "call_digest": call.call_digest(),
        "facts": dict(facts),
        "decision": decision,
        "reasons": sorted(reasons),
    }
