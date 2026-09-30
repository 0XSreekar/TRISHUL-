# SPDX-License-Identifier: Apache-2.0
"""Out-of-band step-up approvals bound to a call digest (spec section 5).

Approval is only reachable from the CLI/REST/console, never through an MCP tool or voice.
Tokens are Ed25519-signed (JCS payload), expire after ``ttl`` and are single use.
"""

import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

from trishul.contracts.authz import ApprovalToken
from trishul.contracts.calls import ToolCall
from trishul.contracts.canonical import canonical_json
from trishul.crypto.keys import KeyRing
from trishul.store.db import iso, parse_iso, transaction
from trishul.store.ids import IdGen

DEFAULT_TTL_SECONDS = 120


class ApprovalCheck(NamedTuple):
    valid: bool
    binding_mismatch: bool
    token: ApprovalToken | None


class ApprovalError(Exception):
    """Invalid approval state transition (unknown id, already decided...)."""


def token_payload(token: ApprovalToken) -> dict[str, object]:
    """The signed body of a token (everything except the signature)."""
    return {
        "token_id": token.token_id,
        "call_digest": token.call_digest,
        "scope": token.scope,
        "approver": token.approver,
        "issued_at": iso(token.issued_at),
        "expires_at": iso(token.expires_at),
        "nonce": token.nonce,
    }


def _now() -> datetime:
    return datetime.now(UTC)


class ApprovalService:
    def __init__(
        self,
        conn: sqlite3.Connection,
        keys: KeyRing,
        ids: IdGen,
        *,
        key_id: str = "approver",
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self.conn = conn
        self.keys = keys
        self.ids = ids
        self.key_id = key_id
        self.ttl = timedelta(seconds=ttl_seconds)
        self.clock = clock

    def request(self, call: ToolCall) -> str:
        """Create a pending approval for exactly this call; returns ``approval_id``."""
        approval_id = self.ids.new("apr")
        canonical_call = canonical_json(
            {
                "server": call.server,
                "tool": call.tool,
                "args": call.args,
                "principal": call.principal,
                "task_id": call.task_id,
            }
        )
        self.conn.execute(
            "INSERT INTO approvals(approval_id, task_id, tool, call_digest, canonical_call,"
            " status, created_ts) VALUES (?,?,?,?,?,'pending',?)",
            (
                approval_id,
                call.task_id,
                call.tool,
                call.call_digest(),
                canonical_call,
                iso(self.clock()),
            ),
        )
        return approval_id

    def get(self, approval_id: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self.conn.execute(
            "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        return row

    def pending(self) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT * FROM approvals WHERE status = 'pending' ORDER BY created_ts, approval_id"
            )
        )

    def approve(self, approval_id: str, approver: str) -> ApprovalToken:
        """Sign a token for the digest recorded at request time."""
        with transaction(self.conn):
            row = self.get(approval_id)
            if row is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            if row["status"] != "pending":
                raise ApprovalError(f"approval {approval_id} is already {row['status']}")
            issued = self.clock().astimezone(UTC).replace(microsecond=0)
            token = ApprovalToken(
                token_id=self.ids.new("tok"),
                call_digest=row["call_digest"],
                scope=row["tool"],
                approver=approver,
                issued_at=issued,
                expires_at=issued + self.ttl,
                nonce=self.ids.new("nonce"),
            )
            signature = self.keys.sign(self.key_id, token_payload(token))
            signed = token.model_copy(update={"signature": signature})
            body = {**token_payload(signed), "signature": signature}
            self.conn.execute(
                "UPDATE approvals SET status='approved', decided_ts=?, approver=?, token=?,"
                " token_id=? WHERE approval_id=?",
                (
                    iso(issued),
                    approver,
                    json.dumps(body, sort_keys=True),
                    signed.token_id,
                    approval_id,
                ),
            )
        return signed

    def reject(self, approval_id: str, approver: str = "") -> None:
        with transaction(self.conn):
            row = self.get(approval_id)
            if row is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            if row["status"] != "pending":
                raise ApprovalError(f"approval {approval_id} is already {row['status']}")
            self.conn.execute(
                "UPDATE approvals SET status='rejected', decided_ts=?, approver=?"
                " WHERE approval_id=?",
                (iso(self.clock()), approver or None, approval_id),
            )

    def _load_token(self, raw: str) -> ApprovalToken | None:
        try:
            body = json.loads(raw)
            return ApprovalToken(
                token_id=body["token_id"],
                call_digest=body["call_digest"],
                scope=body["scope"],
                approver=body["approver"],
                issued_at=parse_iso(body["issued_at"]),
                expires_at=parse_iso(body["expires_at"]),
                nonce=body["nonce"],
                signature=body["signature"],
            )
        except (ValueError, KeyError, TypeError):
            return None

    def check(self, call: ToolCall, now: datetime) -> ApprovalCheck:
        """valid iff an approved, unconsumed, unexpired token for (task, tool) verifies and is
        bound to this exact call digest; mismatch iff such tokens exist but none match."""
        digest = call.call_digest()
        rows = self.conn.execute(
            "SELECT token FROM approvals WHERE status='approved' AND consumed_ts IS NULL"
            " AND task_id=? AND tool=? ORDER BY decided_ts, approval_id",
            (call.task_id, call.tool),
        ).fetchall()
        live = False
        for row in rows:
            token = self._load_token(row["token"] or "")
            if token is None or not token.issued_at <= now < token.expires_at:
                continue
            live = True
            signature_ok = token.signature is not None and self.keys.verify(
                self.key_id, token_payload(token), token.signature
            )
            if signature_ok and token.call_digest == digest:
                return ApprovalCheck(True, False, token)
        return ApprovalCheck(False, live, None)

    def consume(self, token_id: str) -> bool:
        """Mark a token spent after execution. False if unknown or already consumed."""
        cur = self.conn.execute(
            "UPDATE approvals SET consumed_ts=? WHERE token_id=? AND consumed_ts IS NULL",
            (iso(self.clock()), token_id),
        )
        return cur.rowcount == 1
