# SPDX-License-Identifier: Apache-2.0
"""Whole-log verification: exact first bad leaf plus every stored signed tree head."""

import sqlite3

from pydantic import BaseModel, ConfigDict

from trishul.audit import merkle
from trishul.audit.log import SignedTreeHead, sth_from_row
from trishul.crypto.keys import KeyRing, purpose_of


class VerifyResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    ok: bool
    size: int
    bad_index: int | None = None
    invalid_sths: tuple[int, ...] = ()


def verify_sth(sth: SignedTreeHead, keys: KeyRing) -> bool:
    return purpose_of(sth.key_id) == "tree-head-signer" and keys.verify(
        sth.key_id, sth.signed_payload(), sth.sig
    )


def verify(conn: sqlite3.Connection, keys: KeyRing) -> VerifyResult:
    """Recompute each leaf hash from its payload (first mismatch -> ``bad_index``), then check
    every stored STH against the recomputed tree and its signature."""
    rows = conn.execute("SELECT idx, payload, leaf_hash FROM audit_leaves ORDER BY idx").fetchall()
    bad_index: int | None = None
    actual: list[bytes] = []
    for position, row in enumerate(rows):
        computed = merkle.leaf_hash(bytes(row["payload"]))
        actual.append(computed)
        tampered = row["idx"] != position or merkle.hexd(computed) != row["leaf_hash"]
        if bad_index is None and tampered:
            bad_index = position
    invalid: list[int] = []
    for head_row in conn.execute("SELECT * FROM tree_heads ORDER BY size").fetchall():
        sth = sth_from_row(head_row)
        good = (
            0 < sth.size <= len(actual)
            and merkle.hexd(merkle.mth(actual[: sth.size])) == sth.root
            and verify_sth(sth, keys)
        )
        if not good:
            invalid.append(sth.size)
    return VerifyResult(
        ok=bad_index is None and not invalid,
        size=len(rows),
        bad_index=bad_index,
        invalid_sths=tuple(invalid),
    )
