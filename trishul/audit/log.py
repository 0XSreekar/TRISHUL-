"""Append-only Merkle audit log on SQLite with signed tree heads (spec section 8)."""

import sqlite3
from collections.abc import Callable, Mapping
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict

from trishul.audit import merkle
from trishul.crypto.jcs import jcs
from trishul.crypto.keys import KeyRing
from trishul.store.db import iso, transaction

DEFAULT_STH_EVERY = 16
SECRET_KEYS = frozenset(
    {"secret", "password", "passwd", "api_key", "private_key", "seed", "sig", "signature"}
)


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class SignedTreeHead(_Model):
    size: int
    root: str
    ts: str
    sig: str
    key_id: str

    def signed_payload(self) -> dict[str, object]:
        return {"size": self.size, "root": self.root, "ts": self.ts}


class AppendResult(_Model):
    index: int
    leaf_hash: str
    tree_size: int
    root: str
    sth: SignedTreeHead | None = None


class InclusionProof(_Model):
    index: int
    tree_size: int
    leaf_hash: str
    path: tuple[str, ...]
    root: str

    def check(self) -> bool:
        return merkle.verify_inclusion(
            merkle.unhex(self.leaf_hash),
            self.index,
            self.tree_size,
            [merkle.unhex(p) for p in self.path],
            merkle.unhex(self.root),
        )


class ConsistencyProof(_Model):
    first: int
    second: int
    first_root: str
    second_root: str
    path: tuple[str, ...]

    def check(self) -> bool:
        return merkle.verify_consistency(
            self.first,
            self.second,
            merkle.unhex(self.first_root),
            merkle.unhex(self.second_root),
            [merkle.unhex(p) for p in self.path],
        )


def redact(value: object) -> object:
    """Drop secret-bearing keys recursively (digests and ids are kept)."""
    if isinstance(value, Mapping):
        return {k: redact(v) for k, v in value.items() if str(k).lower() not in SECRET_KEYS}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value


def sth_from_row(row: sqlite3.Row) -> SignedTreeHead:
    return SignedTreeHead(
        size=row["size"], root=row["root"], ts=row["ts"], sig=row["sig"], key_id=row["key_id"]
    )


def _now() -> datetime:
    return datetime.now(UTC)


class AuditLog:
    def __init__(
        self,
        conn: sqlite3.Connection,
        keys: KeyRing,
        *,
        key_id: str | None = None,  # default: the active tree-head-signer key
        sth_every: int = DEFAULT_STH_EVERY,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        if sth_every < 1:
            raise ValueError("sth_every must be >= 1")
        self.conn = conn
        self.keys = keys
        self.key_id = key_id
        self.sth_every = sth_every
        self.clock = clock

    # --- reading ------------------------------------------------------------------------
    def size(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM audit_leaves").fetchone()[0])

    def leaf_hashes(self, limit: int | None = None) -> list[bytes]:
        rows = self.conn.execute(
            "SELECT leaf_hash FROM audit_leaves ORDER BY idx LIMIT ?",
            (-1 if limit is None else int(limit),),
        ).fetchall()
        return [merkle.unhex(r["leaf_hash"]) for r in rows]

    def root(self, size: int | None = None) -> bytes:
        return merkle.mth(self.leaf_hashes(size))

    def payload(self, index: int) -> bytes:
        row = self.conn.execute(
            "SELECT payload FROM audit_leaves WHERE idx = ?", (index,)
        ).fetchone()
        if row is None:
            raise IndexError(index)
        return bytes(row["payload"])

    def latest_sth(self) -> SignedTreeHead | None:
        row = self.conn.execute("SELECT * FROM tree_heads ORDER BY size DESC LIMIT 1").fetchone()
        return None if row is None else sth_from_row(row)

    def sth_for(self, size: int) -> SignedTreeHead | None:
        row = self.conn.execute("SELECT * FROM tree_heads WHERE size = ?", (size,)).fetchone()
        return None if row is None else sth_from_row(row)

    # --- writing ------------------------------------------------------------------------
    def _sign_head(self, size: int, root: bytes) -> SignedTreeHead:
        root_hex, ts = merkle.hexd(root), iso(self.clock())
        kid = self.key_id or self.keys.active_kid("tree-head-signer")
        sig = self.keys.sign(kid, {"size": size, "root": root_hex, "ts": ts})
        self.conn.execute(
            "INSERT OR REPLACE INTO tree_heads(size, root, ts, sig, key_id) VALUES (?,?,?,?,?)",
            (size, root_hex, ts, sig, kid),
        )
        return SignedTreeHead(size=size, root=root_hex, ts=ts, sig=sig, key_id=kid)

    def append(self, event: Mapping[str, object]) -> AppendResult:
        """Redact, canonicalise (JCS) and append in one ``BEGIN IMMEDIATE`` transaction."""
        payload = jcs(redact(event))
        leaf = merkle.leaf_hash(payload)
        with transaction(self.conn):
            index = int(self.conn.execute("SELECT COUNT(*) FROM audit_leaves").fetchone()[0])
            self.conn.execute(
                "INSERT INTO audit_leaves(idx, payload, leaf_hash) VALUES (?,?,?)",
                (index, payload, merkle.hexd(leaf)),
            )
            size = index + 1
            root = merkle.mth(self.leaf_hashes())
            sth = self._sign_head(size, root) if size % self.sth_every == 0 else None
        return AppendResult(
            index=index,
            leaf_hash=merkle.hexd(leaf),
            tree_size=size,
            root=merkle.hexd(root),
            sth=sth,
        )

    def sth_now(self) -> SignedTreeHead:
        """Sign the current head (idempotent if this size already has an STH)."""
        with transaction(self.conn):
            size = self.size()
            existing = self.sth_for(size)
            if existing is not None:
                return existing
            return self._sign_head(size, merkle.mth(self.leaf_hashes()))

    # --- proofs -------------------------------------------------------------------------
    def inclusion_proof(self, index: int, size: int | None = None) -> InclusionProof:
        leaves = self.leaf_hashes(size)
        path = merkle.inclusion_proof(index, leaves)
        return InclusionProof(
            index=index,
            tree_size=len(leaves),
            leaf_hash=merkle.hexd(leaves[index]),
            path=tuple(merkle.hexd(p) for p in path),
            root=merkle.hexd(merkle.mth(leaves)),
        )

    def consistency_proof(self, first: int, second: int | None = None) -> ConsistencyProof:
        leaves = self.leaf_hashes(second)
        path = merkle.consistency_proof(first, leaves)
        return ConsistencyProof(
            first=first,
            second=len(leaves),
            first_root=merkle.hexd(merkle.mth(leaves[:first])),
            second_root=merkle.hexd(merkle.mth(leaves)),
            path=tuple(merkle.hexd(p) for p in path),
        )
