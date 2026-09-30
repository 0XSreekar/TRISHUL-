"""DPDP report: every PurposeLock audit event with a Merkle inclusion proof and a signed head."""

import json
import sqlite3
from typing import Any

from trishul.audit import merkle
from trishul.audit.log import AuditLog, InclusionProof, SignedTreeHead
from trishul.audit.verify import verify_sth
from trishul.crypto.jcs import jcs
from trishul.crypto.keys import KeyRing

DOMAIN = "purposelock"


def dpdp_report(conn: sqlite3.Connection, keys: KeyRing) -> dict[str, Any]:
    """Build the report from real audit leaves. Signs a head for the current size if ``keys``
    holds the gateway private key, else uses the latest stored STH; events beyond that head
    cannot be anchored and are listed in ``unanchored``."""
    log = AuditLog(conn, keys)
    try:
        sth: SignedTreeHead | None = log.sth_now() if log.size() else None
    except KeyError:
        sth = log.latest_sth()
    entries: list[dict[str, Any]] = []
    unanchored: list[int] = []
    for row in conn.execute("SELECT idx, payload FROM audit_leaves ORDER BY idx"):
        try:
            event = json.loads(bytes(row["payload"]))
        except ValueError:
            continue
        if not isinstance(event, dict) or event.get("domain") != DOMAIN:
            continue
        if sth is None or row["idx"] >= sth.size:
            unanchored.append(int(row["idx"]))
            continue
        proof = log.inclusion_proof(int(row["idx"]), sth.size)
        entries.append({"index": int(row["idx"]), "event": event, "proof": proof.model_dump()})
    return {
        "report": "dpdp",
        "domain": DOMAIN,
        "sth": None if sth is None else sth.model_dump(),
        "entries": entries,
        "unanchored": unanchored,
    }


def verify_dpdp_report(report: dict[str, Any], public_keys: KeyRing) -> bool:
    """Independently re-check signature of the head, each event's leaf hash and its proof."""
    try:
        sth_raw = report["sth"]
        entries = report["entries"]
        if sth_raw is None:
            return not entries
        sth = SignedTreeHead.model_validate(sth_raw, strict=False)
        if not verify_sth(sth, public_keys):
            return False
        seen: set[int] = set()
        for entry in entries:
            proof = InclusionProof.model_validate(entry["proof"], strict=False)
            event = entry["event"]
            if event.get("domain") != DOMAIN or entry["index"] != proof.index:
                return False
            if proof.index in seen or proof.tree_size != sth.size or proof.root != sth.root:
                return False
            seen.add(proof.index)
            if merkle.hexd(merkle.leaf_hash(jcs(event))) != proof.leaf_hash:
                return False
            if not proof.check():
                return False
        return True
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
