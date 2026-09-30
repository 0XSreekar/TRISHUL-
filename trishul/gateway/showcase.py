"""Phase 3 operator/showcase surface of ``Backend`` (kept apart from the core backend).

Everything here follows the API conventions of ``backend.py`` (``KeyError`` -> 404, ``ValueError``
-> 400) and is fail-closed: nothing on these paths can produce an ALLOW decision.
"""

import asyncio
import json
import logging
import socket
from typing import Any

from trishul.audit import merkle
from trishul.audit.verify import verify
from trishul.domains.payshield import SignedMandate, spent_today
from trishul.ollama import ollama_endpoint
from trishul.store.db import DEMO_NOW, iso, parse_iso
from trishul.verify.showcase import prove_policy

log = logging.getLogger("trishul.gateway")
MAX_LEAVES = 200


class ShowcaseMixin:
    # attributes provided by Backend
    p: Any
    loop: Any
    mcp: Any
    redteam: Any
    _control_seen: int

    def _run(self, fn: Any) -> Any: ...  # pragma: no cover - provided by Backend

    # --- mode -----------------------------------------------------------------------------
    def mode(self) -> dict[str, Any]:
        return self._run(self.p.mode_info)  # type: ignore[no-any-return]

    def set_mode(self, mode: str) -> dict[str, Any]:
        if mode not in ("on", "off"):
            raise ValueError("mode must be on or off")
        return self._run(lambda: self.p.set_mode(mode))  # type: ignore[no-any-return]

    # --- health ---------------------------------------------------------------------------
    def healthz(self) -> dict[str, Any]:
        return {"ok": True}

    def readyz(self) -> dict[str, Any]:
        def go() -> dict[str, Any]:
            checks: dict[str, str] = {}
            try:
                self.p.conn.execute("SELECT 1").fetchone()
                checks["db"] = "ok"
            except Exception:
                checks["db"] = "fail"
            checks["policy"] = "ok" if getattr(self.p.policy, "digest", "") else "fail"
            try:
                self.p.audit.root()
                checks["audit"] = "ok"
            except Exception:
                checks["audit"] = "fail"
            try:
                spoof = self.p.voice.spoof.available()
                asr = self.p.voice.asr.available()
                checks["voice_models"] = "available" if spoof and asr else "unavailable"
            except Exception:
                checks["voice_models"] = "unavailable"
            checks["ollama"] = _ollama()
            ready = all(checks[k] == "ok" for k in ("db", "policy", "audit"))
            return {"ready": ready, "checks": checks}

        return self._run(go)  # type: ignore[no-any-return]

    # --- mandates -------------------------------------------------------------------------
    def mandates(self) -> list[dict[str, Any]]:
        def go() -> list[dict[str, Any]]:
            now = self.p.clock()
            out: list[dict[str, Any]] = []
            rows = self.p.conn.execute("SELECT * FROM mandates ORDER BY rowid").fetchall()
            for row in rows:
                item: dict[str, Any] = {
                    "id": row["mandate_id"],
                    "principal": row["principal_id"],
                    "payee": None,
                    "payees": [],
                    "per_txn_cap": None,
                    "daily_cap": None,
                    "used_today": None,
                    "uses": None,
                    "max_uses": None,
                    "nbf": row["nbf"],
                    "exp": row["exp"],
                    "state": "invalid",
                }
                try:
                    m = SignedMandate.model_validate_json(row["body"])
                    sig_ok = self.p.keys.verify(m.key_id, m.signed_payload(), m.sig)
                    owner = self.p.conn.execute(
                        "SELECT mandate_id FROM mandate_nonces WHERE nonce=?", (m.nonce,)
                    ).fetchone()
                    if not sig_ok or owner is None or owner["mandate_id"] != row["mandate_id"]:
                        state = "invalid"
                    elif now < parse_iso(m.nbf):
                        state = "not_yet_valid"
                    elif now >= parse_iso(m.exp):
                        state = "expired"
                    else:
                        state = "valid"
                    uses = self.p.conn.execute(
                        "SELECT COUNT(*) FROM ledger WHERE principal_id=?", (m.principal,)
                    ).fetchone()[0]
                    item.update(
                        payee=", ".join(p.name for p in m.payees),
                        payees=[p.model_dump(mode="json") for p in m.payees],
                        per_txn_cap=m.per_txn_cap,
                        daily_cap=m.daily_cap,
                        used_today=spent_today(self.p.conn, m.principal, now),
                        uses=int(uses),
                        state=state,
                    )
                except Exception:
                    item["state"] = "invalid"
                out.append(item)
            return out

        return self._run(go)  # type: ignore[no-any-return]

    # --- audit explorer -------------------------------------------------------------------
    def audit_head(self) -> dict[str, Any]:
        def go() -> dict[str, Any]:
            size = self.p.audit.size()
            sth = self.p.audit.latest_sth()
            return {
                "size": size,
                "root": merkle.hexd(self.p.audit.root()),
                "sth": None if sth is None else sth.model_dump(),
            }

        return self._run(go)  # type: ignore[no-any-return]

    def audit_leaves(self, start: int = 0, limit: int = 50) -> dict[str, Any]:
        if start < 0 or limit < 1:
            raise ValueError("from must be >= 0 and limit >= 1")
        limit = min(limit, MAX_LEAVES)

        def go() -> dict[str, Any]:
            rows = self.p.conn.execute(
                "SELECT idx, payload, leaf_hash FROM audit_leaves WHERE idx>=?"
                " ORDER BY idx LIMIT ?",
                (start, limit),
            ).fetchall()
            leaves = []
            for r in rows:
                raw = bytes(r["payload"])
                try:
                    event: Any = json.loads(raw)
                except ValueError:
                    event = None
                leaves.append(
                    {
                        "idx": int(r["idx"]),
                        "leaf_hash": r["leaf_hash"],
                        "intact": merkle.hexd(merkle.leaf_hash(raw)) == r["leaf_hash"],
                        "event": event,
                    }
                )
            return {"from": start, "limit": limit, "size": self.p.audit.size(), "leaves": leaves}

        return self._run(go)  # type: ignore[no-any-return]

    def audit_inclusion(self, idx: int) -> dict[str, Any]:
        def go() -> dict[str, Any]:
            size = self.p.audit.size()
            if not 0 <= idx < size:
                raise KeyError(idx)
            proof = self.p.audit.inclusion_proof(idx)
            raw = self.p.audit.payload(idx)
            sth = self.p.audit.sth_for(proof.tree_size)
            return {
                **proof.model_dump(),
                "verified": proof.check(),
                "payload_intact": merkle.hexd(merkle.leaf_hash(raw)) == proof.leaf_hash,
                "sth": None if sth is None else sth.model_dump(),
            }

        return self._run(go)  # type: ignore[no-any-return]

    def audit_consistency(self, old: int) -> dict[str, Any]:
        def go() -> dict[str, Any]:
            size = self.p.audit.size()
            if not 1 <= old <= size:
                raise ValueError("old must be within 1..size")
            proof = self.p.audit.consistency_proof(old)
            return {**proof.model_dump(), "verified": proof.check()}

        return self._run(go)  # type: ignore[no-any-return]

    # --- proofs ---------------------------------------------------------------------------
    def prove(self, policy: str = "live") -> dict[str, Any]:
        before = self.p.policy.digest
        out = prove_policy(policy, self.p.policy)
        if self.p.policy.digest != before:  # pragma: no cover - live policy is never swapped
            raise RuntimeError("live policy changed during proof")
        summary = [
            {k: r[k] for k in ("id", "tool", "result", "solve_ms")} for r in out["per_invariant"]
        ]
        self._run(
            lambda: self.p.bus.publish(
                {
                    "type": "proof",
                    "policy": out["policy"],
                    "result": out["result"],
                    "policy_digest": out["policy_digest"],
                    "solve_ms": out["solve_ms"],
                    "per_invariant": summary,
                    "replay": out["replay"],
                }
            )
        )
        return out

    # --- ML toggle / control table ---------------------------------------------------------
    def _control_write(self, key: str, value: str, origin: str) -> None:
        self.p.conn.execute(
            "INSERT INTO control(key, value, origin, ts) VALUES (?,?,?,?)",
            (key, value, origin, iso(self.p.clock())),
        )

    def set_ml_cli(self, enabled: bool) -> None:
        """CLI path: apply + audit here, then leave a control row for the running gateway."""
        self.p.set_ml(enabled)
        self._control_write("ml", "on" if enabled else "off", "cli")

    def redteam_kill_cli(self, on: bool) -> dict[str, Any]:
        out = self.redteam.set_killed(on)
        self._control_write("redteam_killed", "1" if on else "0", "cli")
        return out  # type: ignore[no-any-return]

    def control_baseline(self) -> None:
        row = self.p.conn.execute("SELECT COALESCE(MAX(id), 0) FROM control").fetchone()
        self._control_seen = int(row[0])

    def poll_control(self) -> int:
        """Apply control rows written by other processes since the last poll. Returns count."""
        rows = self.p.conn.execute(
            "SELECT id, key, value FROM control WHERE id>? ORDER BY id", (self._control_seen,)
        ).fetchall()
        for row in rows:
            self._control_seen = int(row["id"])
            try:
                self._apply_control(str(row["key"]), str(row["value"]))
            except Exception:
                log.exception("control row failed")
        return len(rows)

    def _apply_control(self, key: str, value: str) -> None:
        bus = self.p.bus
        if key == "ml":
            enabled = value == "on"
            bus.publish({"type": "ml_state", "ml": enabled, "enabled": enabled})
        elif key == "redteam_killed":
            self.redteam.publish_stats()
        elif key == "mode":
            bus.publish({"type": "mode", **self.p.mode_info()})
        elif key == "reset":
            self._after_reset()

    def _after_reset(self) -> None:
        row = self.p.conn.execute("SELECT value FROM meta WHERE key='id_counter'").fetchone()
        self.p.reset_runtime(int(row["value"]) if row else 0)
        self.redteam.reset_limits()
        self.control_baseline()
        bus = self.p.bus
        bus.publish({"type": "mode", **self.p.mode_info()})
        enabled = self.p.ml_enabled()
        bus.publish({"type": "ml_state", "ml": enabled, "enabled": enabled})
        self.redteam.publish_stats()
        bus.publish({"type": "demo", "moment": 0, "step": "reset", "status": "done"})

    async def run_control_poller(self, interval: float = 0.5) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                self.poll_control()
            except Exception:
                log.exception("control poll failed")

    # --- demo reset ------------------------------------------------------------------------
    def demo_reset(self, seed: int = 42) -> dict[str, Any]:
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("seed must be an integer")
        if seed != self.p.ids.seed:
            raise ValueError("seed must match the running gateway (restart to change it)")

        def go() -> dict[str, Any]:
            from trishul.gateway.app import seed_demo_mandate
            from trishul.store.db import reset

            ids = reset(self.p.conn, seed=seed)
            seed_demo_mandate(self.p.conn, self.p.keys, now=DEMO_NOW)
            self.p.conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('id_counter', ?)",
                (str(ids.counter),),
            )
            self._after_reset()
            return {"reset": True, "seed": seed, "ids_issued": ids.counter, **self.p.mode_info()}

        return self._run(go)  # type: ignore[no-any-return]

    # --- report ----------------------------------------------------------------------------
    def verify_head(self) -> dict[str, Any]:
        result = verify(self.p.conn, self.p.keys)
        return {"ok": result.ok, "bad_index": result.bad_index, "size": result.size}


def _ollama() -> str:
    try:
        with socket.create_connection(ollama_endpoint(), timeout=0.15):
            return "available"
    except OSError:
        return "unavailable"
