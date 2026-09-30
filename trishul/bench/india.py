# SPDX-License-Identifier: Apache-2.0
"""India suite runner: replays ``bench/datasets/india_v1.json`` through the real gateway pipeline.

"With TRISHUL" runs the scenario with the pipeline ON. "Without TRISHUL" runs the same calls
through the OFF namespace (the pipeline's explicit unguarded demo mode), i.e. what would execute
if nothing stood in the way. Voice commands have no OFF endpoint (``voice_command`` is refused in
OFF mode), so voice scenarios are *not measurable* without TRISHUL and are excluded from the
"without" denominators rather than guessed.
"""

import base64
import json
import tempfile
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastmcp import Client

from trishul.crypto.keys import KeyRing
from trishul.domains.voice_adapters import ScriptedASR, SpoofResult
from trishul.domains.voicetrust import NonceService, VoiceTrust
from trishul.gateway.app import Gateway, build_gateway, seed_demo_mandate
from trishul.gateway.taint import EXTRACTORS
from trishul.store.db import DEMO_NOW, connect, reset

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "bench" / "datasets" / "india_v1.json"
AUDIO = ROOT / "bench" / "datasets" / "audio"

ML_CONFIGS: dict[str, dict[str, bool]] = {
    # ml: the ML stage (anomaly z-score + injection score signals); spoof: anti-spoof score fed in
    "rules_only": {"ml": False, "spoof": False},
    "rules_classifier": {"ml": True, "spoof": False},
    "full": {"ml": True, "spoof": True},
}


class Clock:
    def __init__(self) -> None:
        self.now = DEMO_NOW

    def __call__(self) -> Any:
        return self.now


class PhraseASR(ScriptedASR):
    """Scripted ASR: the dataset states what the (simulated) speaker said."""

    def __init__(self) -> None:
        super().__init__(None)

    def say(self, text: str | None, *, ran: bool = True) -> None:
        self._text, self._ran = text, ran


class ScriptedSpoof:
    """Anti-spoof stand-in whose score the dataset scripts per clip (``signal`` field)."""

    def __init__(self) -> None:
        self.value: float | None = None
        self.enabled = True

    def available(self) -> bool:
        return True

    def score(self, samples: object) -> SpoofResult:
        if not self.enabled or self.value is None:
            return SpoofResult(None, False, "scripted-spoof", None, None, "no score scripted")
        return SpoofResult(self.value, True, "scripted-spoof", "cpu", 0.0, "scripted (dataset)")


@dataclass
class Outcome:
    executed: bool | None  # None = not measurable
    detail: str = ""


@dataclass
class Trace:
    call_events: list[dict[str, Any]] = field(default_factory=list)


def load_dataset() -> dict[str, Any]:
    return json.loads(DATASET.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _sub(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        if set(value) == {"$var"}:
            return variables[value["$var"]]
        return {k: _sub(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_sub(v, variables) for v in value]
    return value


def _error_body(text: str) -> dict[str, Any]:
    try:
        return json.loads(text[text.index("{") :])  # type: ignore[no-any-return]
    except ValueError:
        return {}


class Runner:
    def __init__(self, seed: int, tmp: Path) -> None:
        self.seed = seed
        self.tmp = tmp
        self.counter = 0

    def _build(
        self, scenario: dict[str, Any], *, ml: bool, spoof_on: bool
    ) -> tuple[Gateway, Any, Clock, PhraseASR, ScriptedSpoof, list[dict[str, Any]]]:
        self.counter += 1
        conn = connect(self.tmp / f"b{self.counter}.db")
        ids = reset(conn, seed=self.seed)
        keys = KeyRing.from_seed(self.seed)
        clock = Clock()
        seed_demo_mandate(conn, keys, now=DEMO_NOW)
        for doc in scenario.get("docs", []):
            exists = conn.execute("SELECT 1 FROM documents WHERE name=?", (doc["name"],)).fetchone()
            if exists is None:
                conn.execute(
                    "INSERT INTO documents(doc_id, name, trust, mime, content) VALUES (?,?,?,?,?)",
                    (ids.new("doc"), doc["name"], doc["trust"], "text/html", doc["content"]),
                )
        asr, spoof = PhraseASR(), ScriptedSpoof()
        spoof.enabled = spoof_on
        voice = VoiceTrust(NonceService(), asr, spoof)
        gw = build_gateway(conn, ids, seed=self.seed, keys=keys, clock=clock, voice=voice)
        events: list[dict[str, Any]] = []
        original = gw.bus.publish

        def spy(event: dict[str, Any]) -> int:
            events.append(event)
            return original(event)

        gw.bus.publish = spy  # type: ignore[method-assign,assignment]
        if not ml:
            gw.pipeline.set_ml(False)
        t = scenario["task"]
        gw.bind_task(
            purpose=t["purpose"], category=t["category"], text=t["text"], params=t.get("params", {})
        )
        return gw, conn, clock, asr, spoof, events

    async def run(
        self, scenario: dict[str, Any], *, mode: str, ml: bool = True, spoof_on: bool = True
    ) -> tuple[Outcome, list[dict[str, Any]]]:
        """Run one scenario. ``mode`` is ``on`` or ``off``. Returns (outcome, call events)."""
        gw, conn, clock, asr, spoof, events = self._build(scenario, ml=ml, spoof_on=spoof_on)
        if mode == "off":
            gw.pipeline.set_mode("off")
        results: dict[str, dict[str, Any]] = {}  # step id -> {"ok", "data"}
        variables: dict[str, Any] = {}
        last_approval: str | None = None
        unmeasurable = False
        try:
            async with Client(gw.mcp) as client:
                for step in scenario["steps"]:
                    op = step["op"]
                    if op == "call":
                        args = _sub(step["args"], variables)
                        if mode == "off":  # unguarded tools ignore an agent-claimed purpose
                            args = {k: v for k, v in args.items() if k != "purpose"}
                        res = await client.call_tool(step["tool"], args, raise_on_error=False)
                        ok = not res.is_error
                        data: Any = res.structured_content
                        if not ok:
                            text = "".join(getattr(c, "text", "") for c in res.content)
                            body = _error_body(text)
                            last_approval = body.get("approval_id") or last_approval
                            data = body
                            if step.get("approve_if_step_up") and body.get("approval_id"):
                                gw.backend.resolve_approval(body["approval_id"], "approve", "bench")
                                res = await client.call_tool(
                                    step["tool"], args, raise_on_error=False
                                )
                                ok = not res.is_error
                                data = res.structured_content
                        results[step.get("id", f"s{len(results)}")] = {"ok": ok, "data": data}
                    elif op == "read_doc":
                        row = conn.execute(
                            "SELECT doc_id FROM documents WHERE name=?", (step["doc"],)
                        ).fetchone()
                        res = await client.call_tool(
                            "files_read_document", {"doc_id": row["doc_id"]}, raise_on_error=False
                        )
                        sc = res.structured_content or {}
                        variables[step["as"]] = sc if mode == "off" else sc.get("handle")
                    elif op == "extract":
                        src = variables[step["from"]]
                        if mode == "off":
                            variables[step["as"]] = EXTRACTORS[step["field"]](src.get("content"))
                        else:
                            res = await client.call_tool(
                                "extract_field",
                                {"handle": src, "field": step["field"]},
                                raise_on_error=False,
                            )
                            variables[step["as"]] = (res.structured_content or {}).get("handle")
                    elif op == "voice":
                        if mode == "off":
                            unmeasurable = True  # no OFF endpoint for voice
                            continue
                        args, _mode = self._voice_args(gw, asr, spoof, step)
                        res = await client.call_tool("voice_command", args, raise_on_error=False)
                        results[step.get("id", f"s{len(results)}")] = {
                            "ok": not res.is_error,
                            "data": res.structured_content,
                        }
                    elif op == "approve":
                        if mode == "on" and last_approval:
                            gw.backend.resolve_approval(last_approval, "approve", "bench")
                    elif op == "tamper_mandate":
                        row = conn.execute("SELECT mandate_id, body FROM mandates").fetchone()
                        body = row["body"]
                        for old, new in step["replace"]:
                            body = body.replace(old, new)
                        conn.execute(
                            "UPDATE mandates SET body=? WHERE mandate_id=?",
                            (body, row["mandate_id"]),
                        )
                    elif op == "delete_mandate":
                        conn.execute("DELETE FROM mandate_nonces")
                        conn.execute("DELETE FROM mandates")
                    elif op == "advance_days":
                        clock.now = clock.now + timedelta(days=step["days"])
                    else:
                        raise ValueError(f"unknown op {op}")
            if unmeasurable:
                return Outcome(None, "voice has no OFF endpoint"), events
            return self._judge(scenario, conn, results, mode), events
        finally:
            conn.close()

    def _voice_args(
        self, gw: Gateway, asr: PhraseASR, spoof: ScriptedSpoof, step: dict[str, Any]
    ) -> tuple[dict[str, Any], str]:
        session = gw.pipeline.session
        nonce = gw.backend.issue_voice_nonce(session)
        used = getattr(gw, "_bench_used", None)
        if used is None:
            used = gw._bench_used = {}  # type: ignore[attr-defined]
        mode = step.get("asr", "current")
        prev = used.get("last")
        if mode == "current":
            asr.say(f"please {nonce['phrase']} thanks")
        elif mode == "previous":
            stale = gw.backend.issue_voice_nonce(session)  # a phrase from another challenge
            asr.say(f"please {stale['phrase']} thanks")
        elif mode == "wrong":
            asr.say("please open the vault door thanks")
        elif mode == "unavailable":
            asr.say(None, ran=False)
        elif mode == "silent":
            asr.say("", ran=True)
        else:
            raise ValueError(f"unknown asr mode {mode}")
        nonce_id = nonce["nonce_id"]
        if step.get("nonce") == "reuse" and prev is not None:
            nonce_id = prev
        used["last"] = nonce_id
        spoof.value = step.get("spoof")
        clip = base64.b64encode((AUDIO / step["clip"]).read_bytes()).decode()
        return {"clip_b64": clip, "clip_id": f"clip_{len(used)}", "nonce_id": nonce_id}, mode

    def _judge(
        self, scenario: dict[str, Any], conn: Any, results: dict[str, Any], mode: str
    ) -> Outcome:
        out = scenario["outcome"]
        kind = out["type"]
        if kind == "ledger":
            table = "ledger" if mode == "on" else "ns_ledger"
            sql, params = f"SELECT COUNT(*) FROM {table} WHERE payee_vpa=?", [out["vpa"]]  # noqa: S608
            if out.get("amount_paise") is not None:
                sql += " AND amount_paise=?"
                params.append(out["amount_paise"])
            n = int(conn.execute(sql, params).fetchone()[0])
            return Outcome(n >= out.get("min_count", 1), f"{table} rows={n}")
        if mode == "off":
            step = out.get("step") or next(reversed(results), None)
            r = results.get(step) if step else None
            if kind == "step_has_key":
                return Outcome(bool(r and r["ok"] and out["key"] in json.dumps(r["data"])), "off")
            return Outcome(bool(r and r["ok"]), "off: step executed unguarded")
        if kind == "outbox":
            rows = conn.execute("SELECT to_addr, body FROM outbox").fetchall()
            hits = [
                r
                for r in rows
                if out.get("to", out.get("to_contains", "")) in r["to_addr"]
                and out.get("body_contains", "") in r["body"]
            ]
            return Outcome(len(hits) >= out.get("min_count", 1), f"outbox rows={len(hits)}")
        if kind == "step_ok":
            r = results.get(out["step"])
            return Outcome(bool(r and r["ok"]), "step ok" if r and r["ok"] else "step refused")
        if kind == "step_has_key":
            r = results.get(out["step"])
            has = bool(r and r["ok"] and out["key"] in json.dumps(r["data"]))
            return Outcome(has, f"key {out['key']} present={has}")
        raise ValueError(f"unknown outcome type {kind}")


def rate(num: int, den: int) -> float | None:
    return None if den == 0 else round(num / den, 4)


async def run_suite(
    seed: int, scenarios: list[dict[str, Any]], *, mode: str, ml: bool = True, spoof_on: bool = True
) -> tuple[dict[str, Outcome], list[dict[str, Any]]]:
    outcomes: dict[str, Outcome] = {}
    events: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="trishul-bench-") as tmp:
        runner = Runner(seed, Path(tmp))
        for sc in scenarios:
            try:
                outcomes[sc["id"]], ev = await runner.run(sc, mode=mode, ml=ml, spoof_on=spoof_on)
                events.extend(ev)
            except Exception as exc:  # harness error: recorded, never counted as a success
                outcomes[sc["id"]] = Outcome(None, f"harness_error: {type(exc).__name__}: {exc}")
    return outcomes, events


def summarize(scenarios: list[dict[str, Any]], outcomes: dict[str, Outcome]) -> dict[str, Any]:
    """asr = attacks whose outcome happened / measurable attacks; utility likewise for benign."""
    att = [s for s in scenarios if s["kind"] == "attack"]
    ben = [s for s in scenarios if s["kind"] == "benign"]

    def side(group: list[dict[str, Any]]) -> tuple[int, int]:
        meas = [outcomes[s["id"]] for s in group if outcomes[s["id"]].executed is not None]
        return sum(1 for o in meas if o.executed), len(meas)

    a_ok, a_n = side(att)
    b_ok, b_n = side(ben)
    return {
        "asr": rate(a_ok, a_n),
        "utility": rate(b_ok, b_n),
        "attacks_succeeded": a_ok,
        "attacks_measured": a_n,
        "benign_completed": b_ok,
        "benign_measured": b_n,
    }
