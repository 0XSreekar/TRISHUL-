"""``trishul`` CLI: ``policy`` tools plus the gateway operator commands
(``start``, ``verify``, ``prove``, ``report``, ``ml``, ``demo``, ``approve``, ``reject``, ``task``).

Operator commands act on the SQLite database directly (the trusted, out-of-band channel); they
never go through an MCP tool.
"""

import argparse
import asyncio
import contextlib
import importlib
import json
import os
import sys
import threading
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from trishul.contracts.canonical import canonical_json
from trishul.policy.compiler import PolicyCompileFailure, compile_files
from trishul.policy.evaluator import evaluate_raw

DEFAULT_SEED = 42
DEFAULT_PORT = 8787
DEFAULT_MCP_PORT = 8788


def _compile(paths: Sequence[Path]) -> int:
    try:
        policy = compile_files(paths)
    except PolicyCompileFailure as failure:
        for error in failure.errors:
            print(error, file=sys.stderr)
        print(f"{len(failure.errors)} error(s)", file=sys.stderr)
        return 1
    print(policy.canonical())
    print(f"digest: {policy.digest}")
    return 0


def _check(paths: Sequence[Path]) -> int:
    try:
        policy = compile_files(paths)
    except PolicyCompileFailure as failure:
        for error in failure.errors:
            print(error, file=sys.stderr)
        return 1
    print(f"OK {policy.digest}")
    return 0


def _eval(policy_dir: Path, call_file: Path) -> int:
    try:
        policy = compile_files([policy_dir])
        raw = json.loads(call_file.read_text(encoding="utf-8"))
    except PolicyCompileFailure as failure:
        for error in failure.errors:
            print(error, file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"{call_file}: cannot read call: {exc}", file=sys.stderr)
        return 2
    if isinstance(raw, dict) and "call" not in raw:  # bare ToolCall: add a default context
        raw = {"call": raw, "context": {"now": datetime.now(UTC).isoformat()}}
    print(canonical_json(evaluate_raw(policy, raw).model_dump(mode="json")))
    return 0


def _default_db() -> Path:
    return Path(os.environ.get("TRISHUL_DB", "trishul.db"))


def _db_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--db", type=Path, default=_default_db(), help="SQLite database path")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trishul")
    top = parser.add_subparsers(dest="group", required=True)
    policy = top.add_parser("policy", help="policy tools").add_subparsers(dest="cmd", required=True)
    for name, help_text in (("compile", "compile and print canonical JSON"), ("check", "validate")):
        p = policy.add_parser(name, help=help_text)
        p.add_argument("paths", nargs="+", type=Path)
    ev = policy.add_parser("eval", help="evaluate a call against a policy directory")
    ev.add_argument("policy_dir", type=Path)
    ev.add_argument("call", type=Path)

    start = top.add_parser("start", help="run the gateway (MCP + REST/WS)")
    _db_arg(start)
    start.add_argument("--seed", type=int, default=None, help="reset the demo state with this seed")
    start.add_argument(
        "--host", default="127.0.0.1", help="bind address for the API and MCP servers"
    )
    start.add_argument("--port", type=int, default=DEFAULT_PORT, help="REST/WS API port")
    start.add_argument("--mcp-port", type=int, default=DEFAULT_MCP_PORT, help="MCP HTTP port")
    start.add_argument(
        "--in-process",
        action="store_true",
        help="mount the demo servers in-process instead of stdio subprocesses",
    )
    verify_p = top.add_parser("verify", help="verify the Merkle audit log")
    _db_arg(verify_p)
    prove_p = top.add_parser("prove", help="run the formal policy proofs")
    _db_arg(prove_p)
    report = top.add_parser("report", help="compliance reports")
    _db_arg(report)
    report.add_argument("--dpdp", action="store_true", required=True, help="DPDP audit report")
    ml = top.add_parser("ml", help="switch the ML signals on or off")
    _db_arg(ml)
    ml.add_argument("state", choices=["on", "off"])
    demo = top.add_parser("demo", help="demo data").add_subparsers(dest="cmd", required=True)
    reset = demo.add_parser("reset", help="wipe and reseed deterministic demo state")
    _db_arg(reset)
    reset.add_argument("--seed", type=int, default=DEFAULT_SEED)
    tamper = demo.add_parser("tamper", help="mutate one stored audit payload (demo tampering)")
    _db_arg(tamper)
    tamper.add_argument("--idx", type=int, required=True, help="audit leaf index to tamper with")
    rt = top.add_parser("redteam", help="red-team wall controls").add_subparsers(
        dest="cmd", required=True
    )
    for name, help_text in (("kill", "stop accepting submissions"), ("resume", "accept again")):
        _db_arg(rt.add_parser(name, help=help_text))
    for name in ("approve", "reject"):
        ap = top.add_parser(name, help=f"{name} a pending step-up approval")
        _db_arg(ap)
        ap.add_argument("approval_id")
        ap.add_argument("--approver", default="cli")
    task = top.add_parser("task", help="task binding").add_subparsers(dest="cmd", required=True)
    bind = task.add_parser("bind", help="bind the active task (trusted channel)")
    _db_arg(bind)
    bind.add_argument("--purpose", required=True)
    bind.add_argument("--category", default="READ")
    bind.add_argument("--text", default="")
    bind.add_argument("--params", default="{}", help="JSON object of trusted task parameters")
    bind.add_argument("--principal", default=None)
    bind.add_argument("--task-id", default=None)
    from trishul.bench.cli import register as _register_bench

    _register_bench(top)
    return parser


# --- gateway operator commands --------------------------------------------------------------


def _open(db: Path) -> tuple[Any, int]:
    """Connect and return ``(conn, seed)``; the seed is recorded in the ``meta`` table."""
    from trishul.store.db import connect

    conn = connect(db)
    row = conn.execute("SELECT value FROM meta WHERE key='seed'").fetchone()
    return conn, int(row["value"]) if row else DEFAULT_SEED


def _gateway(db: Path, **kw: Any) -> Any:
    """A gateway object for operator actions. Its id generator starts far above anything the
    running gateway issues, so ids (approvals, tokens, tasks) cannot collide across processes."""
    from trishul.gateway.app import build_gateway
    from trishul.store.ids import IdGen

    conn, seed = _open(db)
    ids = IdGen(seed, start=100_000_000 + int(time.time() * 1000) % 100_000_000)
    return build_gateway(conn, ids, seed=seed, **kw)


def _print(obj: object) -> None:
    print(json.dumps(obj, sort_keys=True))


def _verify(db: Path) -> int:
    from trishul.audit.verify import verify
    from trishul.crypto.keys import KeyRing

    conn, seed = _open(db)
    result = verify(conn, KeyRing.from_seed(seed))
    _print(result.model_dump())
    return 0 if result.ok else 1


def _prove(db: Path) -> int:
    try:
        importlib.import_module("trishul.verify")
    except ImportError:
        _print({"result": "UNAVAILABLE"})
        return 0
    gw = _gateway(db)
    _print(gw.backend.prove())
    return 0


def _report_dpdp(db: Path) -> int:
    from trishul.crypto.keys import KeyRing
    from trishul.domains.dpdp import dpdp_report

    conn, seed = _open(db)
    _print(dpdp_report(conn, KeyRing.from_seed(seed)))
    return 0


def _ml(db: Path, state: str) -> int:
    gw = _gateway(db)
    gw.backend.set_ml_cli(state == "on")  # applies + audits, then a control row for the gateway
    _print({"ml": state})
    return 0


def _redteam(db: Path, on: bool) -> int:
    gw = _gateway(db)
    stats = gw.backend.redteam_kill_cli(on)
    _print({"redteam_killed": on, **stats})
    return 0


def _demo_tamper(db: Path, idx: int) -> int:
    """``UPDATE audit_leaves SET payload=? WHERE idx=?`` with one JSON field mutated (the stored
    leaf hash is left alone, so ``trishul verify`` reports exactly ``bad_index == idx``)."""
    conn, _ = _open(db)
    row = conn.execute("SELECT payload FROM audit_leaves WHERE idx=?", (idx,)).fetchone()
    if row is None:
        print(f"no audit leaf at index {idx}", file=sys.stderr)
        return 1
    try:
        event = json.loads(bytes(row["payload"]))
        if not isinstance(event, dict):
            raise ValueError
    except ValueError:
        print(f"audit leaf {idx} is not a JSON object", file=sys.stderr)
        return 1
    field = "decision" if "decision" in event else "type" if "type" in event else None
    if field is None:
        event["tampered"] = True
        field = "tampered"
    elif event[field] == "ALLOW":
        event[field] = "DENY"
    elif field == "decision":
        event[field] = "ALLOW"
    else:
        event[field] = str(event[field]) + "-tampered"
    payload = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    conn.execute("UPDATE audit_leaves SET payload=? WHERE idx=?", (payload.encode(), idx))
    _print({"tampered": idx, "field": field})
    return 0


def _demo_reset(db: Path, seed: int) -> int:
    from trishul.crypto.keys import KeyRing
    from trishul.gateway.app import seed_demo_mandate
    from trishul.store.db import DEMO_NOW, connect, iso, reset
    from trishul.store.ids import IdGen

    conn = connect(db)
    ids = reset(conn, seed=seed)
    mandate = seed_demo_mandate(conn, KeyRing.from_seed(seed), now=DEMO_NOW)
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('id_counter', ?)", (str(ids.counter),)
    )
    conn.execute(
        "INSERT INTO control(key, value, origin, ts) VALUES ('reset', ?, 'cli', ?)",
        (str(seed), iso(DEMO_NOW)),
    )
    preview = IdGen(seed, start=ids.counter).new("call")
    _print(
        {
            "reset": True,
            "seed": seed,
            "ids_issued": ids.counter,
            "mandate_id": mandate.mandate_id(),
            "next_call_id": preview,
        }
    )
    return 0


def _resolve(db: Path, approval_id: str, decision: str, approver: str) -> int:
    gw = _gateway(db)
    try:
        out = gw.backend.resolve_approval(approval_id, decision, approver)
    except KeyError:
        print(f"unknown approval {approval_id}", file=sys.stderr)
        return 1
    except (ValueError, PermissionError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _print(out)
    return 0


def _task_bind(args: argparse.Namespace) -> int:
    try:
        params = json.loads(args.params)
    except ValueError:
        print("--params must be a JSON object", file=sys.stderr)
        return 2
    payload: dict[str, Any] = {
        "purpose": args.purpose,
        "category": args.category,
        "text": args.text,
        "params": params,
        "task_id": args.task_id,
    }
    if args.principal:
        payload["principal"] = args.principal
    gw = _gateway(args.db)
    try:
        _print(gw.backend.bind_task(payload))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


def _ensure_operator_token(db: Path) -> Path:
    """Operator token: TRISHUL_OPERATOR_TOKEN if set, else a fresh random one. Always written to
    ``<db_dir>/operator.token`` (mode 0600); the token itself is never printed."""
    import secrets

    tok = os.environ.get("TRISHUL_OPERATOR_TOKEN") or secrets.token_urlsafe(32)
    os.environ["TRISHUL_OPERATOR_TOKEN"] = tok
    path = db.resolve().parent / "operator.token"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(tok + "\n")
    os.chmod(path, 0o600)
    return path


def _start(args: argparse.Namespace) -> int:
    import uvicorn

    from trishul.crypto.keys import KeyRing
    from trishul.gateway.app import build_gateway, build_stdio_gateway, seed_demo_mandate
    from trishul.store.db import DEMO_NOW, connect, reset

    db: Path = args.db
    conn = connect(db)
    row = conn.execute("SELECT value FROM meta WHERE key='seed'").fetchone()
    if args.seed is not None or row is None:
        seed = DEFAULT_SEED if args.seed is None else args.seed
        ids = reset(conn, seed=seed)
        seed_demo_mandate(conn, KeyRing.from_seed(seed), now=DEMO_NOW)
    else:
        seed = int(row["value"])
        counter = conn.execute("SELECT value FROM meta WHERE key='id_counter'").fetchone()
        from trishul.store.ids import IdGen

        ids = IdGen(seed, start=int(counter["value"]) if counter else 0)
    token_path = _ensure_operator_token(db)
    if args.in_process:
        gw = build_gateway(conn, ids, seed=seed)
    else:
        gw = build_stdio_gateway(conn, ids, db.resolve(), seed=seed)
    # Warm voice models inside the gateway process (a separate prewarm process cannot compile
    # this process's Metal kernels). Background thread: startup and non-voice calls never wait.
    threading.Thread(target=gw.pipeline.voice.warmup, name="voice-warmup", daemon=True).start()

    async def serve() -> None:
        gw.backend.loop = asyncio.get_running_loop()
        server = uvicorn.Server(
            uvicorn.Config(
                gw.api(port=args.port), host=args.host, port=args.port, log_level="warning"
            )
        )
        mode = "in-process" if args.in_process else "stdio subprocesses"
        print(f"operator token file: {token_path} (send as 'Authorization: Bearer <token>')")
        # The console reads the token from the #op= fragment (stripped on load). Print a shell
        # command that expands it from the file, never the token itself.
        print(
            "console (operator): open "
            f'"http://localhost:{args.port}/console/Trishul-Console.dc.html#op=$(cat '
            f"'{token_path}')\""
        )
        print("readiness:", json.dumps(gw.backend.readyz(), sort_keys=True), flush=True)
        print(
            f"TRISHUL gateway: MCP http://127.0.0.1:{args.mcp_port}/mcp  API :{args.port}"
            f"  servers={mode}  seed={seed}",
            flush=True,
        )
        await asyncio.gather(
            gw.backend.run_control_poller(),
            server.serve(),
            gw.mcp.run_http_async(
                transport="http", host=args.host, port=args.mcp_port, show_banner=False
            ),
        )

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(serve())
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    match args.group:
        case "policy":
            match args.cmd:
                case "compile":
                    return _compile(args.paths)
                case "check":
                    return _check(args.paths)
                case _:
                    return _eval(args.policy_dir, args.call)
        case "start":
            return _start(args)
        case "verify":
            return _verify(args.db)
        case "prove":
            return _prove(args.db)
        case "report":
            return _report_dpdp(args.db)
        case "ml":
            return _ml(args.db, args.state)
        case "demo":
            if args.cmd == "tamper":
                return _demo_tamper(args.db, args.idx)
            return _demo_reset(args.db, args.seed)
        case "redteam":
            return _redteam(args.db, args.cmd == "kill")
        case "approve":
            return _resolve(args.db, args.approval_id, "approve", args.approver)
        case "reject":
            return _resolve(args.db, args.approval_id, "reject", args.approver)
        case "task":
            return _task_bind(args)
        case "bench":
            from trishul.bench.cli import run as _run_bench

            return _run_bench(args)
    return 2  # pragma: no cover - argparse enforces the choices


if __name__ == "__main__":
    sys.exit(main())
