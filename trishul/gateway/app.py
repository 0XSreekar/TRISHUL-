# SPDX-License-Identifier: Apache-2.0
"""Gateway assembly: FastMCP proxy + PolicyMiddleware + servers + telemetry.

In-process mode mounts the four demo servers (real MCP protocol, no subprocesses) and is what
the tests use. ``trishul start`` builds the same gateway over stdio subprocess servers via
``create_proxy(MCPConfig)`` (see ``build_stdio_gateway``).
"""

import sqlite3
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastmcp import FastMCP
from fastmcp.server import create_proxy
from starlette.applications import Starlette

from trishul.approvals import ApprovalService
from trishul.audit.log import AuditLog
from trishul.contracts.calls import ToolCategory
from trishul.crypto.keys import KeyRing
from trishul.domains.payshield import MandatePayee, SignedMandate, issue_mandate, store_mandate
from trishul.domains.voicetrust import VoiceTrust
from trishul.gateway.backend import Backend
from trishul.gateway.middleware import PolicyMiddleware
from trishul.gateway.native_tools import NativeExecutor, register_native_tools
from trishul.gateway.pipeline import NAMESPACES, Fault, Pipeline
from trishul.gateway.taint import Task
from trishul.policy.ast import CompiledPolicy
from trishul.policy.compiler import compile_files
from trishul.servers import (
    build_crm_server,
    build_files_server,
    build_mail_server,
    build_upi_server,
)
from trishul.store.db import DEMO_NOW, DEMO_PRINCIPAL, iso
from trishul.store.ids import IdGen
from trishul.telemetry import EventBus, StageMetrics, setup_tracing
from trishul.telemetry.api import DEFAULT_ORIGINS, build_api

POLICY_DIR = Path(__file__).resolve().parents[2] / "policies"


def demo_clock() -> datetime:
    return DEMO_NOW


@dataclass
class Gateway:
    mcp: FastMCP
    pipeline: Pipeline
    backend: Backend
    bus: EventBus
    metrics: StageMetrics
    policy: CompiledPolicy

    def api(self, allowed_origins: list[str] | None = None, port: int | None = None) -> Starlette:
        origins = list(DEFAULT_ORIGINS if allowed_origins is None else allowed_origins)
        if port is not None:  # the gateway's own origin (console served at /console)
            origins += [f"http://localhost:{port}", f"http://127.0.0.1:{port}"]
        return build_api(self.bus, self.metrics, self.backend, allowed_origins=origins)

    def bind_task(
        self,
        *,
        purpose: str,
        category: ToolCategory | str = ToolCategory.READ,
        text: str = "",
        params: Mapping[str, object] | None = None,
        principal: str = DEMO_PRINCIPAL,
        task_id: str | None = None,
    ) -> Task:
        """Trusted-channel task binding (test helper; same code path as REST/CLI)."""
        out = self.backend.bind_task(
            {
                "purpose": purpose,
                "category": ToolCategory(category).value,
                "text": text,
                "params": dict(params or {}),
                "principal": principal,
                "task_id": task_id,
            }
        )
        task = self.pipeline.resolve_task(out["task_id"])
        assert task is not None  # noqa: S101
        return task


def seed_demo_mandate(
    conn: sqlite3.Connection,
    keys: KeyRing,
    *,
    now: datetime = DEMO_NOW,
    principal: str = DEMO_PRINCIPAL,
    payees: tuple[MandatePayee, ...] | None = None,
    per_txn_cap: int = 500_000,
    daily_cap: int = 1_000_000,
    categories: tuple[str, ...] = ("PAYMENT",),
    nonce: str = "demo-mandate-1",
) -> SignedMandate:
    """Issue and store a signed demo mandate (Rs 5,000 per txn, Rs 10,000 per day)."""
    chosen = payees or (
        MandatePayee(vpa="acme@okaxis", name="Acme Supplies", cap=1_000_000),
        MandatePayee(vpa="acme.supplies@okbank", name="Acme Supplies", cap=1_000_000),
        MandatePayee(vpa="bharat.stationers@okbank", name="Bharat Stationers", cap=500_000),
    )
    mandate = issue_mandate(
        keys,
        principal=principal,
        payees=chosen,
        per_txn_cap=per_txn_cap,
        daily_cap=daily_cap,
        categories=categories,
        nbf=now - timedelta(days=30),
        exp=now + timedelta(days=90),
        nonce=nonce,
    )
    store_mandate(conn, mandate, now=now)
    return mandate


def build_gateway(
    conn: sqlite3.Connection,
    ids: IdGen,
    *,
    seed: int = 42,
    keys: KeyRing | None = None,
    clock: Callable[[], datetime] = demo_clock,
    servers: Mapping[str, FastMCP] | None = None,
    base: FastMCP | None = None,
    voice: VoiceTrust | None = None,
    bus: EventBus | None = None,
    policy_dir: Path = POLICY_DIR,
    faults: Mapping[str, Fault] | None = None,
    stage_timeout_s: float = 2.0,
    sth_every: int = 16,
    approval_ttl_s: int = 120,
) -> Gateway:
    """Assemble the gateway. ``servers`` maps namespace -> FastMCP (defaults to the four demo
    servers on ``conn``); ``base`` is an already-built proxy to use instead of mounting."""
    keys = keys or KeyRing.from_seed(seed)
    policy = compile_files([policy_dir])
    provider, metrics = setup_tracing()
    bus = bus or EventBus()
    approvals = ApprovalService(conn, keys, ids, ttl_seconds=approval_ttl_s, clock=clock)
    audit = AuditLog(conn, keys, sth_every=sth_every, clock=clock)
    pipeline = Pipeline(
        conn=conn,
        keys=keys,
        ids=ids,
        policy=policy,
        approvals=approvals,
        audit=audit,
        bus=bus,
        tracer=provider.get_tracer("trishul.gateway"),
        voice=voice,
        clock=clock,
        faults=faults,
        stage_timeout_s=stage_timeout_s,
    )
    if base is None:
        mcp = FastMCP("trishul-gateway")
        upstream = dict(servers) if servers is not None else _demo_servers(conn, ids, clock)
        for ns in NAMESPACES:
            if ns in upstream:
                mcp.mount(upstream[ns], namespace=ns)
    else:
        mcp = base
    register_native_tools(mcp)
    mcp.add_middleware(PolicyMiddleware(pipeline, NativeExecutor(pipeline.handles)))
    backend = Backend(pipeline)
    backend.mcp = mcp
    return Gateway(mcp, pipeline, backend, bus, metrics, policy)


def _demo_servers(
    conn: sqlite3.Connection, ids: IdGen, clock: Callable[[], datetime]
) -> dict[str, FastMCP]:
    return {
        "upi": build_upi_server(conn, ids, clock=clock),
        "crm": build_crm_server(conn),
        "mail": build_mail_server(conn, ids, clock=clock),
        "files": build_files_server(conn),
    }


def stdio_config(db: Path, id_base: int = 0) -> dict[str, Any]:
    """MCPConfig for the four servers as stdio subprocesses (``trishul.gateway.server_main``)."""
    return {
        "mcpServers": {
            ns: {
                "command": sys.executable,
                "args": [
                    "-m",
                    "trishul.gateway.server_main",
                    ns,
                    "--db",
                    str(db),
                    "--id-base",
                    str(id_base + (i + 1) * 1_000_000),
                ],
            }
            for i, ns in enumerate(NAMESPACES)
        }
    }


def build_stdio_gateway(
    conn: sqlite3.Connection,
    ids: IdGen,
    db: Path,
    **kwargs: Any,
) -> Gateway:
    """Gateway over stdio subprocess servers (each opens the same WAL database)."""
    proxy = create_proxy(stdio_config(db), name="trishul-gateway")
    return build_gateway(conn, ids, base=proxy, **kwargs)


def issue_ts(now: datetime) -> str:
    return iso(now)
