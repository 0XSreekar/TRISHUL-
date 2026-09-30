"""Acceptance 1 (gateway-only): an agent that reaches a tool server directly cannot run a tool.

Every tool server demands a gateway-signed, single-use, call-bound token
(``trishul.crypto.toolauth``).
"""

import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport
from fastmcp.exceptions import ToolError

from tests.integration.test_gateway_harness import Env
from tests.toolauth_helpers import TokenClient
from trishul.crypto.keys import KeyRing
from trishul.crypto.keystore import write_public
from trishul.crypto.toolauth import TOKEN_ARG, ToolTokenMinter
from trishul.gateway.server_main import BindError, validate_bind_host
from trishul.servers import build_upi_server
from trishul.store.db import connect, reset

pytestmark = pytest.mark.acceptance(1)

PAY = {"payee_vpa": "acme@okaxis", "amount_paise": 1000}


def ledger_rows(db: Path) -> int:
    conn = connect(db)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0])
    finally:
        conn.close()


def stdio_transport(db: Path, pub: Path) -> StdioTransport:
    return StdioTransport(
        command=sys.executable,
        args=["-m", "trishul.gateway.server_main", "upi", "--db", str(db), "--keys", str(pub)],
    )


@pytest.fixture
def stdio_env(tmp_path: Path) -> tuple[Path, Path, KeyRing]:
    db = tmp_path / "t.db"
    conn = connect(db)
    reset(conn, seed=42)
    conn.close()
    keys = KeyRing.generate()
    write_public(keys, tmp_path / "pub")
    return db, tmp_path / "pub", keys


async def _attempts(keys: KeyRing) -> list[tuple[str, dict[str, Any]]]:
    """Direct calls an attacker can craft: no token, foreign key, valid token for other args."""
    foreign = ToolTokenMinter(KeyRing.generate()).mint("upi", "pay_upi", PAY)
    other_args = ToolTokenMinter(keys).mint("upi", "pay_upi", {**PAY, "amount_paise": 1})
    wrong_tool = ToolTokenMinter(keys).mint("upi", "get_balance", PAY)
    wrong_aud = ToolTokenMinter(keys).mint("mail", "pay_upi", PAY)
    return [
        ("no token", dict(PAY)),
        ("garbage token", {**PAY, TOKEN_ARG: "not-a-token"}),
        ("foreign key", {**PAY, TOKEN_ARG: foreign}),
        ("wrong args", {**PAY, TOKEN_ARG: other_args}),
        ("wrong tool", {**PAY, TOKEN_ARG: wrong_tool}),
        ("wrong audience", {**PAY, TOKEN_ARG: wrong_aud}),
    ]


async def test_direct_in_process_call_without_valid_token_is_rejected() -> None:
    conn = connect(":memory:")
    ids = reset(conn, seed=42)
    keys = KeyRing.generate()
    async with TokenClient(
        "upi", lambda v: build_upi_server(conn, ids, verifier=v), conn, keys
    ) as c:
        for label, args in await _attempts(keys):
            with pytest.raises(ToolError, match="rejected"):
                await c.client.call_tool("pay_upi", args)
            assert conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0] == 0, label
        balance = conn.execute("SELECT balance_paise FROM accounts").fetchone()[0]
        assert balance == 5_000_000
        ok = await c.call_tool("pay_upi", PAY)  # the gateway path still works
        assert ok.data["balance_after"] == 5_000_000 - 1000


async def test_direct_stdio_process_call_without_valid_token_is_rejected(
    stdio_env: tuple[Path, Path, KeyRing],
) -> None:
    db, pub, keys = stdio_env
    for label, args in await _attempts(keys):
        async with Client(stdio_transport(db, pub)) as c:
            with pytest.raises(ToolError, match="rejected"):
                await c.call_tool("pay_upi", args)
        assert ledger_rows(db) == 0, label


async def test_replayed_token_is_rejected_across_processes(
    stdio_env: tuple[Path, Path, KeyRing],
) -> None:
    db, pub, keys = stdio_env
    token = ToolTokenMinter(keys).mint("upi", "pay_upi", PAY)
    async with Client(stdio_transport(db, pub)) as c:
        await c.call_tool("pay_upi", {**PAY, TOKEN_ARG: token})
    assert ledger_rows(db) == 1
    async with Client(stdio_transport(db, pub)) as c:  # a different server process
        with pytest.raises(ToolError, match="already used"):
            await c.call_tool("pay_upi", {**PAY, TOKEN_ARG: token})
    assert ledger_rows(db) == 1


async def test_normal_gateway_call_is_accepted_and_agent_cannot_inject_a_token(
    env: Env,
) -> None:
    env.gw.bind_task(purpose="payment_processing", category="PAYMENT", text="pay", params=PAY)
    ok = await env.client.call_tool("upi_pay_upi", PAY)
    assert ok.structured_content and ok.structured_content["balance_after"] == 4_999_000
    rows = env.conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0]
    assert rows == 1
    # the token channel belongs to the gateway: an agent-supplied token is refused outright
    forged = ToolTokenMinter(KeyRing.generate()).mint("upi", "pay_upi", PAY)
    with pytest.raises(ToolError, match="reserved"):
        await env.client.call_tool("upi_pay_upi", {**PAY, TOKEN_ARG: forged})
    assert env.conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0] == rows
    # and the agent-facing tool schema never advertises the reserved argument
    for tool in await env.client.list_tools():
        assert TOKEN_ARG not in str(tool.input_schema)


WILDCARDS = ["0.0.0.0", "::", "[::]", "", "  ", "*", "0", "0:0:0:0:0:0:0:0"]  # noqa: S104


@pytest.mark.parametrize("host", WILDCARDS)
def test_wildcard_bind_is_refused(host: str) -> None:
    with pytest.raises(BindError):
        validate_bind_host(host)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "tools", "10.0.0.5", "unix:/tmp/t.sock"])
def test_specific_bind_is_accepted(host: str) -> None:
    assert validate_bind_host(host) == host


def test_server_process_refuses_wildcard_bind_at_startup(tmp_path: Path) -> None:
    keys = KeyRing.generate()
    write_public(keys, tmp_path / "pub")
    conn = connect(tmp_path / "t.db")
    conn.close()
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "trishul.gateway.server_main",
            "upi",
            "--db",
            str(tmp_path / "t.db"),
            "--keys",
            str(tmp_path / "pub"),
            "--transport",
            "http",
            "--host",
            "0.0.0.0",  # noqa: S104 - the refusal is what is under test
            "--port",
            "9999",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 2 and "wildcard" in proc.stderr


async def test_http_transport_enforces_the_token_too(tmp_path: Path) -> None:
    db = tmp_path / "h.db"
    conn = connect(db)
    reset(conn, seed=42)
    conn.close()
    keys = KeyRing.generate()
    write_public(keys, tmp_path / "pub")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-m",
            "trishul.gateway.server_main",
            "upi",
            "--db",
            str(db),
            "--keys",
            str(tmp_path / "pub"),
            "--transport",
            "http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.2)
        url = f"http://127.0.0.1:{port}/mcp"
        async with Client(url) as c:
            with pytest.raises(ToolError, match="rejected"):
                await c.call_tool("pay_upi", PAY)
            token = ToolTokenMinter(keys).mint("upi", "pay_upi", PAY)
            ok = await c.call_tool("pay_upi", {**PAY, TOKEN_ARG: token})
            assert ok.data["balance_after"] == 5_000_000 - 1000
            with pytest.raises(ToolError, match="already used"):
                await c.call_tool("pay_upi", {**PAY, TOKEN_ARG: token})
        assert ledger_rows(db) == 1
    finally:
        proc.terminate()
        proc.wait(timeout=10)
