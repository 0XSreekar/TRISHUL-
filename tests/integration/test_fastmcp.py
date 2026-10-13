"""Pins the FastMCP symbols Phase 2's gateway will rely on (verified against the installed
package, not the docs). Skipped when the optional ``mcp`` extra is absent."""

import importlib.metadata
import inspect

import pytest

pytest.importorskip("fastmcp")

from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server import create_proxy
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.providers.proxy import FastMCPProxy, ProxyClient

from tests.conftest import POLICY_DIR
from trishul.contracts.decisions import Decision
from trishul.policy.compiler import compile_files


def test_installed_version_meets_extra_requirement() -> None:
    major, minor, *_ = (int(p) for p in importlib.metadata.version("fastmcp").split(".")[:2])
    assert (major, minor) >= (2, 9)


def test_symbols_exist_with_expected_shapes() -> None:
    assert issubclass(FastMCPProxy, FastMCP)
    assert issubclass(ProxyClient, Client)
    assert "target" in inspect.signature(create_proxy).parameters
    assert not hasattr(FastMCP, "as_proxy"), "as_proxy was removed; use create_proxy"
    assert "middleware" in inspect.signature(FastMCP.add_middleware).parameters
    for hook in ("on_call_tool", "on_list_tools", "on_request", "on_message"):
        assert callable(getattr(Middleware, hook))
    fields = set(MiddlewareContext.__dataclass_fields__)
    assert {"message", "fastmcp_context", "method"} <= fields


async def test_policy_middleware_gates_proxied_tool_call() -> None:
    upstream = FastMCP("upstream")

    @upstream.tool
    def get_balance(account_id: str) -> str:
        return f"balance:{account_id}"

    policy = compile_files([POLICY_DIR])
    seen: list[tuple[str | None, str, dict[str, object] | None]] = []

    class PolicyGate(Middleware):
        async def on_call_tool(self, context, call_next):  # type: ignore[no-untyped-def]
            params = context.message
            seen.append((context.method, params.name, params.arguments))
            if params.name not in policy.tools:
                raise ToolError(f"denied by {Decision.DENY.name}")
            return await call_next(context)

    @upstream.tool
    def not_in_policy() -> str:
        return "should never run"

    proxy = create_proxy(upstream, name="trishul-gateway")
    proxy.add_middleware(PolicyGate())

    async with Client(proxy) as client:
        ok = await client.call_tool("get_balance", {"account_id": "A1"})
        assert "balance:A1" in str(ok.content)
        with pytest.raises(ToolError):
            await client.call_tool("not_in_policy", {})
    assert seen == [
        ("tools/call", "get_balance", {"account_id": "A1"}),
        ("tools/call", "not_in_policy", {}),
    ]
