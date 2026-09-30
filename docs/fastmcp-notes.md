# FastMCP API notes (verified against the installed package)

- Installed: `fastmcp==4.0.10` (resolved from the `mcp` extra `fastmcp>=2.9`).
- Verified by `tests/integration/test_fastmcp.py` (in-memory proxy + policy middleware round trip).

## Differences from older docs / the plan

- `FastMCP.as_proxy(...)` **does not exist** in 4.0.10. Use `fastmcp.server.create_proxy(target, *, mode=None, **settings) -> FastMCPProxy`
  (`target` may be a `Client`, transport, `FastMCP` instance, URL, `Path`, `MCPConfig` or dict).
- `FastMCPProxy` (subclass of `FastMCP`), `ProxyProvider`, `ProxyClient`, `StatefulProxyClient`, `ProxyTool` live in
  `fastmcp.server.providers.proxy`. `FastMCPProxy.__init__(*, client_factory, provider_error_strategy="warn", identity="proxy", **kwargs)`.

## Verified symbols

| Purpose | Symbol |
|---|---|
| Server | `fastmcp.FastMCP` (has `add_middleware(middleware)`, `mount(server, namespace=None, tool_names=None)`, `add_provider(provider, *, namespace="")`) |
| Client | `fastmcp.Client`, `fastmcp.server.providers.proxy.ProxyClient` |
| Proxy factory | `fastmcp.server.create_proxy` |
| Middleware base | `fastmcp.server.middleware.Middleware` |
| Middleware hooks | `on_message`, `on_request`, `on_notification`, `on_initialize`, `on_call_tool`, `on_list_tools`, `on_list_resources`, `on_list_resource_templates`, `on_read_resource`, `on_list_prompts`, `on_get_prompt`, `on_discover`, `__call__` |
| Hook signature | `async def on_call_tool(self, context: MiddlewareContext[mt.CallToolRequestParams], call_next: CallNext[...]) -> ToolResult` |
| Context | `fastmcp.server.middleware.MiddlewareContext` dataclass with fields `message, fastmcp_context, source, type, method, timestamp` |
| Denial | raise `fastmcp.exceptions.ToolError` inside `on_call_tool`; client sees `ToolError` |

## Observed behaviour (Phase 2 gateway implications)

- In `on_call_tool`, `context.message` is `CallToolRequestParams`: `.name`, `.arguments` (dict or None); `context.method == "tools/call"`.
- Middleware added to the proxy runs before the upstream call, so a policy gate there sees the exact tool name and arguments and
  can short-circuit by raising `ToolError` (upstream tool never runs).
- Labels are not part of MCP; the gateway must attach `arg_labels` from its own provenance store (Phase 2, keyed by task/session).
