# SPDX-License-Identifier: Apache-2.0
"""Gateway -> tool-server call tokens (gateway bypass protection, acceptance test 1).

After the gateway decides ALLOW it signs a short-lived token bound to exactly one call and
forwards it inside the reserved argument ``__trishul_token`` (FastMCP 4.x drops request ``_meta``
on the mount/proxy path, see docs/fastmcp-notes.md). Every tool server runs ``ToolAuthMiddleware``
which strips the argument, verifies the token with **public keys only** and rejects anything else,
so an agent that reaches a tool server directly (bypassing the gateway) cannot run a tool.

Token = ``b64url(JCS(claims)) + "." + b64url(Ed25519(JCS(claims)))`` with claims
``{v:1, kid, aud, tool, args_sha256, iat, exp, nonce}`` (times in unix ms, ``exp = iat + 30 000``).
Nonces are single use: ``INSERT`` into the shared SQLite table ``tool_nonces`` is the atomic replay
check across processes.
"""

import contextlib
import hashlib
import json
import secrets
import sqlite3
import time
from collections.abc import Callable
from typing import Any

import mcp.types as mt
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult

from trishul.crypto.jcs import JcsError, jcs
from trishul.crypto.keys import KeyRing, b64url, b64url_decode, purpose_of

TOKEN_ARG = "__trishul_token"  # noqa: S105 - an argument name, not a secret
TOKEN_VERSION = 1
TOKEN_TTL_MS = 30_000
MAX_SKEW_MS = 5_000
_CLAIM_KEYS = frozenset({"v", "kid", "aud", "tool", "args_sha256", "iat", "exp", "nonce"})

NONCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_nonces(nonce TEXT PRIMARY KEY, exp INTEGER NOT NULL);
"""


class ToolAuthError(Exception):
    """A tool call was refused; the message is safe to show (it never echoes the token)."""


def _wall_ms() -> int:
    return int(time.time() * 1000)


def args_digest(args: dict[str, Any]) -> str:
    return hashlib.sha256(jcs(args)).hexdigest()


class ToolTokenMinter:
    """Gateway side: signs one token per forwarded call with the active ``gateway-tool`` key."""

    def __init__(self, keys: KeyRing, *, now_ms: Callable[[], int] = _wall_ms) -> None:
        self.keys = keys
        self.now_ms = now_ms

    def mint(self, server: str, tool: str, args: dict[str, Any]) -> str:
        kid = self.keys.active_kid("gateway-tool")
        iat = self.now_ms()
        claims: dict[str, object] = {
            "v": TOKEN_VERSION,
            "kid": kid,
            "aud": server,
            "tool": tool,
            "args_sha256": args_digest(args),
            "iat": iat,
            "exp": iat + TOKEN_TTL_MS,
            "nonce": b64url(secrets.token_bytes(16)),
        }
        return f"{b64url(jcs(claims))}.{self.keys.sign(kid, claims)}"


class ToolTokenVerifier:
    """Tool-server side. ``keys`` may hold public keys only; ``reload`` (optional) re-reads the
    public key directory once when an unknown kid shows up (after a key rotation)."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        keys: KeyRing,
        *,
        reload: Callable[[], KeyRing] | None = None,
        now_ms: Callable[[], int] = _wall_ms,
    ) -> None:
        self.conn = conn
        self.keys = keys
        self.reload = reload
        self.now_ms = now_ms
        conn.executescript(NONCE_SCHEMA)

    def _ring_for(self, kid: str) -> KeyRing:
        if kid not in self.keys.key_ids() and self.reload is not None:
            with contextlib.suppress(Exception):  # fail closed: old ring kept, kid stays unknown
                self.keys = self.reload()
        return self.keys

    def verify(self, server: str, tool: str, args: dict[str, Any], token: object) -> None:
        """Raise ``ToolAuthError`` unless ``token`` authorises exactly this call, once."""
        claims = self._parse(token)
        kid = claims["kid"]
        ring = self._ring_for(kid)
        assert isinstance(token, str)  # noqa: S101 - _parse guarantees it
        if purpose_of(kid) != "gateway-tool" or kid not in ring.key_ids():
            raise ToolAuthError("unknown signing key")
        if not ring.verify(kid, claims, token.partition(".")[2]):
            raise ToolAuthError("bad signature")
        if claims["aud"] != server:
            raise ToolAuthError("audience mismatch")
        if claims["tool"] != tool:
            raise ToolAuthError("tool mismatch")
        try:
            digest = args_digest(args)
        except JcsError as exc:
            raise ToolAuthError("arguments are not canonicalisable") from exc
        if claims["args_sha256"] != digest:
            raise ToolAuthError("arguments mismatch")
        now = self.now_ms()
        iat, exp = claims["iat"], claims["exp"]
        if exp - iat > TOKEN_TTL_MS or exp <= iat:
            raise ToolAuthError("invalid lifetime")
        if now > exp:
            raise ToolAuthError("token expired")
        if iat > now + MAX_SKEW_MS:
            raise ToolAuthError("token issued in the future")
        self._consume(claims["nonce"], exp, now)

    @staticmethod
    def _parse(token: object) -> dict[str, Any]:
        if not isinstance(token, str) or token.count(".") != 1:
            raise ToolAuthError("missing or malformed token")
        body = token.partition(".")[0]
        try:
            claims = json.loads(b64url_decode(body))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ToolAuthError("malformed token") from exc
        if not isinstance(claims, dict) or set(claims) != _CLAIM_KEYS:
            raise ToolAuthError("malformed token claims")
        ints_ok = all(
            isinstance(claims[k], int) and not isinstance(claims[k], bool) for k in ("iat", "exp")
        )
        strs_ok = all(isinstance(claims[k], str) for k in ("kid", "aud", "tool", "args_sha256"))
        nonce = claims["nonce"]
        if (
            claims["v"] != TOKEN_VERSION
            or not ints_ok
            or not strs_ok
            or not isinstance(nonce, str)
            or not 16 <= len(nonce) <= 64
        ):
            raise ToolAuthError("malformed token claims")
        return claims

    def _consume(self, nonce: str, exp: int, now: int) -> None:
        try:
            self.conn.execute("INSERT INTO tool_nonces(nonce, exp) VALUES (?, ?)", (nonce, exp))
        except sqlite3.IntegrityError as exc:
            raise ToolAuthError("token already used") from exc
        self.conn.execute("DELETE FROM tool_nonces WHERE exp < ?", (now - MAX_SKEW_MS,))


class ToolAuthMiddleware(Middleware):
    """Rejects every ``tools/call`` without a valid gateway token; strips it before validation."""

    def __init__(self, verifier: ToolTokenVerifier, server: str) -> None:
        super().__init__()
        self.verifier = verifier
        self.server = server

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        params = context.message
        args = dict(params.arguments or {})
        token = args.pop(TOKEN_ARG, None)
        try:
            self.verifier.verify(self.server, params.name, args, token)
        except ToolAuthError as exc:
            raise ToolError(f"tool call rejected: {exc}") from exc
        stripped = mt.CallToolRequestParams(name=params.name, arguments=args)
        return await call_next(context.copy(message=stripped))
