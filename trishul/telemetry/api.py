"""Starlette REST + WebSocket API consumed by the console."""

import asyncio
import contextlib
import hmac
import json
import logging
import os
import re
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Literal, Protocol

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.websockets import WebSocket, WebSocketDisconnect

from trishul.auth import AuthError, AuthService, RateLimitedError, Session
from trishul.auth.service import ABSOLUTE_SECONDS
from trishul.redteam.errors import RedTeamError
from trishul.telemetry.events import EventBus
from trishul.telemetry.otel import StageMetrics

log = logging.getLogger("trishul.telemetry.api")
DEFAULT_ORIGINS = ["http://localhost", "http://127.0.0.1"]
CONSOLE_DIR = Path(__file__).resolve().parents[2] / "Landing page and dashboard implementation"
BENCH_RESULTS = Path(__file__).resolve().parents[2] / "bench" / "results.json"
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_MAX_BODY = 256 * 1024
SESSION_COOKIE = "trishul_session"


class GatewayBackend(Protocol):
    def list_consent(self) -> list[dict[str, Any]]: ...
    def withdraw_consent(self, consent_id: str) -> dict[str, Any]: ...
    def list_approvals(self) -> list[dict[str, Any]]: ...
    def resolve_approval(
        self, approval_id: str, decision: Literal["approve", "reject"], approver: str
    ) -> dict[str, Any]: ...
    def prove(self, policy: str = "live") -> dict[str, Any]: ...
    def bind_task(self, payload: dict[str, Any]) -> dict[str, Any]: ...
    def issue_voice_nonce(self, session: str) -> dict[str, Any]: ...
    def audit_verify(self) -> dict[str, Any]: ...

    # Phase 3 surface (implemented by ``Backend``; see ``trishul.gateway.showcase``)
    def healthz(self) -> dict[str, Any]: ...
    def readyz(self) -> dict[str, Any]: ...
    def mode(self) -> dict[str, Any]: ...
    def set_mode(self, mode: str) -> dict[str, Any]: ...
    def set_ml(self, enabled: bool) -> None: ...
    def mandates(self) -> list[dict[str, Any]]: ...
    def audit_head(self) -> dict[str, Any]: ...
    def audit_leaves(self, start: int, limit: int) -> dict[str, Any]: ...
    def audit_inclusion(self, idx: int) -> dict[str, Any]: ...
    def audit_consistency(self, old: int) -> dict[str, Any]: ...
    def redteam_stats(self) -> dict[str, Any]: ...
    def redteam_kill(self, on: bool) -> dict[str, Any]: ...
    def demo_reset(self, seed: int, actor: str = "operator") -> dict[str, Any]: ...
    def record_operator_action(self, action: str, actor: str, params: dict[str, Any]) -> None: ...
    async def redteam_submit(self, text: object, client_ip: str) -> dict[str, Any]: ...
    async def redteam_fallback(self, count: int | None = None) -> list[dict[str, Any]]: ...
    async def demo_moment(self, n: int, step: int | None = None) -> dict[str, Any]: ...
    def dpdp(self) -> dict[str, Any]: ...


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


class _NoCacheStatic(StaticFiles):
    """Console files are revalidated on every load so a rehearsal fix is never hidden behind a
    stale browser cache (ETag keeps revalidation cheap)."""

    def file_response(self, *args: Any, **kwargs: Any) -> Response:
        resp = super().file_response(*args, **kwargs)
        resp.headers["Cache-Control"] = "no-cache"
        return resp


def _err(status: int, code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status)


async def _json_body(request: Request) -> dict[str, Any] | None:
    raw = await request.body()
    if len(raw) > _MAX_BODY:
        return None
    try:
        data = json.loads(raw or b"{}")
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _origin_ok(origin: str | None, allowed: list[str]) -> bool:
    """Exact-match allowlist (scheme+host+port). A missing Origin is a non-browser client."""
    return origin is None or origin in allowed


def build_api(
    bus: EventBus,
    metrics: StageMetrics,
    backend: GatewayBackend,
    *,
    allowed_origins: list[str] | None = None,
    heartbeat_s: float = 15.0,
    auth: AuthService | None = None,
) -> Starlette:
    origins = list(allowed_origins) if allowed_origins is not None else list(DEFAULT_ORIGINS)
    accounts: AuthService | None = auth if auth is not None else getattr(backend, "auth", None)

    def _session(request: Request) -> Session | None:
        if accounts is None:
            return None
        return accounts.session(request.cookies.get(SESSION_COOKIE))

    def _csrf_ok(request: Request, session: Session) -> bool:
        presented = request.headers.get("x-csrf-token", "")
        return bool(presented) and hmac.compare_digest(presented.encode(), session.csrf.encode())

    def guarded(
        handler: Callable[[Request], Awaitable[Response]],
    ) -> Callable[[Request], Awaitable[Response]]:
        """CSRF defence for state-changing routes: a present Origin must be allowlisted (browsers
        always send Origin on cross-origin POSTs) and a non-empty body must be declared JSON
        (defence in depth: forces a CORS preflight). Bodyless POSTs such as the console's
        /prove and /consent/{id}/withdraw rely on the Origin check alone. No Origin = CLI."""

        async def wrapper(request: Request) -> Response:
            if not _origin_ok(request.headers.get("origin"), origins):
                return _err(403, "forbidden_origin")
            ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
            if ctype != "application/json" and await request.body():
                return _err(415, "unsupported_media_type")
            return await handler(request)

        return wrapper

    def approver_only(
        handler: Callable[[Request], Awaitable[Response]],
    ) -> Callable[[Request], Awaitable[Response]]:
        """Approval routes: an approver-role session plus a matching ``X-CSRF-Token``. The operator
        bearer token is not an approver credential. No session -> 401; wrong role, missing or
        wrong CSRF token -> 403."""

        async def wrapper(request: Request) -> Response:
            session = _session(request)
            if session is None:
                return _err(401, "approver_login_required")
            if session.role != "approver":
                return _err(403, "forbidden_role")
            if not _csrf_ok(request, session):
                return _err(403, "csrf_required")
            request.state.actor = session.user_id
            return await handler(request)

        return wrapper

    def operator(
        handler: Callable[[Request], Awaitable[Response]],
    ) -> Callable[[Request], Awaitable[Response]]:
        """Operator-only routes: ``Authorization: Bearer <TRISHUL_OPERATOR_TOKEN>`` (constant-time
        compare, regardless of client address; no token configured = fail closed) or an
        operator-role session plus ``X-CSRF-Token``. An approver session is refused (403)."""

        async def wrapper(request: Request) -> Response:
            expected = os.environ.get("TRISHUL_OPERATOR_TOKEN", "")
            auth_header = request.headers.get("authorization", "")
            scheme, _, presented = auth_header.partition(" ")
            if (
                expected
                and scheme.lower() == "bearer"
                and hmac.compare_digest(presented.strip().encode(), expected.encode())
            ):
                request.state.actor = "operator-token"
                return await handler(request)
            session = _session(request)
            if session is None:
                return _err(401, "operator_token_required")
            if session.role != "operator":
                return _err(403, "forbidden_role")
            if not _csrf_ok(request, session):
                return _err(403, "csrf_required")
            request.state.actor = session.user_id
            return await handler(request)

        return wrapper

    def _actor(request: Request) -> str:
        return str(getattr(request.state, "actor", "operator"))

    async def audited(request: Request, action: str, params: dict[str, Any]) -> Response | None:
        """Append the operator action to the audit log BEFORE acting; a failure refuses it."""
        try:
            await run_in_threadpool(backend.record_operator_action, action, _actor(request), params)
        except Exception:
            log.exception("operator action audit failed")
            return _err(500, "audit_unavailable")
        return None

    async def call(fn: Callable[..., Any], *args: Any) -> Response:
        try:
            result = await run_in_threadpool(fn, *args)
        except KeyError:
            return _err(404, "not_found")
        except (ValueError, PermissionError):
            return _err(400, "invalid_request")
        except Exception:
            log.exception("backend error")
            return _err(500, "internal_error")
        return JSONResponse(result)

    async def consent(request: Request) -> Response:
        try:
            items = await run_in_threadpool(backend.list_consent)
        except Exception:
            log.exception("backend error")
            return _err(500, "internal_error")
        return JSONResponse({"consent": items})

    async def withdraw(request: Request) -> Response:
        cid = request.path_params["id"]
        if not _ID.match(cid):
            return _err(400, "invalid_id")
        return await call(backend.withdraw_consent, cid)

    async def approvals(request: Request) -> Response:
        try:
            items = await run_in_threadpool(backend.list_approvals)
        except Exception:
            log.exception("backend error")
            return _err(500, "internal_error")
        return JSONResponse({"approvals": items})

    async def resolve(request: Request) -> Response:
        aid = request.path_params["id"]
        if not _ID.match(aid):
            return _err(400, "invalid_id")
        body = await _json_body(request)
        if body is None or body.get("decision") not in ("approve", "reject"):
            return _err(400, "invalid_decision")
        return await call(backend.resolve_approval, aid, body["decision"], _actor(request))

    async def prove(request: Request) -> Response:
        body = await _json_body(request)
        if body is None:
            return _err(400, "invalid_body")
        policy = body.get("policy", "live")
        if policy not in ("live", "unsafe_fixture"):
            return _err(400, "invalid_policy")
        if policy == "unsafe_fixture" and (
            bad := await audited(request, "prove", {"policy": policy})
        ):
            return bad
        return await call(backend.prove, policy)

    async def healthz(request: Request) -> Response:
        return JSONResponse({"ok": True})

    async def readyz(request: Request) -> Response:
        try:
            out = await run_in_threadpool(backend.readyz)
        except Exception:
            log.exception("backend error")
            return JSONResponse({"ready": False, "checks": {}}, status_code=503)
        return JSONResponse(out, status_code=200 if out.get("ready") else 503)

    async def mode_get(request: Request) -> Response:
        return await call(backend.mode)

    async def mode_post(request: Request) -> Response:
        body = await _json_body(request)
        if body is None or body.get("mode") not in ("on", "off"):
            return _err(400, "invalid_mode")
        if bad := await audited(request, "mode", {"mode": body["mode"]}):
            return bad
        return await call(backend.set_mode, body["mode"])

    async def ml_post(request: Request) -> Response:
        body = await _json_body(request)
        enabled = None if body is None else body.get("enabled")
        if not isinstance(enabled, bool):
            return _err(400, "invalid_enabled")
        if bad := await audited(request, "ml", {"enabled": enabled}):
            return bad
        result = await call(backend.set_ml, enabled)
        return result if result.status_code != 200 else JSONResponse({"ml": enabled})

    async def mandates(request: Request) -> Response:
        try:
            items = await run_in_threadpool(backend.mandates)
        except Exception:
            log.exception("backend error")
            return _err(500, "internal_error")
        return JSONResponse({"mandates": items})

    def _int_param(request: Request, name: str, default: int | None) -> int | None:
        raw = request.query_params.get(name)
        if raw is None:
            return default
        return int(raw) if re.fullmatch(r"[0-9]{1,9}", raw) else None

    async def audit_head(request: Request) -> Response:
        return await call(backend.audit_head)

    async def audit_leaves(request: Request) -> Response:
        start, limit = _int_param(request, "from", 0), _int_param(request, "limit", 50)
        if start is None or limit is None:
            return _err(400, "invalid_range")
        return await call(backend.audit_leaves, start, limit)

    async def audit_inclusion(request: Request) -> Response:
        idx = _int_param(request, "idx", None)
        if idx is None:
            return _err(400, "invalid_idx")
        return await call(backend.audit_inclusion, idx)

    async def audit_consistency(request: Request) -> Response:
        old = _int_param(request, "old", None)
        if old is None:
            return _err(400, "invalid_old")
        return await call(backend.audit_consistency, old)

    async def acall(coro_fn: Callable[..., Awaitable[Any]], *args: Any) -> Response:
        """Async backend methods run on the API's own loop (the gateway loop in production)."""
        try:
            result = await coro_fn(*args)
        except RedTeamError as exc:
            return _err(exc.status, exc.code)
        except KeyError:
            return _err(404, "not_found")
        except (ValueError, PermissionError):
            return _err(400, "invalid_request")
        except Exception:
            log.exception("backend error")
            return _err(500, "internal_error")
        return JSONResponse(result)

    async def redteam_submit(request: Request) -> Response:
        """Operator-only test submission. The public audience route lives in its own app
        (``trishul.redteam.app``) on its own port."""
        body = await _json_body(request)
        if body is None or not isinstance(body.get("text"), str):
            return _err(400, "invalid_text")
        return await acall(backend.redteam_submit, body["text"], _client_ip(request))

    async def redteam_kill(request: Request) -> Response:
        body = await _json_body(request)
        on = None if body is None else body.get("on")
        if not isinstance(on, bool):
            return _err(400, "invalid_on")
        if bad := await audited(request, "redteam_kill", {"on": on}):
            return bad
        return await call(backend.redteam_kill, on)

    async def redteam_stats(request: Request) -> Response:
        return await call(backend.redteam_stats)

    async def redteam_fallback(request: Request) -> Response:
        body = await _json_body(request)
        count = None if body is None else body.get("count")
        if body is None or (
            count is not None and (not isinstance(count, int) or isinstance(count, bool))
        ):
            return _err(400, "invalid_count")

        if bad := await audited(request, "redteam_fallback", {"count": count}):
            return bad

        async def run() -> dict[str, Any]:
            return {"results": await backend.redteam_fallback(count)}

        return await acall(run)

    async def demo_moment(request: Request) -> Response:
        n = request.path_params["n"]
        body = await _json_body(request)
        if not re.fullmatch(r"[1-6]", n) or body is None:
            return _err(400, "invalid_moment")
        step = body.get("step")
        if step is not None and (not isinstance(step, int) or isinstance(step, bool)):
            return _err(400, "invalid_step")
        if bad := await audited(request, "demo_moment", {"n": int(n), "step": step}):
            return bad
        return await acall(backend.demo_moment, int(n), step)

    async def demo_reset(request: Request) -> Response:
        body = await _json_body(request)
        seed = 42 if body is None else body.get("seed", 42)
        if body is None or not isinstance(seed, int) or isinstance(seed, bool):
            return _err(400, "invalid_seed")
        return await call(backend.demo_reset, seed, _actor(request))

    async def auth_login(request: Request) -> Response:
        if accounts is None:
            return _err(503, "auth_unavailable")
        body = await _json_body(request)
        username = None if body is None else body.get("username")
        password = None if body is None else body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return _err(400, "invalid_credentials_format")
        try:
            sid, session = accounts.login(username, password, _client_ip(request))
        except RateLimitedError:
            return _err(429, "rate_limited")
        except AuthError:
            return _err(401, "invalid_credentials")
        old = request.cookies.get(SESSION_COOKIE)
        if old:
            accounts.logout(old)
        resp = JSONResponse(
            {"user_id": session.user_id, "role": session.role, "csrf": session.csrf}
        )
        resp.set_cookie(
            SESSION_COOKIE,
            sid,
            max_age=ABSOLUTE_SECONDS,
            path="/",
            httponly=True,
            samesite="strict",
            secure=os.environ.get("TRISHUL_COOKIE_SECURE") == "1",
        )
        return resp

    async def auth_me(request: Request) -> Response:
        session = _session(request)
        if session is None:
            return _err(401, "not_logged_in")
        return JSONResponse(
            {
                "user_id": session.user_id,
                "username": session.username,
                "role": session.role,
                "csrf": session.csrf,
            }
        )

    async def auth_logout(request: Request) -> Response:
        session = _session(request)
        if session is not None and not _csrf_ok(request, session):
            return _err(403, "csrf_required")
        if accounts is not None:
            accounts.logout(request.cookies.get(SESSION_COOKIE))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="strict")
        return resp

    async def report_dpdp(request: Request) -> Response:
        try:
            report = await run_in_threadpool(backend.dpdp)
        except Exception:
            log.exception("backend error")
            return _err(500, "internal_error")
        return JSONResponse(
            report,
            headers={"Content-Disposition": 'attachment; filename="trishul-dpdp-report.json"'},
        )

    async def tasks(request: Request) -> Response:
        body = await _json_body(request)
        if body is None:
            return _err(400, "invalid_body")
        return await call(backend.bind_task, body)

    async def voice_nonce(request: Request) -> Response:
        body = await _json_body(request)
        session = body.get("session") if body else None
        if not isinstance(session, str) or not _ID.match(session):
            return _err(400, "invalid_session")
        return await call(backend.issue_voice_nonce, session)

    async def audit_verify(request: Request) -> Response:
        return await call(backend.audit_verify)

    async def bench_results(request: Request) -> Response:
        try:
            data = await run_in_threadpool(BENCH_RESULTS.read_bytes)
        except OSError:
            return _err(404, "not_found")
        return Response(data, media_type="application/json")

    async def metrics_route(request: Request) -> Response:
        return JSONResponse({"stages": metrics.percentiles()})

    async def events_ws(ws: WebSocket) -> None:
        if not _origin_ok(ws.headers.get("origin"), origins):
            await ws.close(code=1008)
            return
        await ws.accept()
        loop = asyncio.get_running_loop()
        resume: asyncio.Future[int | None] = loop.create_future()

        async def receiver() -> None:
            try:
                while True:
                    msg = await ws.receive_text()
                    if resume.done():
                        continue
                    try:
                        val = json.loads(msg).get("resume_from")
                    except (ValueError, AttributeError):
                        val = None
                    ok = isinstance(val, int) and not isinstance(val, bool) and val >= 0
                    resume.set_result(val if ok else None)
            except (WebSocketDisconnect, RuntimeError):
                pass
            finally:
                if not resume.done():
                    resume.set_result(None)

        rtask = asyncio.create_task(receiver())
        sub = None
        try:
            try:
                start = await asyncio.wait_for(asyncio.shield(resume), timeout=0.25)
            except TimeoutError:
                start = None
            sub = bus.subscribe(start)
            while not rtask.done():
                nxt = asyncio.ensure_future(sub.__anext__())
                done, _ = await asyncio.wait(
                    {nxt, rtask}, timeout=heartbeat_s, return_when=asyncio.FIRST_COMPLETED
                )
                if nxt in done:
                    try:
                        await ws.send_json(nxt.result())
                    except StopAsyncIteration:
                        break
                    continue
                nxt.cancel()
                if rtask in done:
                    break
                await ws.send_json({"type": "heartbeat", "ts": int(time.time() * 1000)})
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            if sub is not None:
                sub.close()
            rtask.cancel()
            with contextlib.suppress(BaseException):
                await rtask

    routes: list[Any] = [
        WebSocketRoute("/events", events_ws),
        Route("/consent", consent, methods=["GET"]),
        Route("/consent/{id}/withdraw", guarded(operator(withdraw)), methods=["POST"]),
        Route("/approvals", approvals, methods=["GET"]),
        Route("/approvals/{id}", guarded(approver_only(resolve)), methods=["POST"]),
        Route("/auth/login", guarded(auth_login), methods=["POST"]),
        Route("/auth/me", auth_me, methods=["GET"]),
        Route("/auth/logout", guarded(auth_logout), methods=["POST"]),
        Route("/prove", guarded(operator(prove)), methods=["POST"]),
        Route("/healthz", healthz, methods=["GET"]),
        Route("/readyz", readyz, methods=["GET"]),
        Route("/mode", mode_get, methods=["GET"]),
        Route("/mode", guarded(operator(mode_post)), methods=["POST"]),
        Route("/ml", guarded(operator(ml_post)), methods=["POST"]),
        Route("/mandates", mandates, methods=["GET"]),
        Route("/audit/head", audit_head, methods=["GET"]),
        Route("/audit/leaves", audit_leaves, methods=["GET"]),
        Route("/audit/proof/inclusion", audit_inclusion, methods=["GET"]),
        Route("/audit/proof/consistency", audit_consistency, methods=["GET"]),
        Route("/redteam/submit", guarded(operator(redteam_submit)), methods=["POST"]),
        Route("/redteam/kill", guarded(operator(redteam_kill)), methods=["POST"]),
        Route("/redteam/fallback", guarded(operator(redteam_fallback)), methods=["POST"]),
        Route("/redteam/stats", redteam_stats, methods=["GET"]),
        Route("/demo/moment/{n}", guarded(operator(demo_moment)), methods=["POST"]),
        Route("/demo/reset", guarded(operator(demo_reset)), methods=["POST"]),
        Route("/report/dpdp", report_dpdp, methods=["GET"]),
        Route("/tasks", guarded(operator(tasks)), methods=["POST"]),
        Route("/voice/nonce", guarded(voice_nonce), methods=["POST"]),
        Route("/audit/verify", audit_verify, methods=["GET"]),
        Route("/bench/results.json", bench_results, methods=["GET"]),
        # relative link from the landing page served under /console
        Route("/console/bench/results.json", bench_results, methods=["GET"]),
        Route("/metrics", metrics_route, methods=["GET"]),
    ]
    if CONSOLE_DIR.is_dir():  # read-only static console, same-origin with the API
        routes.append(Mount("/console", _NoCacheStatic(directory=CONSOLE_DIR), name="console"))
    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
        )
    ]
    return Starlette(routes=routes, middleware=middleware)
