"""Starlette REST + WebSocket API consumed by the console."""

import asyncio
import contextlib
import json
import logging
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

from trishul.telemetry.events import EventBus
from trishul.telemetry.otel import StageMetrics

log = logging.getLogger("trishul.telemetry.api")
DEFAULT_ORIGINS = ["http://localhost", "http://127.0.0.1"]
CONSOLE_DIR = Path(__file__).resolve().parents[2] / "Landing page and dashboard implementation"
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_MAX_BODY = 256 * 1024


class GatewayBackend(Protocol):
    def list_consent(self) -> list[dict[str, Any]]: ...
    def withdraw_consent(self, consent_id: str) -> dict[str, Any]: ...
    def list_approvals(self) -> list[dict[str, Any]]: ...
    def resolve_approval(
        self, approval_id: str, decision: Literal["approve", "reject"], approver: str
    ) -> dict[str, Any]: ...
    def prove(self) -> dict[str, Any]: ...
    def bind_task(self, payload: dict[str, Any]) -> dict[str, Any]: ...
    def issue_voice_nonce(self, session: str) -> dict[str, Any]: ...
    def audit_verify(self) -> dict[str, Any]: ...


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
) -> Starlette:
    origins = list(allowed_origins) if allowed_origins is not None else list(DEFAULT_ORIGINS)

    def guarded(
        handler: Callable[[Request], Awaitable[Response]],
    ) -> Callable[[Request], Awaitable[Response]]:
        """CSRF defence for state-changing routes: a present Origin must be allowlisted and the
        body must be declared JSON (forces a CORS preflight from browsers). No Origin = CLI."""

        async def wrapper(request: Request) -> Response:
            if not _origin_ok(request.headers.get("origin"), origins):
                return _err(403, "forbidden_origin")
            ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
            if ctype != "application/json":
                return _err(415, "unsupported_media_type")
            return await handler(request)

        return wrapper

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
        # approver is fixed: approvals are out-of-band console actions only
        return await call(backend.resolve_approval, aid, body["decision"], "console")

    async def prove(request: Request) -> Response:
        return await call(backend.prove)

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
        Route("/consent/{id}/withdraw", guarded(withdraw), methods=["POST"]),
        Route("/approvals", approvals, methods=["GET"]),
        Route("/approvals/{id}", guarded(resolve), methods=["POST"]),
        Route("/prove", guarded(prove), methods=["POST"]),
        Route("/tasks", guarded(tasks), methods=["POST"]),
        Route("/voice/nonce", guarded(voice_nonce), methods=["POST"]),
        Route("/audit/verify", audit_verify, methods=["GET"]),
        Route("/metrics", metrics_route, methods=["GET"]),
    ]
    if CONSOLE_DIR.is_dir():  # read-only static console, same-origin with the API
        routes.append(Mount("/console", StaticFiles(directory=CONSOLE_DIR), name="console"))
    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type"],
        )
    ]
    return Starlette(routes=routes, middleware=middleware)
