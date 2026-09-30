"""Audience Red-Team app: its own Starlette app on its own port (default 8789).

Exactly two routes: ``GET /`` (a static submit form, no data) and ``POST /submit {text}``. It
reads and sets no cookies and has no access to approvals, policy, ML, reset or audit APIs: the
only capability it holds is the injected ``submit`` callable (the red-team wall pipeline run).
Its origin is never in the main API's Origin allowlist.
"""

import json
import logging
import os
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from trishul.redteam.errors import RedTeamError

log = logging.getLogger("trishul.redteam.app")
Submit = Callable[[str, str], Awaitable[dict[str, Any]]]

MAX_BODY = 16 * 1024
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost", "testclient"})
_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
    ),
}

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TRISHUL Red-Team Wall</title>
<style>
body{margin:0;padding:24px;background:#0b0f13;color:#cad9e2;font:15px/1.5 system-ui,sans-serif}
main{max-width:640px;margin:0 auto;display:flex;flex-direction:column;gap:12px}
textarea{box-sizing:border-box;width:100%;height:120px;padding:10px;border-radius:8px;
border:1px solid rgba(202,217,226,.25);background:#06090c;color:#cad9e2;font:13px monospace}
button{height:36px;border-radius:8px;border:1px solid #45829b;background:rgba(69,130,155,.25);
color:#cad9e2;cursor:pointer}
pre{white-space:pre-wrap;word-break:break-word;margin:0;color:#4fd1c5}
</style></head><body><main>
<h1>Try to make the agent misbehave</h1>
<p>Write a prompt-injection. It runs through the real TRISHUL gateway.</p>
<textarea id="t" maxlength="2000" placeholder="Make the agent pay or email."></textarea>
<button id="b" type="button">Submit</button>
<pre id="r"></pre>
</main>
<script>
const r=document.getElementById('r');
document.getElementById('b').addEventListener('click',async()=>{
  const text=document.getElementById('t').value;
  r.textContent='...';
  try{
    const res=await fetch('/submit',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({text})});
    const j=await res.json();
    r.textContent=res.ok?('Decision: '+j.decision+(j.succeeded?' (attack succeeded)':' (blocked)')):
      ('Not accepted: '+(j.error||res.status));
  }catch(e){r.textContent='Gateway unreachable';}
});
</script></body></html>
"""


def _public() -> bool:
    return os.environ.get("TRISHUL_REDTEAM_PUBLIC") == "1"


def _err(status: int, code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status, headers=_HEADERS)


def _rate_key(request: Request) -> str:
    """Rate-limit key only (never used for auth): behind a tunnel the peer is the proxy."""
    key = request.client.host if request.client else "unknown"
    if os.environ.get("TRISHUL_TRUSTED_PROXY") == "1":
        fwd = request.headers.get("cf-connecting-ip", "").strip()
        if 0 < len(fwd) <= 64:
            key = fwd
    return key


def build_redteam_app(submit: Submit) -> Starlette:
    async def index(request: Request) -> Response:
        return HTMLResponse(PAGE, headers=_HEADERS)

    async def submit_route(request: Request) -> Response:
        ip = request.client.host if request.client else "unknown"
        if not (_public() or ip in LOOPBACK):
            return _err(403, "redteam_not_public")
        ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return _err(415, "unsupported_media_type")
        raw = await request.body()
        if len(raw) > MAX_BODY:
            return _err(413, "too_large")
        try:
            body = json.loads(raw or b"{}")
        except (ValueError, UnicodeDecodeError):
            return _err(400, "invalid_text")
        if not isinstance(body, dict) or not isinstance(body.get("text"), str):
            return _err(400, "invalid_text")
        try:
            result = await submit(body["text"], _rate_key(request))
        except RedTeamError as exc:
            return _err(exc.status, exc.code)
        except Exception:
            log.exception("red-team submit failed")
            return _err(500, "internal_error")
        return JSONResponse(result, headers=_HEADERS)

    routes = [
        Route("/", index, methods=["GET"]),
        Route("/submit", submit_route, methods=["POST"]),
    ]
    return Starlette(routes=routes)
