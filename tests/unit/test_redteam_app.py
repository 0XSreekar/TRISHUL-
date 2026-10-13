"""The audience Red-Team app: its own app, exactly two routes, no cookies, no other APIs."""

from typing import Any

from starlette.routing import Route
from starlette.testclient import TestClient

from trishul.redteam.app import build_redteam_app
from trishul.redteam.errors import RedTeamError
from trishul.telemetry.api import DEFAULT_ORIGINS, build_api
from trishul.telemetry.events import EventBus
from trishul.telemetry.otel import setup_tracing


class Recorder:
    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []

    async def __call__(self, text: str, key: str) -> dict[str, Any]:
        self.seen.append((text, key))
        if text == "limited":
            raise RedTeamError("rate_limited", 429)
        if text == "boom":
            raise RuntimeError("secret internal path /etc/passwd")
        return {"decision": "DENY", "succeeded": False}


def test_redteam_app_route_set_is_exactly_the_two_routes() -> None:
    app = build_redteam_app(Recorder())
    routes = [r for r in app.routes if isinstance(r, Route)]
    assert len(app.routes) == 2
    shape = {r.path: sorted(m for m in (r.methods or set()) if m != "HEAD") for r in routes}
    assert shape == {"/": ["GET"], "/submit": ["POST"]}
    assert app.user_middleware == []


def test_index_is_static_and_sets_no_cookie() -> None:
    with TestClient(build_redteam_app(Recorder())) as c:
        r = c.get("/")
        assert r.status_code == 200 and "<textarea" in r.text
        assert "set-cookie" not in r.headers
        assert "default-src 'none'" in r.headers["content-security-policy"]
        assert ".innerHTML" not in r.text


def test_submit_runs_the_injected_callable_and_ignores_cookies() -> None:
    rec = Recorder()
    with TestClient(build_redteam_app(rec)) as c:
        c.cookies.set("trishul_session", "x")
        r = c.post("/submit", json={"text": "hello"})
        assert r.status_code == 200 and r.json()["decision"] == "DENY"
        assert "set-cookie" not in r.headers
    assert rec.seen == [("hello", "testclient")]


def test_submit_validation_and_error_mapping() -> None:
    with TestClient(build_redteam_app(Recorder())) as c:
        assert c.post("/submit", json={"text": 5}).status_code == 400
        assert c.post("/submit", json={}).status_code == 400
        assert (
            c.post(
                "/submit", content=b"{", headers={"content-type": "application/json"}
            ).status_code
            == 400
        )
        assert (
            c.post(
                "/submit", content=b'{"text":"a"}', headers={"content-type": "text/plain"}
            ).status_code
            == 415
        )
        assert c.post("/submit", json={"text": "x" * 20_000}).status_code == 413
        assert c.post("/submit", json={"text": "limited"}).status_code == 429
        r = c.post("/submit", json={"text": "boom"})
        assert r.status_code == 500 and "passwd" not in r.text


def test_other_paths_do_not_exist_on_the_audience_port() -> None:
    with TestClient(build_redteam_app(Recorder())) as c:
        for path in ("/approvals", "/mode", "/audit/head", "/auth/login", "/demo/reset", "/events"):
            assert c.get(path).status_code == 404, path
            assert c.post(path, json={}).status_code == 404, path
        assert c.get("/submit").status_code == 405


def test_main_api_has_no_public_redteam_submit_and_no_audience_origin() -> None:
    from tests.unit.test_ws_api import FakeBackend

    _, metrics = setup_tracing()
    app = build_api(EventBus(), metrics, FakeBackend(), allowed_origins=list(DEFAULT_ORIGINS))
    with TestClient(app) as c:
        r = c.post("/redteam/submit", headers={"authorization": ""}, json={"text": "x"})
        assert r.status_code == 401  # operator-only now, never public
    assert "http://localhost:8789" not in DEFAULT_ORIGINS
