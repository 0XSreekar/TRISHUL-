"""Approver authentication, route separation and operator-action auditing (Phase 4 section 3)."""

import logging

import pytest
from starlette.testclient import TestClient

from tests.conftest import OP_TOKEN
from tests.unit.test_ws_api import (
    APPROVER_PW,
    OPERATOR_PW,
    FakeBackend,
    login,
    make_auth,
    user_id,
)
from trishul.auth import AuthService, hash_password, verify_password
from trishul.auth.service import ABSOLUTE_SECONDS, IDLE_SECONDS, LOGIN_PER_MINUTE
from trishul.telemetry.api import DEFAULT_ORIGINS, build_api
from trishul.telemetry.events import EventBus
from trishul.telemetry.otel import setup_tracing

CONSOLE = "http://localhost:8787"
AUDIENCE = "http://localhost:8789"
NO_BEARER = {"authorization": ""}


def _app(be: FakeBackend | None = None):
    be = be or FakeBackend()
    _, metrics = setup_tracing()
    app = build_api(EventBus(), metrics, be, allowed_origins=[*DEFAULT_ORIGINS, CONSOLE])
    return app, be


@pytest.fixture
def api():
    app, be = _app()
    with TestClient(app) as c:
        yield c, be


# --- section 3 acceptance tests ---------------------------------------------------------


def test_unauthenticated_approve_is_401(api) -> None:
    c, be = api
    r = c.post("/approvals/a1", json={"decision": "approve"})
    assert r.status_code == 401 and be.calls == []


def test_audience_origin_approve_is_403(api) -> None:
    c, be = api
    csrf = login(c)  # even a valid approver session + CSRF cannot be driven from the audience port
    r = c.post("/approvals/a1", json={"decision": "approve"}, headers={**csrf, "Origin": AUDIENCE})
    assert r.status_code == 403 and r.json() == {"error": "forbidden_origin"} and be.calls == []


def test_csrf_less_approve_is_403(api) -> None:
    c, be = api
    login(c)
    assert c.post("/approvals/a1", json={"decision": "approve"}).status_code == 403
    wrong = {"X-CSRF-Token": "not-the-token"}
    assert c.post("/approvals/a1", json={"decision": "approve"}, headers=wrong).status_code == 403
    assert be.calls == []


def test_operator_token_cannot_approve(api) -> None:
    c, be = api
    # the bearer token is sent by default (conftest); it is not an approver credential
    assert c.headers["authorization"] == f"Bearer {OP_TOKEN}"
    r = c.post("/approvals/a1", json={"decision": "approve"})
    assert r.status_code == 401
    # an operator-role session (with CSRF) is not an approver either
    hdr = login(c, "operator", OPERATOR_PW)
    r = c.post("/approvals/a1", json={"decision": "approve"}, headers=hdr)
    assert r.status_code == 403 and r.json() == {"error": "forbidden_role"}
    assert be.calls == []


OPERATOR_POSTS = [
    ("/mode", {"mode": "off"}),
    ("/ml", {"enabled": False}),
    ("/prove", {"policy": "unsafe_fixture"}),
    ("/demo/reset", {"seed": 42}),
    ("/demo/moment/1", {}),
    ("/redteam/kill", {"on": True}),
    ("/redteam/fallback", {}),
    ("/consent/k1/withdraw", {}),
]


def test_approver_cannot_run_operator_actions(api) -> None:
    c, be = api
    hdr = {**login(c), **NO_BEARER}
    for path, body in OPERATOR_POSTS:
        r = c.post(path, json=body, headers=hdr)
        assert r.status_code == 403, path
    assert be.actions == []


def test_operator_session_needs_csrf_and_is_audited(api) -> None:
    c, be = api
    hdr = login(c, "operator", OPERATOR_PW)
    assert c.post("/mode", json={"mode": "on"}, headers=NO_BEARER).status_code == 403  # no CSRF
    assert be.actions == []
    r = c.post("/mode", json={"mode": "on"}, headers={**hdr, **NO_BEARER})
    assert r.status_code == 200
    (action, actor, params) = be.actions[0]
    assert (action, params) == ("mode", {"mode": "on"}) and actor == user_id(be, "operator")


def test_operator_actions_audited(api) -> None:
    c, be = api
    cases = [
        ("/mode", {"mode": "off"}, "mode", {"mode": "off"}),
        ("/ml", {"enabled": False}, "ml", {"enabled": False}),
        ("/prove", {"policy": "unsafe_fixture"}, "prove", {"policy": "unsafe_fixture"}),
        ("/demo/reset", {"seed": 42}, "demo_reset", {"seed": 42}),
        ("/demo/moment/3", {"step": 2}, "demo_moment", {"n": 3, "step": 2}),
        ("/redteam/kill", {"on": True}, "redteam_kill", {"on": True}),
        ("/redteam/fallback", {"count": 2}, "redteam_fallback", {"count": 2}),
    ]
    for path, body, action, params in cases:
        be.actions.clear()
        r = c.post(path, json=body)
        assert r.status_code == 200, (path, r.text)
        assert be.actions == [(action, "operator-token", params)], path
    # the live proof is read-only and not an operator action
    be.actions.clear()
    assert c.post("/prove", json={"policy": "live"}).status_code == 200
    assert be.actions == []


def test_operator_action_refused_when_audit_unavailable(api) -> None:
    c, be = api

    def boom(*_a, **_k):
        raise RuntimeError("disk full")

    be.record_operator_action = boom
    r = c.post("/mode", json={"mode": "off"})
    assert r.status_code == 500 and be.mode_calls == []


# --- login / session behaviour ------------------------------------------------------------


def test_login_cookie_flags_and_body(api) -> None:
    c, _ = api
    r = c.post("/auth/login", json={"username": "approver", "password": APPROVER_PW})
    assert r.status_code == 200
    body = r.json()
    assert body["role"] == "approver" and len(body["csrf"]) >= 32
    cookie = r.headers["set-cookie"]
    flags = cookie.lower()
    assert cookie.startswith("trishul_session=") and "httponly" in flags
    assert "samesite=strict" in flags and "path=/" in flags and "secure" not in flags
    assert len(cookie.split("=", 1)[1].split(";")[0]) >= 43  # 256-bit urlsafe token
    me = c.get("/auth/me")
    assert me.json()["username"] == "approver" and me.json()["csrf"] == body["csrf"]


def test_cookie_secure_when_configured(api, monkeypatch) -> None:
    monkeypatch.setenv("TRISHUL_COOKIE_SECURE", "1")
    c, _ = api
    r = c.post("/auth/login", json={"username": "approver", "password": APPROVER_PW})
    assert "secure" in r.headers["set-cookie"].lower()


def test_login_failures_are_uniform_and_never_logged(api, caplog) -> None:
    c, _ = api
    caplog.set_level(logging.DEBUG)
    secret = "distinct-wrong-password-xyz"
    unknown = c.post("/auth/login", json={"username": "nobody", "password": secret})
    wrong = c.post("/auth/login", json={"username": "approver", "password": secret})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json() == {"error": "invalid_credentials"}
    assert "set-cookie" not in unknown.headers and "set-cookie" not in wrong.headers
    assert secret not in caplog.text and APPROVER_PW not in caplog.text
    assert c.post("/auth/login", json={"username": 5, "password": "x"}).status_code == 400


def test_login_rate_limited_per_client(api) -> None:
    c, _ = api
    codes = [
        c.post("/auth/login", json={"username": "approver", "password": "wrong-password-0"})
        for _ in range(LOGIN_PER_MINUTE + 1)
    ]
    assert [r.status_code for r in codes[:-1]] == [401] * LOGIN_PER_MINUTE
    assert codes[-1].status_code == 429
    # the right password is also refused while limited
    good = c.post("/auth/login", json={"username": "approver", "password": APPROVER_PW})
    assert good.status_code == 429


def test_logout_ends_the_session(api) -> None:
    c, be = api
    hdr = login(c)
    assert c.post("/auth/logout", json={}).status_code == 403  # CSRF required
    assert c.post("/auth/logout", json={}, headers=hdr).status_code == 200
    assert c.get("/auth/me").status_code == 401
    r = c.post("/approvals/a1", json={"decision": "approve"}, headers=hdr)
    assert r.status_code == 401 and be.calls == []


def test_approved_call_records_the_session_user(api) -> None:
    c, be = api
    hdr = login(c)
    assert c.post("/approvals/a1", json={"decision": "approve"}, headers=hdr).status_code == 200
    assert be.calls == [("a1", "approve", user_id(be, "approver"))]


def test_no_accounts_fails_closed() -> None:
    be = FakeBackend()
    conn = be.auth.conn
    conn.execute("DELETE FROM sessions")
    conn.execute("DELETE FROM users")
    app, _ = _app(be)
    with TestClient(app) as c:
        r = c.post("/auth/login", json={"username": "approver", "password": APPROVER_PW})
        assert r.status_code == 401
        assert c.post("/approvals/a1", json={"decision": "approve"}).status_code == 401


# --- service -------------------------------------------------------------------------------


def test_passwords_are_argon2id_and_min_12() -> None:
    h = hash_password("a-long-enough-pw")
    assert h.startswith("$argon2id$") and verify_password(h, "a-long-enough-pw")
    assert not verify_password(h, "a-long-enough-pX") and not verify_password("junk", "x")
    with pytest.raises(ValueError):
        hash_password("short-pw-11")  # 11 characters
    auth = make_auth()
    rows = auth.conn.execute("SELECT pw_hash FROM users").fetchall()
    assert rows and all(r[0].startswith("$argon2id$") for r in rows)
    assert APPROVER_PW not in "".join(r[0] for r in rows)


def test_provisioning_needs_env_and_length() -> None:
    auth = make_auth()
    out = auth.provision_demo_accounts({})
    assert all(v.startswith("not created: set TRISHUL_") for v in out.values())
    out = auth.provision_demo_accounts({"TRISHUL_APPROVER_PASSWORD": "short"})
    assert out["approver"].startswith("not created") and "12" in out["approver"]
    assert "short" not in " ".join(out.values())
    out = auth.provision_demo_accounts({"TRISHUL_APPROVER_PASSWORD": "a-new-approver-pw"})
    assert out["approver"] == "updated"
    assert auth.authenticate("approver", "a-new-approver-pw", role="approver") is not None
    assert auth.authenticate("approver", APPROVER_PW) is None


def test_sessions_expire_idle_and_absolute() -> None:
    now = [1_000.0]
    auth = make_auth()
    auth.clock = lambda: now[0]
    sid, _ = auth.login("approver", APPROVER_PW, "k1")
    now[0] += IDLE_SECONDS - 1
    assert auth.session(sid) is not None  # touching keeps it alive
    now[0] += IDLE_SECONDS - 1
    assert auth.session(sid) is not None
    now[0] += IDLE_SECONDS
    assert auth.session(sid) is None  # idle
    sid, _ = auth.login("approver", APPROVER_PW, "k2")
    for _ in range(ABSOLUTE_SECONDS // (IDLE_SECONDS - 1)):
        now[0] += IDLE_SECONDS - 1
        auth.session(sid)
    now[0] += IDLE_SECONDS - 1
    assert auth.session(sid) is None  # absolute 8 h


def test_session_id_stored_only_as_hash() -> None:
    auth = make_auth()
    sid, _ = auth.login("approver", APPROVER_PW, "k")
    stored = auth.conn.execute("SELECT sid_sha256 FROM sessions").fetchone()[0]
    assert stored != sid and len(stored) == 64
    assert isinstance(auth, AuthService)


def test_redaction_covers_hashes_and_session_cookie() -> None:
    from trishul.contracts.patterns import scrub_text

    h = hash_password("another-long-pw")
    assert h not in scrub_text(f"hash={h}") and "REDACTED:password_hash" in scrub_text(h)
    assert "abc123" not in scrub_text("Cookie: trishul_session=abc123xyz")


pytestmark = pytest.mark.acceptance(8)
