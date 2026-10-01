import sqlite3

import pytest
from starlette.testclient import TestClient

from trishul.auth import AuthService
from trishul.telemetry.api import DEFAULT_ORIGINS, build_api
from trishul.telemetry.events import EventBus
from trishul.telemetry.otel import setup_tracing, stage_span

APPROVER_PW = "approver-password-1"
OPERATOR_PW = "operator-password-1"


def make_auth() -> AuthService:
    conn = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    auth = AuthService(conn)
    auth.provision_demo_accounts(
        {"TRISHUL_APPROVER_PASSWORD": APPROVER_PW, "TRISHUL_OPERATOR_PASSWORD": OPERATOR_PW}
    )
    return auth


def login(c, username="approver", password=APPROVER_PW):
    """Log in (cookie lands in the client's jar) and return the CSRF header for POSTs."""
    r = c.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": r.json()["csrf"]}


class FakeBackend:
    def __init__(self):
        self.calls = []
        self.actions = []
        self.mode_calls = []
        self.auth = make_auth()

    def set_mode(self, mode):
        self.mode_calls.append(mode)
        return {"mode": mode}

    def set_ml(self, enabled):
        return None

    def redteam_kill(self, on):
        return {"killed": on}

    async def redteam_fallback(self, count=None):
        return []

    async def demo_moment(self, n, step=None):
        return {"moment": n}

    def record_operator_action(self, action, actor, params):
        self.actions.append((action, actor, params))

    def demo_reset(self, seed, actor="operator"):
        self.actions.append(("demo_reset", actor, {"seed": seed}))
        return {"reset": True, "seed": seed}

    def list_consent(self):
        return [{"id": "k1", "status": "active"}]

    def withdraw_consent(self, consent_id):
        if consent_id == "missing":
            raise KeyError(consent_id)
        return {"id": consent_id, "status": "withdrawn"}

    def list_approvals(self):
        return [{"id": "a1"}]

    def resolve_approval(self, approval_id, decision, approver):
        self.calls.append((approval_id, decision, approver))
        if approval_id == "boom":
            raise RuntimeError("secret internal path /etc/passwd")
        return {"id": approval_id, "decision": decision}

    def prove(self, policy="live"):
        return {"proved": True}

    def bind_task(self, payload):
        return {"task": payload}

    def issue_voice_nonce(self, session):
        return {"nonce": "n-" + session}

    def audit_verify(self):
        return {"ok": True}


def user_id(be, username):
    return be.auth.conn.execute(
        "SELECT user_id FROM users WHERE username=?", (username,)
    ).fetchone()[0]


@pytest.fixture
def env():
    bus = EventBus()
    provider, metrics = setup_tracing()
    be = FakeBackend()
    app = build_api(bus, metrics, be, allowed_origins=["null", "http://localhost"])
    with TestClient(app) as c:
        c.headers.update(login(c))
        yield c, bus, metrics, be, provider


def test_rest_routes(env):
    c, _, _, be, _ = env
    assert c.get("/consent").json() == {"consent": [{"id": "k1", "status": "active"}]}
    assert (
        c.post("/consent/k1/withdraw", headers={"Content-Type": "application/json"}).json()[
            "status"
        ]
        == "withdrawn"
    )
    assert (
        c.post(
            "/consent/missing/withdraw", headers={"Content-Type": "application/json"}
        ).status_code
        == 404
    )
    assert (
        c.post(
            "/consent/bad id!/withdraw", headers={"Content-Type": "application/json"}
        ).status_code
        == 400
    )
    assert c.get("/approvals").json() == {"approvals": [{"id": "a1"}]}
    assert c.post("/approvals/a1", json={"decision": "approve"}).json()["decision"] == "approve"
    assert be.calls == [("a1", "approve", user_id(be, "approver"))]
    assert c.post("/prove", headers={"Content-Type": "application/json"}).json() == {"proved": True}
    assert c.post("/tasks", json={"goal": "x"}).json() == {"task": {"goal": "x"}}
    assert c.post("/voice/nonce", json={"session": "s1"}).json() == {"nonce": "n-s1"}
    assert c.get("/audit/verify").json() == {"ok": True}


def test_rest_400s_and_no_leak(env):
    c = env[0]
    assert c.post("/approvals/a1", json={"decision": "maybe"}).status_code == 400
    assert c.post("/approvals/a1", json={"decision": "approve", "approver": "x"}).status_code == 200
    assert (
        c.post(
            "/approvals/a1", content=b"not json", headers={"Content-Type": "application/json"}
        ).status_code
        == 400
    )
    assert c.post("/approvals/a1", json=["x"]).status_code == 400
    assert (
        c.post("/tasks", content=b"[1]", headers={"Content-Type": "application/json"}).status_code
        == 400
    )
    assert c.post("/voice/nonce", json={}).status_code == 400
    assert c.post("/voice/nonce", json={"session": 5}).status_code == 400
    r = c.post("/approvals/boom", json={"decision": "reject"})
    assert r.status_code == 500 and "passwd" not in r.text


def test_metrics(env):
    c, _, _, _, provider = env
    assert c.get("/metrics").json() == {"stages": {}}
    tracer = provider.get_tracer("t")
    with stage_span(tracer, "policy", correlation_id="c", tool="t"):
        pass
    assert c.get("/metrics").json()["stages"]["policy"]["n"] == 1


def test_cors(env):
    c = env[0]
    r = c.get("/consent", headers={"Origin": "null"})
    assert r.headers.get("access-control-allow-origin") == "null"
    r = c.get("/consent", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_ws_stream_and_resume(env):
    c, bus, *_ = env
    for i in range(3):
        bus.publish({"type": "call", "id": f"c{i}", "tool": "t"})
    with c.websocket_connect("/events") as ws:
        ws.send_json({"resume_from": 1})
        assert [ws.receive_json()["seq"] for _ in range(2)] == [2, 3]
        bus.publish({"type": "call", "id": "c3", "tool": "<t>"})
        e = ws.receive_json()
        assert e["seq"] == 4 and e["tool"] == "&lt;t&gt;"


def test_ws_live_without_resume_and_heartbeat():
    bus = EventBus()
    _, metrics = setup_tracing()
    app = build_api(bus, metrics, FakeBackend(), allowed_origins=["null"], heartbeat_s=0.2)
    with TestClient(app) as c, c.websocket_connect("/events") as ws:
        assert ws.receive_json()["type"] == "heartbeat"
        bus.publish({"type": "ml_state", "ml": True})
        while (m := ws.receive_json())["type"] == "heartbeat":
            pass
        assert m["type"] == "ml_state"


def test_ws_rejects_bad_origin(env):
    c = env[0]
    from starlette.websockets import WebSocketDisconnect

    with (
        pytest.raises(WebSocketDisconnect),
        c.websocket_connect("/events", headers={"origin": "http://evil.example"}),
    ):
        pass


# --- CSRF: origin allowlist + JSON content-type on every POST ---------------------------


@pytest.fixture
def csrf():
    _, metrics = setup_tracing()
    be = FakeBackend()
    with TestClient(
        build_api(
            EventBus(), metrics, be, allowed_origins=[*DEFAULT_ORIGINS, "http://localhost:8787"]
        )
    ) as c:
        c.headers.update(login(c))
        yield c, be


def test_cross_origin_text_plain_approve_rejected(csrf) -> None:
    c, be = csrf
    r = c.post(
        "/approvals/a1",
        content=b'{"decision":"approve"}',
        headers={"Origin": "https://evil.example", "Content-Type": "text/plain"},
    )
    assert r.status_code == 403 and be.calls == []  # approval still pending


def test_cross_origin_json_rejected(csrf) -> None:
    c, be = csrf
    r = c.post(
        "/approvals/a1",
        json={"decision": "approve"},
        headers={"Origin": "https://evil.example"},
    )
    assert r.status_code == 403 and be.calls == []


def test_null_origin_rejected(csrf) -> None:
    c, be = csrf
    r = c.post("/approvals/a1", json={"decision": "approve"}, headers={"Origin": "null"})
    assert r.status_code == 403 and be.calls == []


def test_text_plain_without_origin_is_415(csrf) -> None:
    c, be = csrf
    for path in ("/approvals/a1", "/tasks", "/prove", "/voice/nonce", "/consent/k1/withdraw"):
        r = c.post(path, content=b'{"decision":"approve"}', headers={"Content-Type": "text/plain"})
        assert r.status_code == 415, path
    assert c.post("/approvals/a1", content=b"{}").status_code == 415
    assert be.calls == []


def test_same_origin_and_no_origin_json_accepted(csrf) -> None:
    c, be = csrf
    ok = c.post(
        "/approvals/a1",
        json={"decision": "approve"},
        headers={"Origin": "http://localhost:8787"},
    )
    assert ok.status_code == 200
    ok = c.post("/approvals/a2", json={"decision": "reject"})
    assert ok.status_code == 200
    assert [x[0] for x in be.calls] == ["a1", "a2"]


def test_console_served_read_only(csrf) -> None:
    c, _ = csrf
    assert c.get("/console/Trishul-Console.dc.html").status_code == 200
    assert c.post("/console/Trishul-Console.dc.html", json={}).status_code in (403, 405)
    assert c.get("/console/../CLAUDE.md").status_code == 404


def test_bodyless_console_posts_need_allowed_origin(csrf) -> None:
    """The console's /prove and /consent/{id}/withdraw send no body and no Content-Type."""
    c, be = csrf
    same = {"Origin": "http://localhost:8787"}
    assert c.post("/prove", headers=same).status_code == 200
    assert c.post("/consent/k1/withdraw", headers=same).status_code == 200
    evil = {"Origin": "https://evil.example"}
    calls = len(be.calls)
    assert c.post("/prove", headers=evil).status_code == 403
    assert c.post("/consent/k1/withdraw", headers=evil).status_code == 403
    assert len(be.calls) == calls


# --- AT-17: reconnect/resume + CLI `ml off` pushes a live ml_state -----------------------------


def _dbpath(conn) -> str:
    return next(r[2] for r in conn.execute("PRAGMA database_list") if r[1] == "main")


@pytest.mark.acceptance("S-WS")
def test_at17_ws_reconnect_resumes_after_last_seq(tmp_path):
    from tests.integration.test_gateway_harness import make_env_sync

    gw, *_ = make_env_sync(tmp_path)
    with TestClient(gw.api(allowed_origins=["null"])) as c:
        gw.bus.publish({"type": "mode", "mode": "on"})
        with c.websocket_connect("/events") as ws:
            ws.send_json({"resume_from": 0})
            first = ws.receive_json()
        last = first["seq"]
        gw.bus.publish({"type": "ml_state", "ml": False, "enabled": False})  # while disconnected
        gw.bus.publish({"type": "mode", "mode": "off"})
        with c.websocket_connect("/events") as ws:
            ws.send_json({"resume_from": last})
            got = [ws.receive_json(), ws.receive_json()]
        assert [g["seq"] for g in got] == [last + 1, last + 2]
        assert got[0]["type"] == "ml_state" and got[0]["enabled"] is False


@pytest.mark.acceptance("S-WS")
def test_at17_cli_ml_off_is_pushed_live_via_control_table(tmp_path, capsys):
    from tests.integration.test_gateway_harness import make_env_sync
    from trishul.cli.main import main

    gw, conn, *_ = make_env_sync(tmp_path)
    with TestClient(gw.api(allowed_origins=["null"])) as c, c.websocket_connect("/events") as ws:
        ws.send_json({"resume_from": gw.bus.seq})
        assert main(["ml", "off", "--db", _dbpath(conn)]) == 0
        capsys.readouterr()
        assert gw.pipeline.ml_enabled() is False  # CLI applied it durably
        assert gw.backend.poll_control() == 1  # the gateway's 500 ms poll, run once
        while (m := ws.receive_json())["type"] != "ml_state":
            pass
        assert m["ml"] is False and m["enabled"] is False
        assert gw.backend.poll_control() == 0  # rows are applied exactly once
        assert main(["ml", "on", "--db", _dbpath(conn)]) == 0
        gw.backend.poll_control()
        while (m := ws.receive_json())["type"] != "ml_state":
            pass
        assert m["enabled"] is True


@pytest.mark.acceptance("S-WS")
async def test_at17_control_poller_task_publishes_within_interval(tmp_path):
    import asyncio

    from tests.integration.test_gateway_harness import make_env_sync
    from trishul.cli.main import main

    gw, conn, *_ = make_env_sync(tmp_path)
    seen: list[dict] = []
    sub = gw.bus.subscribe(gw.bus.seq)
    task = asyncio.create_task(gw.backend.run_control_poller(0.05))
    try:
        assert await asyncio.to_thread(main, ["ml", "off", "--db", _dbpath(conn)]) == 0
        async with asyncio.timeout(3):
            async for event in sub:
                if event.get("type") == "ml_state":
                    seen.append(event)
                    break
    finally:
        task.cancel()
        sub.close()
    assert seen and seen[0]["enabled"] is False


def test_rest_ml_toggle_pushes_ml_state(tmp_path):
    from tests.integration.test_gateway_harness import make_env_sync

    gw, *_ = make_env_sync(tmp_path)
    with TestClient(gw.api(allowed_origins=["null"])) as c:
        assert c.post("/ml", json={"enabled": "no"}).status_code == 400
        assert c.post("/ml", json={"enabled": False}).json() == {"ml": False}
        assert gw.pipeline.ml_enabled() is False
    assert any(e["type"] == "ml_state" and e["enabled"] is False for e in gw.bus.snapshot(0))
