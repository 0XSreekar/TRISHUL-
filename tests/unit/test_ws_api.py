import pytest
from starlette.testclient import TestClient

from trishul.telemetry.api import DEFAULT_ORIGINS, build_api
from trishul.telemetry.events import EventBus
from trishul.telemetry.otel import setup_tracing, stage_span


class FakeBackend:
    def __init__(self):
        self.calls = []

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

    def prove(self):
        return {"proved": True}

    def bind_task(self, payload):
        return {"task": payload}

    def issue_voice_nonce(self, session):
        return {"nonce": "n-" + session}

    def audit_verify(self):
        return {"ok": True}


@pytest.fixture
def env():
    bus = EventBus()
    provider, metrics = setup_tracing()
    be = FakeBackend()
    app = build_api(bus, metrics, be, allowed_origins=["null", "http://localhost"])
    with TestClient(app) as c:
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
    assert be.calls == [("a1", "approve", "console")]
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
