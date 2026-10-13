"""Operator routes require a bearer token regardless of client address."""

from starlette.testclient import TestClient

from tests.unit.test_ws_api import FakeBackend
from trishul.telemetry.api import build_api
from trishul.telemetry.events import EventBus
from trishul.telemetry.otel import setup_tracing

JSON = {"Content-Type": "application/json"}
ROUTES = ["/mode", "/consent/k1/withdraw", "/prove", "/approvals/a1", "/demo/reset"]


def _client(**headers):
    _, metrics = setup_tracing()
    app = build_api(EventBus(), metrics, FakeBackend(), allowed_origins=["null"])
    return TestClient(app, headers=headers)


def test_missing_token_rejected():
    c = _client(authorization="")
    for r in ROUTES:
        assert c.post(r, headers=JSON, json={}).status_code == 401, r


def test_wrong_token_rejected():
    c = _client(authorization="Bearer nope")
    for r in ROUTES:
        assert c.post(r, headers=JSON, json={}).status_code == 401, r


def test_unconfigured_token_fails_closed(monkeypatch):
    monkeypatch.delenv("TRISHUL_OPERATOR_TOKEN")
    assert _client().post("/mode", headers=JSON, json={"mode": "on"}).status_code == 401


def test_right_token_ok():
    c = _client()
    assert c.post("/prove", headers=JSON, json={}).status_code == 200
    assert c.post("/consent/k1/withdraw", headers=JSON).status_code == 200


def test_bench_results_served():
    r = _client(authorization="").get("/bench/results.json")
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert isinstance(r.json(), dict)


def test_bench_results_missing(monkeypatch, tmp_path):
    import trishul.telemetry.api as api

    monkeypatch.setattr(api, "BENCH_RESULTS", tmp_path / "none.json")
    assert _client().get("/bench/results.json").status_code == 404
