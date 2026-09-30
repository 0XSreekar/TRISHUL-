"""Approver authentication against the real gateway: the approver id reaches the approval record,
the signed token and a Merkle leaf; operator actions and demo reset are audited."""

import json
from typing import Any

import pytest
from starlette.testclient import TestClient

from tests.integration.test_gateway import ACME, bind_pay
from tests.integration.test_gateway_harness import Env
from tests.unit.test_ws_api import APPROVER_PW, OPERATOR_PW
from trishul.auth.service import user_id_for

ENV = {"TRISHUL_APPROVER_PASSWORD": APPROVER_PW, "TRISHUL_OPERATOR_PASSWORD": OPERATOR_PW}


def leaves(env: Env) -> list[dict[str, Any]]:
    rows = env.conn.execute("SELECT payload FROM audit_leaves ORDER BY idx").fetchall()
    return [json.loads(bytes(r["payload"])) for r in rows]


def client(env: Env) -> TestClient:
    assert env.gw.backend.auth.provision_demo_accounts() == {
        "approver": "created",
        "operator": "created",
    }
    return TestClient(env.gw.api(allowed_origins=["http://localhost:8787"]))


async def test_approver_id_in_record_token_and_merkle_leaf(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    bind_pay(env, amount_paise=750_000)
    args = {"payee_vpa": ACME, "amount_paise": 750_000}
    body = await env.denied("upi_pay_upi", args)
    aid = body["approval_id"]
    approver_id = user_id_for("approver")
    with client(env) as c:
        assert (
            c.post(f"/approvals/{aid}", headers={"authorization": ""}, json={"decision": "approve"})
        ).status_code == 401  # no session: nothing recorded
        assert env.gw.pipeline.approvals.get(aid)["status"] == "pending"
        login = c.post("/auth/login", json={"username": "approver", "password": APPROVER_PW})
        assert login.json()["user_id"] == approver_id
        r = c.post(
            f"/approvals/{aid}",
            headers={"X-CSRF-Token": login.json()["csrf"]},
            json={"decision": "approve"},
        )
        assert r.status_code == 200 and r.json()["status"] == "approved"
    row = env.gw.pipeline.approvals.get(aid)
    assert row["approver"] == approver_id
    token = json.loads(row["token"])
    assert token["approver"] == approver_id  # inside the signed payload
    leaf = next(x for x in leaves(env) if x.get("type") == "approval_resolved")
    assert leaf["approver_id"] == approver_id and leaf["approval_id"] == aid
    assert leaf["call_digest"] == row["call_digest"] and leaf["decision"] == "approved"
    assert leaf["kid"]
    out = await env.call("upi_pay_upi", args)  # the signed token still verifies at the gate
    assert out["balance_after"] == 4_250_000


async def test_operator_actions_and_reset_are_leaves(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    operator_id = user_id_for("operator")
    with client(env) as c:
        assert c.post("/ml", json={"enabled": False}).status_code == 200  # bearer (conftest)
        op = c.post(
            "/auth/login",
            json={"username": "operator", "password": OPERATOR_PW},
            headers={"authorization": ""},
        ).json()
        hdr = {"authorization": "", "X-CSRF-Token": op["csrf"]}
        assert c.post("/mode", json={"mode": "off"}, headers=hdr).status_code == 200
        acts = [x for x in leaves(env) if x.get("type") == "operator_action"]
        assert [(a["action"], a["actor"], a["params"]) for a in acts] == [
            ("ml", "operator-token", {"enabled": False}),
            ("mode", operator_id, {"mode": "off"}),
        ]
        r = c.post("/demo/reset", json={"seed": 42}, headers=hdr)
        assert r.status_code == 200 and r.json()["accounts"]["approver"] == "updated"
        first = leaves(env)[0]  # the fresh log starts with the reset record
        assert first["type"] == "operator_action" and first["action"] == "demo_reset"
        assert first["actor"] == operator_id and first["params"] == {"data_seed": 42}
        assert c.get("/auth/me").json()["role"] == "operator"  # accounts/sessions survive reset
