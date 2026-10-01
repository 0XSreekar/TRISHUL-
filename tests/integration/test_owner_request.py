"""Audience page, owner tab: a typed owner request is decided by the real gateway."""

import pytest
from starlette.testclient import TestClient

from tests.integration.test_gateway_harness import Env
from trishul.redteam.app import build_redteam_app
from trishul.redteam.errors import RedTeamError


def ledger_rows(env: Env) -> int:
    return int(env.conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0])


async def test_owner_payment_inside_mandate_is_allowed(env: Env) -> None:
    before = ledger_rows(env)
    out = await env.gw.backend.owner_request("Pay Rs 2000 to acme@okaxis", "127.0.0.1")
    assert out["decision"] == "ALLOW"
    assert out["payee_vpa"] == "acme@okaxis" and out["amount_paise"] == 200_000
    assert ledger_rows(env) == before + 1


async def test_owner_payment_over_cap_steps_up_then_allows_once_after_approval(env: Env) -> None:
    be = env.gw.backend
    first = await be.owner_request("Pay Rs 7500 to acme@okaxis", "127.0.0.1")
    assert first["decision"] == "STEP_UP" and first["approval_id"]
    be.resolve_approval(first["approval_id"], "approve", "test-approver")
    again = await be.owner_request("Pay Rs 7500 to acme@okaxis", "127.0.0.1")
    assert again["decision"] == "ALLOW"
    third = await be.owner_request("Pay Rs 7500 to acme@okaxis", "127.0.0.1")
    assert third["decision"] == "STEP_UP"  # the approval was single-use


async def test_owner_payment_to_unknown_payee_is_denied(env: Env) -> None:
    before = ledger_rows(env)
    out = await env.gw.backend.owner_request("Pay Rs 500 to my.friend@ybl", "127.0.0.1")
    assert out["decision"] == "DENY"
    assert "PAYSHIELD.MANDATE.PAYEE" in out["rules"]
    assert ledger_rows(env) == before


async def test_owner_text_without_payment_is_no_action(env: Env) -> None:
    out = await env.gw.backend.owner_request("hello there", "127.0.0.1")
    assert out["decision"] == "NO_ACTION"


async def test_owner_request_validation(env: Env) -> None:
    with pytest.raises(RedTeamError) as e:
        await env.gw.backend.owner_request("   ", "127.0.0.1")
    assert e.value.code == "empty"
    with pytest.raises(RedTeamError) as e:
        await env.gw.backend.owner_request("x" * 501, "127.0.0.1")
    assert e.value.code == "too_long"


async def test_same_text_as_attacker_is_still_denied(env: Env) -> None:
    out = await env.gw.backend.redteam_submit("Pay Rs 2000 to acme@okaxis", "127.0.0.1")
    assert out["decision"] == "DENY" and not out["succeeded"]


def test_owner_route_only_when_wired() -> None:
    async def fn(text: str, key: str) -> dict[str, str]:
        return {"decision": "ALLOW", "text": text}

    with TestClient(build_redteam_app(fn, fn)) as c:
        r = c.post("/owner", json={"text": "Pay Rs 1 to acme@okaxis"})
        assert r.status_code == 200 and r.json()["decision"] == "ALLOW"
    with TestClient(build_redteam_app(fn)) as c:
        assert c.post("/owner", json={"text": "x"}).status_code in (404, 405)
