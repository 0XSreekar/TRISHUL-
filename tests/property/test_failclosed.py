"""Fail-closed property (I3): a fault in any of stages 2-6 (plus ingress/preview) never yields
ALLOW and never executes the side effect, even when a valid approval token exists."""

import asyncio
import tempfile
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.integration.test_gateway_harness import make_env_sync, parse_error
from trishul.gateway.pipeline import FAILSAFE_DECISION

ORDER = ["ingress", "handles", "provenance", "guards", "policy", "ml", "preview"]
ACME = "acme@okaxis"
SMALL = {"payee_vpa": ACME, "amount_paise": 100_000}
BIG = {"payee_vpa": ACME, "amount_paise": 750_000}
EXCEPTIONS: list[BaseException] = [
    RuntimeError("boom"),
    ValueError("bad"),
    KeyError("k"),
    OSError(),
]


async def attempt(
    faults: dict[str, BaseException], args: dict[str, Any], *, approve_first: bool = False
) -> tuple[dict[str, Any] | None, int, int]:
    """Run one pay_upi with faults injected. Returns (error body or None, ledger rows, balance)."""
    with tempfile.TemporaryDirectory() as d:
        gw, conn, _, _, _, _ = make_env_sync(Path(d))
        try:
            async with Client(gw.mcp) as client:
                gw.bind_task(
                    purpose="payment_processing",
                    category="PAYMENT",
                    text="pay",
                    params={"payee_vpa": ACME, "amounts": [100_000, 750_000]},
                )
                if approve_first:
                    try:
                        await client.call_tool("upi_pay_upi", args)
                    except ToolError as exc:
                        gw.backend.resolve_approval(parse_error(exc)["approval_id"], "approve", "t")
                gw.pipeline.faults = dict(faults)
                result = await client.call_tool("upi_pay_upi", args, raise_on_error=False)
            rows = int(conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0])
            balance = int(conn.execute("SELECT balance_paise FROM accounts").fetchone()[0])
            body = None
            if result.is_error:
                text = result.content[0].text  # type: ignore[union-attr]
                import json

                body = json.loads(text[text.index("{") :])
            return body, rows, balance
        finally:
            conn.close()


def test_baseline_is_allowed_without_faults() -> None:
    body, rows, balance = asyncio.run(attempt({}, SMALL))
    assert body is None and rows == 1 and balance == 4_900_000


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    stages=st.sets(st.sampled_from(ORDER), min_size=1),
    exc=st.sampled_from(EXCEPTIONS),
    big=st.booleans(),
    approved=st.booleans(),
)
@pytest.mark.acceptance(4)
def test_fault_in_any_stage_never_allows_or_executes(
    stages: set[str], exc: BaseException, big: bool, approved: bool
) -> None:
    args = BIG if big else SMALL
    body, rows, balance = asyncio.run(
        attempt(dict.fromkeys(stages, exc), args, approve_first=approved and big)
    )
    assert body is not None, "a faulted pipeline must not ALLOW"
    assert body["decision"] in {"DENY", "STEP_UP"}
    assert rows == 0 and balance == 5_000_000, "side effect ran despite a stage fault"
    first = next(s for s in ORDER if s in stages)
    # (policy rules that already fired before a later-stage fault, e.g. CAP.PER_TXN, may co-occur)
    assert f"CORE.FAILSAFE.{first.upper()}" in body["rules"]
    assert body["decision"] == FAILSAFE_DECISION[first].name


@pytest.mark.acceptance(4)
def test_stage_timeout_fails_closed() -> None:
    async def slow() -> None:
        await asyncio.sleep(5)

    async def go() -> tuple[dict[str, Any] | None, int]:
        with tempfile.TemporaryDirectory() as d:
            gw, conn, _, _, _, _ = make_env_sync(Path(d), stage_timeout_s=0.05)
            gw.pipeline.faults = {"policy": slow}  # type: ignore[dict-item]
            async with Client(gw.mcp) as client:
                gw.bind_task(
                    purpose="payment_processing", category="PAYMENT", text="pay", params=SMALL
                )
                result = await client.call_tool("upi_pay_upi", SMALL, raise_on_error=False)
            rows = int(conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0])
            conn.close()
            assert result.is_error
            return None, rows

    _, rows = asyncio.run(go())
    assert rows == 0
