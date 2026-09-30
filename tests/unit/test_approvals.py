from datetime import UTC, datetime, timedelta

import pytest

from tests.conftest import NOW, make_call
from trishul.approvals import ApprovalError, ApprovalService
from trishul.contracts.calls import ToolCall
from trishul.crypto.keys import KeyRing
from trishul.store.db import connect
from trishul.store.ids import IdGen

T0 = datetime(2026, 9, 30, 9, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


def setup() -> tuple[ApprovalService, Clock]:
    clock = Clock()
    svc = ApprovalService(connect(":memory:"), KeyRing.from_seed(42), IdGen(42), clock=clock)
    return svc, clock


def pay(amount: int = 100, payee: str = "a@upi") -> ToolCall:
    return make_call("pay_upi", {"payee_vpa": payee, "amount_paise": amount})


def test_no_approval_is_neither_valid_nor_mismatch() -> None:
    svc, _ = setup()
    check = svc.check(pay(), T0)
    assert (check.valid, check.binding_mismatch, check.token) == (False, False, None)


def test_request_pending_then_approved_is_valid_and_single_use() -> None:
    svc, clock = setup()
    call = pay()
    aid = svc.request(call)
    assert not svc.check(call, T0).valid  # pending is not approval
    token = svc.approve(aid, "sreekar")
    assert token.call_digest == call.call_digest() and token.signature
    check = svc.check(call, clock.now)
    assert check.valid and not check.binding_mismatch and check.token == token
    assert svc.consume(token.token_id)
    assert not svc.consume(token.token_id)
    after = svc.check(call, clock.now)
    assert (after.valid, after.binding_mismatch) == (False, False)


@pytest.mark.parametrize(
    "swapped",
    [
        pay(amount=101),
        pay(payee="evil@upi"),
        pay(amount=100).model_copy(update={"principal": "eve"}),
    ],
)
def test_argument_swap_is_binding_mismatch(swapped: ToolCall) -> None:
    svc, _ = setup()
    svc.approve(svc.request(pay()), "sreekar")
    check = svc.check(swapped, T0)
    assert (check.valid, check.binding_mismatch) == (False, True)


def test_other_task_or_tool_does_not_see_token() -> None:
    svc, _ = setup()
    svc.approve(svc.request(pay()), "sreekar")
    other_task = pay().model_copy(update={"task_id": "t2"})
    assert svc.check(other_task, T0) == (False, False, None)


def test_expiry_and_not_yet_valid() -> None:
    svc, clock = setup()
    call = pay()
    token = svc.approve(svc.request(call), "sreekar")
    assert svc.check(call, token.expires_at - timedelta(seconds=1)).valid
    expired = svc.check(call, token.expires_at)
    assert (expired.valid, expired.binding_mismatch) == (False, False)
    assert not svc.check(call, token.issued_at - timedelta(seconds=1)).valid
    assert token.expires_at - token.issued_at == timedelta(seconds=120)
    assert clock.now == T0


def test_signature_forgery_is_not_valid() -> None:
    svc, _ = setup()
    call = pay()
    svc.approve(svc.request(call), "sreekar")
    svc.conn.execute("UPDATE approvals SET token = replace(token, 'sreekar', 'mallory')")
    check = svc.check(call, T0)
    assert (check.valid, check.binding_mismatch) == (False, True)
    # a different key ring cannot validate
    other = ApprovalService(svc.conn, KeyRing.from_seed(9), IdGen(1))
    svc.conn.execute("DELETE FROM approvals")
    svc.approve(svc.request(call), "sreekar")
    assert not other.check(call, T0).valid


def test_reject_and_state_errors() -> None:
    svc, _ = setup()
    aid = svc.request(pay())
    svc.reject(aid)
    assert not svc.check(pay(), T0).valid
    with pytest.raises(ApprovalError):
        svc.approve(aid, "x")
    with pytest.raises(ApprovalError):
        svc.approve("apr_missing", "x")
    assert svc.pending() == []
    assert NOW  # conftest import sanity
