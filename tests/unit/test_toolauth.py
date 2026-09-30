"""Gateway->tool token verification rules (acceptance 1: gateway-only)."""

import json

import pytest

from trishul.crypto.jcs import jcs
from trishul.crypto.keys import KeyRing, b64url, b64url_decode
from trishul.crypto.toolauth import (
    MAX_SKEW_MS,
    TOKEN_TTL_MS,
    ToolAuthError,
    ToolTokenMinter,
    ToolTokenVerifier,
    args_digest,
)
from trishul.store.db import connect

pytestmark = pytest.mark.acceptance(1)

ARGS = {"payee_vpa": "a@b", "amount_paise": 5}
T0 = 1_800_000_000_000


def make(now: list[int]) -> tuple[ToolTokenMinter, ToolTokenVerifier, KeyRing]:
    keys = KeyRing.generate()
    conn = connect(":memory:")
    return (
        ToolTokenMinter(keys, now_ms=lambda: now[0]),
        ToolTokenVerifier(conn, keys.public_ring(), now_ms=lambda: now[0]),
        keys,
    )


def test_valid_token_verifies_once_and_records_kid() -> None:
    now = [T0]
    minter, verifier, keys = make(now)
    token = minter.mint("upi", "pay_upi", ARGS)
    claims = json.loads(b64url_decode(token.split(".")[0]))
    assert claims["kid"] == keys.active_kid("gateway-tool")
    assert claims["exp"] - claims["iat"] == TOKEN_TTL_MS
    assert claims["args_sha256"] == args_digest(ARGS)
    verifier.verify("upi", "pay_upi", ARGS, token)
    with pytest.raises(ToolAuthError, match="already used"):
        verifier.verify("upi", "pay_upi", ARGS, token)


@pytest.mark.parametrize(
    ("server", "tool", "args", "message"),
    [
        ("mail", "pay_upi", ARGS, "audience"),
        ("upi", "get_balance", ARGS, "tool mismatch"),
        ("upi", "pay_upi", {**ARGS, "amount_paise": 6}, "arguments mismatch"),
    ],
)
def test_binding_mismatches_are_rejected(
    server: str, tool: str, args: dict[str, object], message: str
) -> None:
    minter, verifier, _ = make([T0])
    token = minter.mint("upi", "pay_upi", ARGS)
    with pytest.raises(ToolAuthError, match=message):
        verifier.verify(server, tool, args, token)


def test_expired_and_future_tokens_are_rejected() -> None:
    now = [T0]
    minter, verifier, _ = make(now)
    token = minter.mint("upi", "pay_upi", ARGS)
    now[0] = T0 + TOKEN_TTL_MS + 1
    with pytest.raises(ToolAuthError, match="expired"):
        verifier.verify("upi", "pay_upi", ARGS, token)
    now[0] = T0
    future = minter.mint("upi", "pay_upi", {"x": 1})
    now[0] = T0 - MAX_SKEW_MS - 1  # verifier clock far behind the minter's
    with pytest.raises(ToolAuthError, match="future"):
        verifier.verify("upi", "pay_upi", {"x": 1}, future)


def test_foreign_unknown_kid_and_tampered_tokens_are_rejected() -> None:
    minter, verifier, _ = make([T0])
    foreign = ToolTokenMinter(KeyRing.generate(), now_ms=lambda: T0).mint("upi", "pay_upi", ARGS)
    with pytest.raises(ToolAuthError, match="unknown signing key"):
        verifier.verify("upi", "pay_upi", ARGS, foreign)
    good = minter.mint("upi", "pay_upi", ARGS)
    body, _, sig = good.partition(".")
    claims = json.loads(b64url_decode(body))
    claims["aud"] = "mail"
    forged = f"{b64url(jcs(claims))}.{sig}"
    with pytest.raises(ToolAuthError, match="bad signature"):
        verifier.verify("mail", "pay_upi", ARGS, forged)
    for junk in (None, 7, "", "a.b", "a.b.c", f"{body}.", "!!.!!"):
        with pytest.raises(ToolAuthError):
            verifier.verify("upi", "pay_upi", ARGS, junk)


def test_signature_by_another_purpose_key_is_rejected() -> None:
    now = [T0]
    _, verifier, keys = make(now)
    kid = keys.active_kid("approval-signer")  # a real key, but not a gateway-tool key
    claims = {
        "v": 1,
        "kid": kid,
        "aud": "upi",
        "tool": "pay_upi",
        "args_sha256": args_digest(ARGS),
        "iat": T0,
        "exp": T0 + TOKEN_TTL_MS,
        "nonce": "n" * 22,
    }
    token = f"{b64url(jcs(claims))}.{keys.sign(kid, claims)}"
    with pytest.raises(ToolAuthError, match="unknown signing key"):
        verifier.verify("upi", "pay_upi", ARGS, token)


def test_verifier_reloads_public_keys_after_rotation() -> None:
    now = [T0]
    keys = KeyRing.generate()
    conn = connect(":memory:")
    fresh = KeyRing.generate()  # stands in for the rotated ring
    verifier = ToolTokenVerifier(
        conn, keys.public_ring(), reload=lambda: fresh.public_ring(), now_ms=lambda: now[0]
    )
    token = ToolTokenMinter(fresh, now_ms=lambda: now[0]).mint("upi", "pay_upi", ARGS)
    verifier.verify("upi", "pay_upi", ARGS, token)


def test_tokens_are_scrubbed_by_the_redaction_backstop() -> None:
    from trishul.contracts.patterns import scrub_text

    minter, _, _ = make([T0])
    token = minter.mint("upi", "pay_upi", ARGS)
    assert token not in scrub_text(f"forwarded with {token}")
    assert "[REDACTED:tool_token]" in scrub_text(token)
