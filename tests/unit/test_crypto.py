import json

import pytest

from trishul.crypto.jcs import JcsError, jcs
from trishul.crypto.keys import KeyRing


def test_rfc8785_key_order_vector() -> None:
    # RFC 8785 section 3.2.3: keys sort by UTF-16 code units (emoji surrogates < U+FB33).
    obj = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    keys = list(json.loads(jcs(obj).decode("utf-8")))
    assert keys == ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]


def test_jcs_basics() -> None:
    assert jcs({"b": [1, True, None], "a": 'x\n\u001f"\\'}) == (
        b'{"a":"x\\n\\u001f\\"\\\\","b":[1,true,null]}'
    )
    assert jcs({}) == b"{}"


@pytest.mark.parametrize("bad", ["\ud800", {"\udc00": 1}, ["a\udfffb"], 1.5, {1: 2}, object()])
def test_jcs_rejects(bad: object) -> None:
    with pytest.raises(JcsError):
        jcs(bad)


def test_from_seed_is_deterministic() -> None:
    a, b, c = KeyRing.from_seed(42), KeyRing.from_seed(42), KeyRing.from_seed(43)
    assert a.public_bytes("gateway") == b.public_bytes("gateway")
    assert a.public_bytes("gateway") != c.public_bytes("gateway")
    assert a.public_bytes("gateway") != a.public_bytes("approver")
    assert a.sign("approver", {"x": 1}) == b.sign("approver", {"x": 1})


def test_sign_verify_and_tamper() -> None:
    ring = KeyRing.from_seed(1)
    payload = {"amount": 100, "payee": "a@upi"}
    sig = ring.sign("gateway", payload)
    assert ring.verify("gateway", payload, sig)
    assert ring.verify("gateway", {"payee": "a@upi", "amount": 100}, sig)  # key order irrelevant
    assert not ring.verify("gateway", {**payload, "amount": 101}, sig)
    assert not ring.verify("approver", payload, sig)
    assert not ring.verify("nobody", payload, sig)
    assert not ring.verify("gateway", payload, sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB"))
    assert not ring.verify("gateway", payload, "not base64!!")
    assert not ring.verify("gateway", payload, "")


def test_public_ring_cannot_sign_but_verifies() -> None:
    ring = KeyRing.from_seed(1)
    pub = ring.public_ring()
    assert pub.verify("gateway", {"a": 1}, ring.sign("gateway", {"a": 1}))
    with pytest.raises(KeyError):
        pub.sign("gateway", {"a": 1})
