import io
import json
import logging

import pytest
from pydantic import ValidationError

from tests.conftest import TRUSTED, make_call, make_ctx
from trishul.contracts.canonical import canonical_json
from trishul.contracts.decisions import Verdict
from trishul.contracts.events import PolicyEvent
from trishul.contracts.labels import Label, Level, Tag
from trishul.contracts.values import Redacted
from trishul.observability.logging import JsonFormatter, get_logger
from trishul.observability.redaction import redact, redact_args
from trishul.policy.ast import CompiledPolicy
from trishul.policy.evaluator import evaluate

AADHAAR = "2345 6789 0123"
AADHAAR_BARE = "234567890123"
PAN = "ABCDE1234F"
API_KEY = "sk-live-abcdef1234567890abcdef"
BEARER = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig123"
EMAIL = "priya.sharma@example.com"
PHONE = "+91 98765 43210"
RAW_SECRETS = [
    AADHAAR,
    AADHAAR_BARE,
    PAN,
    API_KEY,
    "eyJhbGciOiJIUzI1NiJ9.payload.sig123",
    EMAIL,
    "98765 43210",
]


def test_secret_tag_redacts_without_digest_and_pii_with_pseudonym() -> None:
    secret = redact("hunter2", Label.make(Level.TRUSTED_USER, tags=[Tag.SECRET]))
    assert secret == Redacted(reason="secret", digest=None)
    pii = redact("Priya", Label.make(Level.TRUSTED_USER, tags=[Tag.PII_PHONE]))
    assert isinstance(pii, Redacted) and pii.reason == "pii" and pii.digest
    assert "Priya" not in pii.model_dump_json()
    same = redact("Priya", Label.make(Level.UNTRUSTED, tags=[Tag.PII]))
    assert isinstance(same, Redacted) and same.digest == pii.digest  # keyed and stable


def test_backstop_catches_unlabeled_patterns_and_keeps_clean_values() -> None:
    for raw in (AADHAAR, AADHAAR_BARE, PAN, API_KEY, BEARER, EMAIL, PHONE, "9876543210"):
        out = redact(f"note: {raw}", Label.bottom())
        assert isinstance(out, Redacted), raw
    assert redact("hello", Label.bottom()) == "hello"
    assert redact(123, Label.bottom()) == 123
    assert redact("alice@okhdfc", Label.bottom()) == "alice@okhdfc"  # a UPI VPA is not an email
    assert redact(None, Label.bottom()) is None and redact(False, Label.bottom()) is False


def test_redact_args_uses_ancestor_labels_and_recurses() -> None:
    args = {"user": {"name": "Priya", "note": "hi"}, "n": 3, "list": [PAN, "ok"]}
    out = redact_args(args, {"/user/name": Label.make(Level.TRUSTED_USER, tags=[Tag.PII])})
    assert isinstance(out["user"], dict) and isinstance(out["user"]["name"], Redacted)  # type: ignore[index]
    assert out["user"]["note"] == "hi"  # type: ignore[index]
    assert out["n"] == 3 and out["list"][1] == "ok"  # type: ignore[index]
    assert isinstance(out["list"][0], Redacted)  # type: ignore[index]
    whole = redact_args(args, {"/user": Label.make(Level.TRUSTED_USER, tags=[Tag.PII])})
    assert isinstance(whole["user"], Redacted)


@pytest.fixture
def leaky_event(policy: CompiledPolicy) -> tuple[PolicyEvent, Verdict]:
    call = make_call(
        "send_email",
        {
            "to": EMAIL,
            "body": f"Aadhaar {AADHAAR}, PAN {PAN}, key {API_KEY}, {BEARER}, call {PHONE}",
            "fields": ["email", AADHAAR_BARE],
        },
        {
            "/to": Label.make(Level.UNTRUSTED, tags=[Tag.PII_EMAIL]),
            "/body": TRUSTED,  # deliberately unlabeled-as-PII: the backstop must catch it
            "/fields": TRUSTED,
        },
    )
    verdict = evaluate(policy, call, make_ctx())
    event = PolicyEvent.from_call(call, verdict, event_id="e1", session="s", agent="a")
    return event, verdict


def test_no_secret_leaks_into_serialized_event(leaky_event: tuple[PolicyEvent, Verdict]) -> None:
    event, verdict = leaky_event
    for text in (
        event.model_dump_json(),
        canonical_json(event.model_dump(mode="json")),
        repr(event),
        verdict.model_dump_json(),
    ):
        for raw in RAW_SECRETS:
            assert raw not in text, raw


def test_policy_event_roundtrip_and_schema(leaky_event: tuple[PolicyEvent, Verdict]) -> None:
    event, _ = leaky_event
    back = PolicyEvent.model_validate_json(event.model_dump_json())
    assert back == event
    assert isinstance(back.args["to"], Redacted)
    assert event.schema_version == 1 and event.latency_us is None and event.audit_leaf_hash is None
    dumped = event.model_dump(mode="json")
    assert dumped["decision"] in {"ALLOW", "STEP_UP", "DENY"}


def test_policy_event_schema_rejections(leaky_event: tuple[PolicyEvent, Verdict]) -> None:
    event, _ = leaky_event
    good = event.model_dump(mode="json")
    for patch in (
        {"schema_version": 2},
        {"domain": "other"},
        {"latency_us": -1},
        {"audit_leaf_hash": "xyz"},
        {"extra": 1},
        {"ts": "2026-01-01T00:00:00"},
        {"args": {"to": EMAIL}},  # raw secret can't be smuggled through the constructor
        {"args": {"note": PAN}},
    ):
        with pytest.raises(ValidationError):
            PolicyEvent.model_validate_json(json.dumps({**good, **patch}))


def test_json_log_formatter_applies_backstop() -> None:
    stream = io.StringIO()
    logger = get_logger("trishul.test.redaction", logging.StreamHandler(stream))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.info(
        "paid %s via %s", EMAIL, API_KEY, extra={"payload": {"pan": PAN, "list": [AADHAAR]}}
    )
    try:
        raise ValueError(f"bad {BEARER}")
    except ValueError:
        logger.exception("failed for %s", PHONE)
    out = stream.getvalue()
    lines = [json.loads(line) for line in out.splitlines()]
    assert len(lines) == 2 and lines[0]["level"] == "INFO"
    for raw in [EMAIL, API_KEY, PAN, AADHAAR, "eyJhbGciOiJIUzI1NiJ9.payload.sig123", "98765 43210"]:
        assert raw not in out, raw
    assert "[REDACTED:email]" in lines[0]["message"]


def test_formatter_handles_non_json_extras() -> None:
    record = logging.LogRecord("n", logging.INFO, "f", 1, "m", (), None)
    record.thing = object()  # type: ignore[attr-defined]
    assert "thing" in json.loads(JsonFormatter().format(record))["fields"]
