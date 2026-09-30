"""AgentDojo adapter: the policy core decides in-process; no LLM and no network are needed."""

from types import SimpleNamespace

import pytest

from trishul.bench.agentdojo_adapter import (
    PolicyCore,
    authorised_payees,
    not_run,
    subset_note,
)

KNOWN = "GB29NWBK60161331926819"
ATTACKER = "US133000000121212121212"


def _env() -> SimpleNamespace:
    txns = [
        SimpleNamespace(sender="me", recipient=KNOWN),
        SimpleNamespace(sender=KNOWN, recipient="me"),
    ]
    sched = [SimpleNamespace(sender="DE89370400440532013000", recipient="CH9300762011623852957")]
    acct = SimpleNamespace(iban="DE89370400440532013000", transactions=txns,
                           scheduled_transactions=sched)  # fmt: skip
    return SimpleNamespace(bank_account=acct)


def test_authorised_payees_from_history_and_prompt() -> None:
    got = authorised_payees(_env(), "also pay FR1420041010050500013M02606 please")
    assert got == {KNOWN, "CH9300762011623852957", "FR1420041010050500013M02606"}
    assert "me" not in got and "DE89370400440532013000" not in got


def test_known_payee_allowed_attacker_blocked() -> None:
    core = PolicyCore(42)
    auth = authorised_payees(_env(), "pay my friend")
    assert core.allow("send_money", "pay my friend", {"recipient": KNOWN, "amount": 10.0}, auth)
    assert not core.allow(
        "send_money", "pay my friend", {"recipient": ATTACKER, "amount": 10.0}, auth
    )


def test_unmapped_tool_is_unguarded_and_bad_args_fail_closed() -> None:
    core = PolicyCore(42)
    auth = frozenset({KNOWN})
    assert core.allow("update_password", "x", {"password": "p"}, auth)
    assert not core.allow("send_money", "x", {"recipient": KNOWN, "amount": "abc"}, auth)
    assert not core.allow("send_money", "x", {"recipient": KNOWN, "amount": -5}, auth)
    assert core.allow("update_scheduled_transaction", "x", {"id": 7, "amount": 1.0}, auth)
    assert not core.allow(
        "update_scheduled_transaction", "x", {"id": 7, "recipient": ATTACKER}, auth
    )


def test_not_run_shape_and_subset_note() -> None:
    nr = not_run("because")
    assert nr["status"] == "not_run" and nr["with_trishul"] is None and nr["without"] is None
    note = subset_note({"banking": (8, 16, 4, 9)})
    assert "8/16" in note and "4/9" in note and "subset" in note
    assert "subset" not in subset_note({"banking": (16, 16, 9, 9)}).split("; attack")[0]


@pytest.mark.parametrize("missing", ["agentdojo"])
def test_optional_extra_is_not_a_hard_dependency(missing: str) -> None:
    import tomllib
    from pathlib import Path

    data = tomllib.loads((Path(__file__).resolve().parents[2] / "pyproject.toml").read_text())
    assert missing not in " ".join(data["project"]["dependencies"])
    assert any(missing in d for d in data["project"]["optional-dependencies"]["bench"])
