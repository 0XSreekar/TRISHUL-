"""Shared fixtures and builders."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from trishul.contracts.calls import SourceMetadata, ToolCall, ToolCategory
from trishul.contracts.labels import Label, Level, SourceRef, Tag
from trishul.policy.ast import CompiledPolicy
from trishul.policy.compiler import compile_files
from trishul.policy.evaluator import EvalContext

POLICY_DIR = Path(__file__).resolve().parent.parent / "policies"
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

TRUSTED = Label.make(Level.TRUSTED_USER, sources=[SourceRef(kind="user", id="u1")])
UNTRUSTED = Label.make(Level.UNTRUSTED, sources=[SourceRef(kind="email", id="m1")])


@pytest.fixture(scope="session")
def policy() -> CompiledPolicy:
    return compile_files([POLICY_DIR])


def make_call(
    tool: str,
    args: dict[str, object],
    labels: dict[str, Label] | None = None,
    *,
    category: ToolCategory | None = None,
) -> ToolCall:
    labels = labels if labels is not None else {f"/{k}": TRUSTED for k in args}
    return ToolCall(
        call_id="c1",
        server="srv",
        tool=tool,
        args=args,  # type: ignore[arg-type]
        arg_labels=labels,
        principal="alice",
        task_id="t1",
        declared_category=category,
        source=SourceMetadata(),
        ts=NOW,
    )


# the gateway supplies these for every non-voice tool; without them the rules fail closed
APPROVAL_FACTS: dict[str, bool | None] = {
    "approval_valid": False,
    "approval_binding_mismatch": False,
}


def make_ctx(**kw: object) -> EvalContext:
    facts = {**APPROVAL_FACTS, **(kw.pop("facts", None) or {})}  # type: ignore[call-overload]
    return EvalContext(now=NOW, facts=facts, **kw)  # type: ignore[arg-type]


__all__ = ["NOW", "TRUSTED", "UNTRUSTED", "Tag", "make_call", "make_ctx"]


OP_TOKEN = "test-operator-token"


@pytest.fixture(autouse=True)
def _operator_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Operator routes always need a bearer token: set one and send it by default from every
    TestClient (auth tests override the header explicitly)."""
    from starlette.testclient import TestClient

    monkeypatch.setenv("TRISHUL_OPERATOR_TOKEN", OP_TOKEN)
    orig = TestClient.__init__

    def init(self, *a, **kw):  # type: ignore[no-untyped-def]
        hdrs = {"authorization": f"Bearer {OP_TOKEN}", **(kw.pop("headers", None) or {})}
        orig(self, *a, headers=hdrs, **kw)

    monkeypatch.setattr(TestClient, "__init__", init)
