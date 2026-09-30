"""PolicyEvent: the UI/audit record. Args are redacted by construction."""

from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from trishul.contracts.authz import UtcDatetime
from trishul.contracts.calls import ToolCall
from trishul.contracts.decisions import DecisionName, DecisionReason, Verdict
from trishul.contracts.labels import Label
from trishul.contracts.lineage import LineageGraph
from trishul.contracts.patterns import contains_secret_deep
from trishul.contracts.values import Redacted, RedactedJson

Domain = Literal["payshield", "purposelock", "voicetrust", "core"]


def _has_raw_secret(value: RedactedJson) -> bool:
    if isinstance(value, Redacted):
        return False
    if isinstance(value, dict):
        return any(contains_secret_deep(k) or _has_raw_secret(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_has_raw_secret(v) for v in value)
    return contains_secret_deep(value)


class PolicyEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    schema_version: Literal[1] = 1
    event_id: str = Field(min_length=1)
    ts: UtcDatetime
    session: str = Field(min_length=1)
    agent: str = Field(min_length=1)
    domain: Domain
    tool: str = Field(min_length=1)
    args: dict[str, RedactedJson]
    labels: dict[str, Label]
    decision: DecisionName
    reasons: tuple[DecisionReason, ...]
    lineage: LineageGraph = LineageGraph()
    latency_us: int | None = Field(default=None, ge=0)
    audit_leaf_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("args")
    @classmethod
    def _args_are_redacted(cls, args: dict[str, RedactedJson]) -> dict[str, RedactedJson]:
        if _has_raw_secret(args):
            raise ValueError("args contain an unredacted secret or PII pattern")
        return args

    @classmethod
    def from_call(
        cls,
        call: ToolCall,
        verdict: Verdict,
        *,
        event_id: str,
        session: str,
        agent: str,
        domain: Domain = "core",
        ts: datetime | None = None,
        lineage: LineageGraph | None = None,
        latency_us: int | None = None,
        audit_leaf_hash: str | None = None,
    ) -> Self:
        """The only sanctioned constructor: redacts args before they enter the event."""
        # Imported lazily: observability depends on contracts, not the other way round.
        from trishul.observability.redaction import redact_args

        return cls(
            event_id=event_id,
            ts=ts or call.ts,
            session=session,
            agent=agent,
            domain=domain,
            tool=call.tool,
            args=redact_args(call.args, call.arg_labels),
            labels=dict(call.arg_labels),
            decision=verdict.decision,
            reasons=verdict.reasons,
            lineage=lineage or LineageGraph(),
            latency_us=latency_us,
            audit_leaf_hash=audit_leaf_hash,
        )
