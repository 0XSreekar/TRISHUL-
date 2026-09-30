"""Decisions, reasons and verdicts."""

from enum import IntEnum, StrEnum
from typing import Annotated, Self

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    PlainSerializer,
    field_validator,
    model_validator,
)

from trishul.contracts.canonical import ensure_canonical
from trishul.contracts.patterns import contains_secret_deep
from trishul.contracts.values import parse_enum_name


class Decision(IntEnum):
    ALLOW = 0
    STEP_UP = 1
    DENY = 2

    @classmethod
    def combine(cls, *decisions: "Decision") -> "Decision":
        """Join of decisions: the most restrictive wins; ``ALLOW`` if none."""
        return max(decisions, default=cls.ALLOW)


DecisionName = Annotated[
    Decision,
    BeforeValidator(parse_enum_name(Decision)),
    PlainSerializer(lambda v: v.name, return_type=str, when_used="json"),
]


class Stage(StrEnum):
    PARSE = "PARSE"
    SCHEMA = "SCHEMA"
    LABEL = "LABEL"
    PURPOSE = "PURPOSE"
    MANDATE = "MANDATE"
    APPROVAL = "APPROVAL"
    CAP = "CAP"
    ML = "ML"
    INTERNAL = "INTERNAL"


RULE_ID_PATTERN = r"^[A-Z][A-Z0-9_]*(\.[A-Z0-9_]+)+$"


class DecisionReason(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    rule_id: str = Field(pattern=RULE_ID_PATTERN)
    stage: Stage
    decision: DecisionName
    explanation: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    lineage_refs: tuple[str, ...] = ()
    unknown: bool = False

    @field_validator("evidence")
    @classmethod
    def _evidence_is_safe(cls, evidence: dict[str, JsonValue]) -> dict[str, JsonValue]:
        ensure_canonical(evidence)
        if contains_secret_deep(evidence):
            raise ValueError("evidence contains unredacted secret or PII")
        return evidence


def _sort_key(reason: DecisionReason) -> tuple[int, str]:
    return (-int(reason.decision), reason.rule_id)


class Verdict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    decision: DecisionName
    reasons: tuple[DecisionReason, ...]
    policy_digest: str

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if list(self.reasons) != sorted(self.reasons, key=_sort_key):
            raise ValueError("reasons must be sorted by (decision desc, rule_id)")
        if self.decision != Decision.combine(*(r.decision for r in self.reasons)):
            raise ValueError("decision must equal the combination of reason decisions")
        return self

    @classmethod
    def build(cls, reasons: list[DecisionReason], policy_digest: str) -> Self:
        ordered = tuple(sorted(reasons, key=_sort_key))
        return cls(
            decision=Decision.combine(*(r.decision for r in ordered)),
            reasons=ordered,
            policy_digest=policy_digest,
        )
