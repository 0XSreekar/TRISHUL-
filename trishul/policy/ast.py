"""Typed policy AST (A9). Small, first-order, discriminated on ``kind``."""

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from trishul.contracts.calls import ToolCategory
from trishul.contracts.canonical import canonical_json, digest, ensure_canonical, is_pointer
from trishul.contracts.decisions import RULE_ID_PATTERN, Decision, DecisionName, Stage
from trishul.contracts.labels import LevelName, SourceKind, Tag

CompareOp = Literal["eq", "ne", "lt", "le", "gt", "ge"]


class _Node(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


def _check_pointer(path: str) -> str:
    if not is_pointer(path):
        raise ValueError("path must be a JSON pointer such as /payee_vpa")
    return path


class Const(_Node):
    kind: Literal["const"] = "const"
    value: bool


class All(_Node):
    kind: Literal["all"] = "all"
    items: tuple["Predicate", ...]


class Any(_Node):
    kind: Literal["any"] = "any"
    items: tuple["Predicate", ...]


class Not(_Node):
    kind: Literal["not"] = "not"
    item: "Predicate"


class ToolIs(_Node):
    kind: Literal["tool_is"] = "tool_is"
    tool: str = Field(min_length=1)


class ToolCategoryIn(_Node):
    kind: Literal["tool_category_in"] = "tool_category_in"
    categories: tuple[ToolCategory, ...] = Field(min_length=1)


class ArgExists(_Node):
    kind: Literal["arg_exists"] = "arg_exists"
    path: str

    _p = field_validator("path")(_check_pointer)


class ArgCompare(_Node):
    kind: Literal["arg_compare"] = "arg_compare"
    path: str
    op: CompareOp
    value: JsonValue

    _p = field_validator("path")(_check_pointer)

    @field_validator("value")
    @classmethod
    def _scalar(cls, value: JsonValue) -> JsonValue:
        ensure_canonical(value)
        if isinstance(value, list | dict):
            raise ValueError("compare value must be a scalar")
        return value


class LabelAtLeast(_Node):
    kind: Literal["label_at_least"] = "label_at_least"
    path: str
    level: LevelName

    _p = field_validator("path")(_check_pointer)


class LabelHasTag(_Node):
    kind: Literal["label_has_tag"] = "label_has_tag"
    path: str
    tag: Tag

    _p = field_validator("path")(_check_pointer)


class SourceKindIn(_Node):
    kind: Literal["source_kind_in"] = "source_kind_in"
    path: str
    kinds: tuple[SourceKind, ...] = Field(min_length=1)

    _p = field_validator("path")(_check_pointer)


class PurposeIs(_Node):
    kind: Literal["purpose_is"] = "purpose_is"
    purpose: str = Field(min_length=1)


class ConsentCovers(_Node):
    kind: Literal["consent_covers"] = "consent_covers"
    purpose: str = Field(min_length=1)
    fields_path: str

    _p = field_validator("fields_path")(_check_pointer)


class MandatePresent(_Node):
    kind: Literal["mandate_present"] = "mandate_present"


class MandateCovers(_Node):
    kind: Literal["mandate_covers"] = "mandate_covers"
    amount_path: str
    payee_path: str

    _a = field_validator("amount_path")(_check_pointer)
    _b = field_validator("payee_path")(_check_pointer)


class ApprovalPresent(_Node):
    kind: Literal["approval_present"] = "approval_present"
    scope: str = Field(min_length=1)


class AmountExceeds(_Node):
    kind: Literal["amount_exceeds"] = "amount_exceeds"
    path: str
    cap_paise: int = Field(ge=0)

    _p = field_validator("path")(_check_pointer)


type Predicate = Annotated[
    Const
    | All
    | Any
    | Not
    | ToolIs
    | ToolCategoryIn
    | ArgExists
    | ArgCompare
    | LabelAtLeast
    | LabelHasTag
    | SourceKindIn
    | PurposeIs
    | ConsentCovers
    | MandatePresent
    | MandateCovers
    | ApprovalPresent
    | AmountExceeds,
    Field(discriminator="kind"),
]

for _model in (All, Any, Not):
    _model.model_rebuild()


class Rule(_Node):
    id: str = Field(pattern=RULE_ID_PATTERN)
    stage: Stage
    then: DecisionName
    explain: str = Field(min_length=1)
    when: Predicate

    @field_validator("then")
    @classmethod
    def _only_escalate(cls, then: Decision) -> Decision:
        if then == Decision.ALLOW:
            raise ValueError("rules may only escalate (STEP_UP or DENY); ALLOW is the base")
        return then


class ArgSpec(_Node):
    type: Literal["string", "integer", "boolean", "array", "object"]
    required: bool = False


class ToolSpec(_Node):
    category: ToolCategory
    args: dict[str, ArgSpec] = Field(default_factory=dict)


def _body(policy_id: str, tools: dict[str, ToolSpec], rules: tuple[Rule, ...]) -> dict[str, object]:
    return {
        "version": 1,
        "id": policy_id,
        "tools": {k: v.model_dump(mode="json") for k, v in tools.items()},
        "rules": [r.model_dump(mode="json") for r in rules],
    }


class CompiledPolicy(_Node):
    version: Literal[1] = 1
    id: str = Field(min_length=1)
    tools: dict[str, ToolSpec]
    rules: tuple[Rule, ...]
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _integrity(self) -> Self:
        ids = [r.id for r in self.rules]
        if ids != sorted(set(ids)):
            raise ValueError("rules must be unique and sorted by id")
        if self.digest != digest(_body(self.id, self.tools, self.rules)):
            raise ValueError("digest does not match policy content")
        return self

    @classmethod
    def create(cls, policy_id: str, tools: dict[str, ToolSpec], rules: list[Rule]) -> Self:
        ordered = tuple(sorted(rules, key=lambda r: r.id))
        return cls(
            id=policy_id,
            tools=dict(sorted(tools.items())),
            rules=ordered,
            digest=digest(_body(policy_id, tools, ordered)),
        )

    def canonical(self) -> str:
        """Canonical JSON of the whole compiled policy (including its digest)."""
        return canonical_json(self.model_dump(mode="json"))
