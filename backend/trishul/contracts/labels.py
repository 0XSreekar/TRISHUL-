# SPDX-License-Identifier: Apache-2.0
"""Security labels: a product lattice ``(level, sources, tags)`` (A5)."""

from collections.abc import Iterable
from enum import IntEnum, StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    field_serializer,
    field_validator,
)

from trishul.contracts.values import parse_enum_name


class Level(IntEnum):
    """Integrity level. Higher is less trusted: ``TRUSTED_USER ⊑ TRUSTED_SYSTEM ⊑ UNTRUSTED``."""

    TRUSTED_USER = 0
    TRUSTED_SYSTEM = 1
    UNTRUSTED = 2


LevelName = Annotated[
    Level,
    BeforeValidator(parse_enum_name(Level)),
    PlainSerializer(lambda v: v.name, return_type=str, when_used="json"),
]

SourceKind = Literal["user", "system", "tool_result", "document", "web", "email", "voice", "model"]


class Tag(StrEnum):
    PII = "PII"
    PII_AADHAAR = "PII_AADHAAR"
    PII_PAN = "PII_PAN"
    PII_PHONE = "PII_PHONE"
    PII_EMAIL = "PII_EMAIL"
    FINANCIAL = "FINANCIAL"
    SECRET = "SECRET"  # noqa: S105
    HEALTH = "HEALTH"


PII_TAGS: frozenset[Tag] = frozenset(t for t in Tag if t.value.startswith("PII"))


def close_tags(tags: Iterable[Tag]) -> frozenset[Tag]:
    """Every specific ``PII_*`` tag implies ``PII``. Closure is preserved by set union."""
    closed = frozenset(tags)
    return closed | {Tag.PII} if closed & PII_TAGS else closed


class SourceRef(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    kind: SourceKind
    id: str = Field(min_length=1)

    @property
    def sort_key(self) -> tuple[str, str]:
        return (self.kind, self.id)

    def __lt__(self, other: "SourceRef") -> bool:
        return self.sort_key < other.sort_key


class Label(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    level: LevelName
    sources: frozenset[SourceRef] = frozenset()
    tags: frozenset[Tag] = frozenset()

    @field_validator("tags")
    @classmethod
    def _close(cls, tags: frozenset[Tag]) -> frozenset[Tag]:
        return close_tags(tags)

    @field_serializer("sources", when_used="json")
    def _ser_sources(self, sources: frozenset[SourceRef]) -> list[dict[str, str]]:
        return [{"kind": s.kind, "id": s.id} for s in sorted(sources)]

    @field_serializer("tags", when_used="json")
    def _ser_tags(self, tags: frozenset[Tag]) -> list[str]:
        return sorted(t.value for t in tags)

    @classmethod
    def bottom(cls) -> Self:
        return cls(level=Level.TRUSTED_USER)

    @classmethod
    def make(
        cls,
        level: Level,
        *,
        sources: Iterable[SourceRef] = (),
        tags: Iterable[Tag] = (),
    ) -> Self:
        return cls(level=level, sources=frozenset(sources), tags=frozenset(tags))
