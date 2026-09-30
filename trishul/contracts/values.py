# SPDX-License-Identifier: Apache-2.0
"""Sentinels and value wrappers that keep absent / null / empty / redacted distinct."""

from collections.abc import Callable
from enum import Enum
from typing import Literal, final

from pydantic import BaseModel, ConfigDict, Field, model_serializer


@final
class Absent:
    """Singleton marking a missing key. Never equal to ``None`` (explicit JSON null)."""

    _instance: "Absent | None" = None

    def __new__(cls) -> "Absent":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "ABSENT"

    def __bool__(self) -> bool:
        return False


ABSENT = Absent()


class Redacted(BaseModel):
    """A value that was removed from an event. ``digest`` is a keyed pseudonym or ``None``."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, populate_by_name=True)

    redacted: Literal[True] = Field(default=True, alias="$redacted")
    reason: str
    digest: str | None = None

    @model_serializer
    def _serialize(self) -> dict[str, object]:
        return {"$redacted": True, "reason": self.reason, "digest": self.digest}


type RedactedJson = (
    Redacted | bool | int | str | list[RedactedJson] | dict[str, RedactedJson] | None
)


def parse_enum_name[E: Enum](enum_cls: type[E]) -> Callable[[object], object]:
    """Build a before-validator accepting the enum instance or its member *name*."""

    def _parse(value: object) -> object:
        if isinstance(value, enum_cls):
            return value
        if isinstance(value, str) and value in enum_cls.__members__:
            return enum_cls[value]
        raise ValueError(f"expected one of {sorted(enum_cls.__members__)}")

    return _parse
