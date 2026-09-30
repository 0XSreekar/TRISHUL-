"""Tool call / result contracts."""

from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from trishul.contracts.authz import UtcDatetime
from trishul.contracts.canonical import digest, ensure_canonical, is_pointer
from trishul.contracts.labels import Label
from trishul.contracts.lineage import LineageNode


class ToolCategory(StrEnum):
    READ = "READ"
    WRITE = "WRITE"
    PAYMENT = "PAYMENT"
    COMMUNICATION = "COMMUNICATION"
    EXPORT = "EXPORT"
    IDENTITY = "IDENTITY"
    VOICE = "VOICE"


class SourceMetadata(BaseModel):
    """Where a call entered the system (transport-level facts, not content)."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    transport: Literal["stdio", "http", "sse", "in_process", "replay"] = "in_process"
    client_id: str | None = None


class EgressMetadata(BaseModel):
    """Where a result is going when it leaves the trust boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    destination: str = Field(min_length=1)
    recipient_domain: str | None = None
    bytes_out: int | None = Field(default=None, ge=0)


class ToolCall(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    call_id: str = Field(min_length=1)
    server: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    args: dict[str, JsonValue]
    arg_labels: dict[str, Label]
    principal: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    declared_category: ToolCategory | None = None
    source: SourceMetadata
    ts: UtcDatetime

    @field_validator("args")
    @classmethod
    def _canonical_args(cls, args: dict[str, JsonValue]) -> dict[str, JsonValue]:
        ensure_canonical(args)  # rejects floats (A3)
        return args

    @field_validator("arg_labels")
    @classmethod
    def _pointer_keys(cls, labels: dict[str, Label]) -> dict[str, Label]:
        bad = [k for k in labels if not is_pointer(k)]
        if bad:
            raise ValueError("arg_labels keys must be JSON pointers such as /payee/vpa")
        return labels

    def call_digest(self) -> str:
        """Digest an approval binds to: the semantic call, not its id, labels or timestamp."""
        return digest(
            {
                "server": self.server,
                "tool": self.tool,
                "args": self.args,
                "principal": self.principal,
                "task_id": self.task_id,
            }
        )


class ToolResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    call_id: str = Field(min_length=1)
    value: JsonValue
    label: Label
    provenance: tuple[LineageNode, ...] = ()
    egress: EgressMetadata | None = None

    @model_validator(mode="after")
    def _canonical_value(self) -> Self:
        ensure_canonical(self.value)
        return self
