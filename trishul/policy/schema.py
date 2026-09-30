"""YAML source model. Predicates (``when``) stay raw here and are parsed by the compiler
so that every nested node can be reported with its own line/column."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class _Src(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class ArgSource(_Src):
    type: Literal["string", "integer", "boolean", "array", "object"]
    required: bool = False


class ToolSource(_Src):
    category: Literal["READ", "WRITE", "PAYMENT", "COMMUNICATION", "EXPORT", "IDENTITY", "VOICE"]
    args: dict[str, ArgSource] = Field(default_factory=dict)


class RuleSource(_Src):
    id: str
    stage: str
    then: str
    explain: str
    when: JsonValue


class PolicyFile(_Src):
    version: Literal[1]
    id: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$")
    tools: dict[str, ToolSource] = Field(default_factory=dict)
    rules: list[RuleSource] = Field(default_factory=list)
