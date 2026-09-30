# SPDX-License-Identifier: Apache-2.0
"""Audit-log contracts (implementation is Phase 2)."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from trishul.contracts.authz import UtcDatetime

HEX64 = r"^[0-9a-f]{64}$"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class AuditLeaf(_Frozen):
    index: int = Field(ge=0)
    event_digest: str = Field(pattern=HEX64)
    prev_root: str | None = Field(default=None, pattern=HEX64)
    ts: UtcDatetime


class SignedTreeHead(_Frozen):
    tree_size: int = Field(ge=0)
    root_hash: str = Field(pattern=HEX64)
    ts: UtcDatetime
    signature: str | None = None
    key_id: str | None = None


class InclusionProof(_Frozen):
    leaf_index: int = Field(ge=0)
    tree_size: int = Field(ge=1)
    hashes: tuple[str, ...]


class ConsistencyProof(_Frozen):
    old_size: int = Field(ge=0)
    new_size: int = Field(ge=0)
    hashes: tuple[str, ...]


class ProofResult(_Frozen):
    status: Literal["VERIFIED", "FAILED", "UNAVAILABLE"]
    detail: str
