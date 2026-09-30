# SPDX-License-Identifier: Apache-2.0
"""Authorization artefacts: approvals, mandates, consents.

Signatures are carried but **not verified** in Phase 1 (Ed25519 arrives in Phase 2). The
evaluator therefore must only ever be handed tokens the trusted gateway already authenticated.
"""

from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    model_validator,
)


def require_utc(value: datetime) -> datetime:
    offset = value.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("timestamp must be timezone-aware UTC")
    return value


UtcDatetime = Annotated[datetime, AfterValidator(require_utc)]


class ApprovalToken(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    token_id: str = Field(min_length=1)
    call_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope: str = Field(min_length=1)
    approver: str = Field(min_length=1)
    issued_at: UtcDatetime
    expires_at: UtcDatetime
    nonce: str = Field(min_length=1)
    signature: str | None = None

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self


class Mandate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    mandate_id: str = Field(min_length=1)
    principal: str = Field(min_length=1)
    payee_vpa: str = Field(min_length=1)
    max_amount_paise: int = Field(gt=0)
    currency: Literal["INR"]
    valid_from: UtcDatetime
    valid_until: UtcDatetime
    max_uses: int = Field(gt=0)
    nonce: str = Field(min_length=1)
    signature: str | None = None

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


class Consent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    consent_id: str = Field(min_length=1)
    principal: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    fields: frozenset[str]
    granted_at: UtcDatetime
    withdrawn_at: UtcDatetime | None = None
    status: Literal["active", "withdrawn", "expired"]

    @field_serializer("fields", when_used="json")
    def _ser_fields(self, fields: frozenset[str]) -> list[str]:
        return sorted(fields)
