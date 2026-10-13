# SPDX-License-Identifier: Apache-2.0
"""Typed extraction schemas. ``extra="forbid"`` + strict types: anything the model adds, omits
or mistypes is invalid output and the call is denied."""

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

VPA_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}@[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
_CFG = ConfigDict(extra="forbid", strict=True)


class InvoiceFields(BaseModel):
    model_config = _CFG
    payee_vpa: str = Field(pattern=VPA_PATTERN)
    amount_paise: int = Field(gt=0, le=10**12)
    due_date: date | None = None
    invoice_id: str | None = Field(default=None, max_length=64)


class VoiceCommandFields(BaseModel):
    model_config = _CFG
    intent: Literal["pay", "add_payee", "balance", "other"]
    payee_vpa: str | None = Field(default=None, pattern=VPA_PATTERN)
    amount_paise: int | None = Field(default=None, gt=0, le=10**12)


class EmailFields(BaseModel):
    model_config = _CFG
    sender: str = Field(min_length=1, max_length=320)
    subject_intent: str = Field(min_length=1, max_length=200)


SCHEMAS: dict[str, type[BaseModel]] = {
    "invoice": InvoiceFields,
    "voice_command": VoiceCommandFields,
    "email": EmailFields,
}
