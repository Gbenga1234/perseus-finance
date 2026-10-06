from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from perseus_common.money import validate_currency
from pydantic import BaseModel, ConfigDict, Field, field_validator

SAFE_TEXT = r"^[^\x00-\x1f\x7f<>]+$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CreateAccountRequest(StrictModel):
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    kind: Literal["checking", "savings"] = "checking"
    nickname: str | None = Field(default=None, min_length=1, max_length=50, pattern=SAFE_TEXT)

    @field_validator("currency")
    @classmethod
    def _supported(cls, value: str) -> str:
        return validate_currency(value)


class UpdateAccountRequest(StrictModel):
    nickname: str | None = Field(default=None, min_length=1, max_length=50, pattern=SAFE_TEXT)


class FreezeRequest(StrictModel):
    reason: str = Field(min_length=3, max_length=200, pattern=SAFE_TEXT)


class AccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    owner_id: uuid.UUID
    account_number: str
    currency: str
    kind: str
    status: str
    nickname: str | None
    created_at: datetime
    closed_at: datetime | None


class InternalAccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    owner_id: uuid.UUID
    currency: str
    status: str
    created_at: datetime
