from __future__ import annotations

import uuid
from datetime import datetime

from perseus_common.money import AMOUNT_PATTERN, format_minor_units, validate_currency
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ledger_service.models import Entry, Transaction

SAFE_TEXT = r"^[^\x00-\x1f\x7f<>]+$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class _MoneyIn(StrictModel):
    # Amounts are decimal strings (e.g. "25.00"); JSON numbers are rejected to avoid floats.
    amount: str = Field(pattern=AMOUNT_PATTERN, examples=["25.00"])
    currency: str = Field(pattern=r"^[A-Z]{3}$", examples=["USD"])

    @field_validator("currency")
    @classmethod
    def _supported(cls, value: str) -> str:
        return validate_currency(value)


class TransferRequest(_MoneyIn):
    source_account_id: uuid.UUID
    destination_account_id: uuid.UUID
    description: str | None = Field(default=None, max_length=140, pattern=SAFE_TEXT)


class DepositRequest(_MoneyIn):
    account_id: uuid.UUID
    reference: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._\-]+$")


class RejectRequest(StrictModel):
    reason: str = Field(min_length=3, max_length=50, pattern=r"^[a-z0-9_]+$")


class TransactionOut(BaseModel):
    id: uuid.UUID
    kind: str
    status: str
    source_account_id: uuid.UUID
    destination_account_id: uuid.UUID
    amount: str
    amount_minor: int
    currency: str
    description: str | None
    failure_reason: str | None
    created_at: datetime
    completed_at: datetime | None

    @classmethod
    def from_model(cls, tx: Transaction) -> TransactionOut:
        return cls(
            id=tx.id,
            kind=tx.kind,
            status=tx.status,
            source_account_id=tx.source_account_id,
            destination_account_id=tx.destination_account_id,
            amount=format_minor_units(tx.amount_minor, tx.currency),
            amount_minor=tx.amount_minor,
            currency=tx.currency,
            description=tx.description,
            failure_reason=tx.failure_reason,
            created_at=tx.created_at,
            completed_at=tx.completed_at,
        )


class BalanceOut(BaseModel):
    account_id: uuid.UUID
    currency: str
    balance: str
    balance_minor: int


class EntryOut(BaseModel):
    id: uuid.UUID
    transaction_id: uuid.UUID
    amount: str
    amount_minor: int
    balance_after_minor: int
    currency: str
    created_at: datetime

    @classmethod
    def from_model(cls, entry: Entry) -> EntryOut:
        sign = "-" if entry.amount_minor < 0 else ""
        return cls(
            id=entry.id,
            transaction_id=entry.transaction_id,
            amount=sign + format_minor_units(abs(entry.amount_minor), entry.currency),
            amount_minor=entry.amount_minor,
            balance_after_minor=entry.balance_after,
            currency=entry.currency,
            created_at=entry.created_at,
        )


class InternalBalanceOut(BaseModel):
    account_id: uuid.UUID
    currency: str
    balance_minor: int
