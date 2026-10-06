from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from perseus_common.db import NAMING_CONVENTION, UTCDateTime
from perseus_common.outbox import OutboxEventMixin
from perseus_common.timeutil import utcnow
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Settlement (house) accounts are the counter-party for money entering the platform.
SETTLEMENT_NAMESPACE = uuid.UUID("8f9a4c1e-5b7d-4e0a-9c3f-2d6b8e1f4a70")


def settlement_account_id(currency: str) -> uuid.UUID:
    return uuid.uuid5(SETTLEMENT_NAMESPACE, f"settlement:{currency}")


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class TransactionKind(StrEnum):
    TRANSFER = "transfer"
    DEPOSIT = "deposit"


class TransactionStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    COMPLETED = "completed"
    REJECTED = "rejected"


class Balance(Base):
    __tablename__ = "balances"
    __table_args__ = (
        # Last line of defence: the database itself refuses overdrafts.
        CheckConstraint("allow_negative OR balance_minor >= 0", name="non_negative"),
    )

    account_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    currency: Mapped[str] = mapped_column(String(3))
    balance_minor: Mapped[int] = mapped_column(BigInteger, default=0)
    allow_negative: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class Transaction(Base):
    __tablename__ = "transactions"
    __table_args__ = (
        CheckConstraint("amount_minor > 0", name="positive_amount"),
        CheckConstraint("source_account_id <> destination_account_id", name="distinct_accounts"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), index=True)
    source_account_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    destination_account_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    amount_minor: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3))
    description: Mapped[str | None] = mapped_column(String(140))
    initiated_by: Mapped[str] = mapped_column(String(64), index=True)
    source_owner_id: Mapped[str | None] = mapped_column(String(64))
    destination_owner_id: Mapped[str | None] = mapped_column(String(64))
    risk_score: Mapped[int | None] = mapped_column(Integer)
    risk_decision: Mapped[str | None] = mapped_column(String(10))
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    failure_reason: Mapped[str | None] = mapped_column(String(50))
    reviewed_by: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class Entry(Base):
    """Immutable posting. Entries of one transaction always sum to zero."""

    __tablename__ = "entries"
    __table_args__ = (Index("ix_entries_account_created", "account_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    transaction_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("transactions.id"), index=True
    )
    account_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    amount_minor: Mapped[int] = mapped_column(BigInteger)  # negative = debit
    balance_after: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_keys"
    __table_args__ = (UniqueConstraint("principal_id", "key", name="principal_key"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    principal_id: Mapped[str] = mapped_column(String(64))
    key: Mapped[str] = mapped_column(String(128))
    request_hash: Mapped[str] = mapped_column(String(64))
    status_code: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class OutboxEvent(OutboxEventMixin, Base):
    __tablename__ = "outbox_events"
