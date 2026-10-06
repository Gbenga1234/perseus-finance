from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from perseus_common.db import NAMING_CONVENTION, UTCDateTime
from perseus_common.outbox import OutboxEventMixin
from perseus_common.timeutil import utcnow
from sqlalchemy import MetaData, String, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class AccountStatus(StrEnum):
    ACTIVE = "active"
    FROZEN = "frozen"
    CLOSED = "closed"


class AccountKind(StrEnum):
    CHECKING = "checking"
    SAVINGS = "savings"


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    account_number: Mapped[str] = mapped_column(String(10), unique=True)
    currency: Mapped[str] = mapped_column(String(3))
    kind: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default=AccountStatus.ACTIVE)
    nickname: Mapped[str | None] = mapped_column(String(50))
    frozen_reason: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class OutboxEvent(OutboxEventMixin, Base):
    __tablename__ = "outbox_events"
