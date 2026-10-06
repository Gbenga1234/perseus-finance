from __future__ import annotations

import uuid
from datetime import datetime

from perseus_common.db import NAMING_CONVENTION, UTCDateTime
from perseus_common.outbox import OutboxEventMixin
from perseus_common.timeutil import utcnow
from sqlalchemy import JSON, BigInteger, Integer, MetaData, String, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    transaction_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    source_account_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    destination_account_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    amount_minor: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3))
    score: Mapped[int] = mapped_column(Integer)
    decision: Mapped[str] = mapped_column(String(10), index=True)
    rules: Mapped[list[str]] = mapped_column(JSON, default=list)
    requested_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class OutboxEvent(OutboxEventMixin, Base):
    __tablename__ = "outbox_events"
