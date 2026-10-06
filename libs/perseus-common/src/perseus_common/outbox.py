"""Transactional outbox: events are written in the same DB transaction as the state
change they describe, then relayed to Redis. This guarantees we never emit an event
for a rolled-back change, nor lose an event for a committed one."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any

from redis.exceptions import RedisError
from sqlalchemy import Integer, String, Text, Uuid, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column

from perseus_common.background import sleep_or_stop
from perseus_common.db import UTCDateTime
from perseus_common.events import EventEnvelope, EventPublisher
from perseus_common.logging import get_logger
from perseus_common.timeutil import utcnow

log = get_logger(__name__)


class OutboxEventMixin:
    """Mixin for a service's ``outbox_events`` table."""

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(100))
    envelope: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)


def enqueue_event(
    session: AsyncSession,
    model: type[OutboxEventMixin],
    *,
    producer: str,
    event_type: str,
    data: dict[str, Any],
    actor_id: str | None = None,
    subject_id: str | None = None,
) -> EventEnvelope:
    envelope = EventEnvelope(
        type=event_type, producer=producer, actor_id=actor_id, subject_id=subject_id, data=data
    )
    row = model()
    row.id = envelope.id
    row.event_type = event_type
    row.envelope = envelope.model_dump_json()
    row.created_at = envelope.occurred_at
    row.attempts = 0
    session.add(row)
    return envelope


class OutboxRelay:
    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        model: type[OutboxEventMixin],
        publisher: EventPublisher,
        *,
        batch_size: int = 100,
        poll_interval: float = 1.0,
    ) -> None:
        self._sessionmaker = sessionmaker
        self._model = model
        self._publisher = publisher
        self._batch_size = batch_size
        self._poll_interval = poll_interval

    async def run_once(self) -> int:
        model = self._model
        async with self._sessionmaker() as session, session.begin():
            # SKIP LOCKED lets several replicas relay concurrently without double work.
            stmt = (
                select(model)
                .where(model.published_at.is_(None))
                .order_by(model.created_at)
                .limit(self._batch_size)
                .with_for_update(skip_locked=True)
            )
            rows = (await session.scalars(stmt)).all()
            for row in rows:
                row.attempts += 1
                await self._publisher.publish_raw(row.envelope)
                row.published_at = utcnow()
            return len(rows)

    async def run(self, stop: asyncio.Event) -> None:
        backoff = self._poll_interval
        while not stop.is_set():
            try:
                published = await self.run_once()
                backoff = self._poll_interval
                if published:
                    continue
            except (RedisError, SQLAlchemyError, OSError) as exc:
                log.warning("outbox_relay_error", error=str(exc), retry_in=backoff)
                backoff = min(backoff * 2, 30.0)
            await sleep_or_stop(stop, backoff)
