"""Signed domain events over Redis Streams.

Every event is wrapped in an envelope and HMAC-SHA256 signed by the producer. Consumers
reject unsigned or tampered messages, so write access to Redis alone is not enough to
inject forged events (e.g. a fake ``transfer.completed``).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import socket
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError

from perseus_common.background import sleep_or_stop
from perseus_common.logging import get_logger
from perseus_common.timeutil import utcnow

log = get_logger(__name__)

MIN_KEY_BYTES = 32


class EventEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    type: str = Field(min_length=1, max_length=100)
    version: int = 1
    producer: str
    occurred_at: datetime = Field(default_factory=utcnow)
    actor_id: str | None = None
    subject_id: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class InvalidEventError(Exception):
    pass


class EventSigner:
    def __init__(self, key: str | bytes) -> None:
        key_bytes = key.encode() if isinstance(key, str) else key
        if len(key_bytes) < MIN_KEY_BYTES:
            raise ValueError("Event signing key must be at least 32 bytes")
        self._key = key_bytes

    def sign(self, body: str) -> str:
        return hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()

    def verify(self, body: str, signature: str) -> bool:
        return hmac.compare_digest(self.sign(body), signature)


def decode_event(fields: dict[str, str], signer: EventSigner) -> EventEnvelope:
    body = fields.get("envelope")
    signature = fields.get("sig")
    if not body or not signature or not signer.verify(body, signature):
        raise InvalidEventError("Missing or invalid event signature")
    try:
        return EventEnvelope.model_validate_json(body)
    except ValidationError as exc:
        raise InvalidEventError("Malformed event envelope") from exc


class EventPublisher(Protocol):
    async def publish_raw(self, body: str) -> None: ...


class RedisEventPublisher:
    def __init__(
        self, redis: Redis, stream: str, signer: EventSigner, *, maxlen: int = 1_000_000
    ) -> None:
        self._redis = redis
        self._stream = stream
        self._signer = signer
        self._maxlen = maxlen

    async def publish_raw(self, body: str) -> None:
        await self._redis.xadd(
            self._stream,
            {"envelope": body, "sig": self._signer.sign(body)},
            maxlen=self._maxlen,
            approximate=True,
        )

    async def publish(self, envelope: EventEnvelope) -> None:
        await self.publish_raw(envelope.model_dump_json())


EventHandler = Callable[[EventEnvelope], Awaitable[None]]


class EventConsumer:
    """At-least-once consumer using a Redis consumer group.

    * Messages are acknowledged only after the handler succeeds.
    * Messages left pending (crashed consumer / handler error) are re-claimed after
      ``reclaim_idle_ms`` and retried; after ``max_deliveries`` they go to a DLQ.
    * Messages with a bad signature go straight to the DLQ.
    Handlers must therefore be idempotent (dedupe on ``envelope.id``).
    """

    def __init__(
        self,
        redis: Redis,
        *,
        stream: str,
        group: str,
        signer: EventSigner,
        handler: EventHandler,
        consumer_name: str | None = None,
        max_deliveries: int = 5,
        reclaim_idle_ms: int = 60_000,
        block_ms: int = 5_000,
        batch_size: int = 20,
    ) -> None:
        self._redis = redis
        self._stream = stream
        self._group = group
        self._signer = signer
        self._handler = handler
        self._consumer = consumer_name or f"{socket.gethostname()}-{os.getpid()}"
        self._max_deliveries = max_deliveries
        self._reclaim_idle_ms = reclaim_idle_ms
        self._block_ms = block_ms
        self._batch_size = batch_size
        self.dlq_stream = f"{stream}:dlq"

    async def ensure_group(self) -> None:
        try:
            await self._redis.xgroup_create(self._stream, self._group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def run(self, stop: asyncio.Event) -> None:
        backoff = 1.0
        await self._retrying(self.ensure_group, stop)
        log.info("event_consumer_started", group=self._group, consumer=self._consumer)
        iteration = 0
        while not stop.is_set():
            try:
                if iteration % 12 == 0:
                    await self.reclaim_stale()
                iteration += 1
                await self.poll_once()
                backoff = 1.0
            except (RedisError, OSError) as exc:
                log.warning("event_consumer_error", error=str(exc), retry_in=backoff)
                await sleep_or_stop(stop, backoff)
                backoff = min(backoff * 2, 30.0)

    async def poll_once(self) -> int:
        response = await self._redis.xreadgroup(
            self._group,
            self._consumer,
            {self._stream: ">"},
            count=self._batch_size,
            block=self._block_ms,
        )
        handled = 0
        for _stream, messages in response or []:
            for message_id, fields in messages:
                await self._process(message_id, fields)
                handled += 1
        return handled

    async def reclaim_stale(self) -> None:
        pending = await self._redis.xpending_range(
            self._stream,
            self._group,
            min="-",
            max="+",
            count=self._batch_size,
            idle=self._reclaim_idle_ms,
        )
        for entry in pending:
            message_id = entry["message_id"]
            if entry["times_delivered"] >= self._max_deliveries:
                claimed = await self._redis.xclaim(
                    self._stream, self._group, self._consumer, self._reclaim_idle_ms, [message_id]
                )
                fields = claimed[0][1] if claimed and claimed[0][1] else {}
                await self._dead_letter(message_id, fields, "max_deliveries_exceeded")
                continue
            claimed = await self._redis.xclaim(
                self._stream, self._group, self._consumer, self._reclaim_idle_ms, [message_id]
            )
            for claimed_id, fields in claimed:
                if fields:
                    await self._process(claimed_id, fields)

    async def _process(self, message_id: str, fields: dict[str, str]) -> None:
        try:
            envelope = decode_event(fields, self._signer)
        except InvalidEventError as exc:
            log.error("event_rejected", message_id=message_id, reason=str(exc), security=True)
            await self._dead_letter(message_id, fields, str(exc))
            return
        try:
            await self._handler(envelope)
        except Exception:
            # Leave un-acked: it will be re-claimed and retried, then dead-lettered.
            log.exception("event_handler_failed", event_id=str(envelope.id), type=envelope.type)
            return
        await self._redis.xack(self._stream, self._group, message_id)

    async def _dead_letter(self, message_id: str, fields: dict[str, str], reason: str) -> None:
        entry: dict[Any, Any] = {
            **fields,
            "original_id": message_id,
            "group": self._group,
            "reason": reason,
        }
        await self._redis.xadd(
            self.dlq_stream,
            entry,
            maxlen=100_000,
            approximate=True,
        )
        await self._redis.xack(self._stream, self._group, message_id)

    @staticmethod
    async def _retrying(func: Callable[[], Awaitable[None]], stop: asyncio.Event) -> None:
        delay = 1.0
        while not stop.is_set():
            try:
                await func()
                return
            except (RedisError, OSError) as exc:
                log.warning("redis_unavailable", error=str(exc), retry_in=delay)
                await sleep_or_stop(stop, delay)
                delay = min(delay * 2, 30.0)
