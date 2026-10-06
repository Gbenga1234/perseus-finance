"""Hash-chained audit log.

Each record stores ``hash = SHA-256(prev_hash || canonical_record)``. Altering, deleting
or re-ordering any record breaks every later link, which ``verify`` detects. Publish the
head hash periodically to an external system (anchoring) to also detect truncation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime

from perseus_common.db import is_postgres
from perseus_common.events import EventEnvelope
from perseus_common.logging import get_logger
from perseus_common.timeutil import utcnow
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from audit_service.models import AuditRecord

log = get_logger(__name__)

GENESIS_HASH = "0" * 64
_CHAIN_LOCK_KEY = 0x5045525345  # arbitrary constant for pg_advisory_xact_lock


def canonical_record(envelope: EventEnvelope, recorded_at: datetime) -> str:
    return json.dumps(
        {"event": envelope.model_dump(mode="json"), "recorded_at": recorded_at.isoformat()},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def chain_hash(prev_hash: str, record_json: str) -> str:
    return hashlib.sha256(f"{prev_hash}\n{record_json}".encode()).hexdigest()


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    records_checked: int
    head_seq: int | None
    head_hash: str
    first_invalid_seq: int | None = None


class AuditLog:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def append(self, envelope: EventEnvelope) -> bool:
        """Append an event; returns False if it was already recorded (redelivery)."""
        async with self._sessionmaker() as session:
            if is_postgres(session):
                # Serialise appends across replicas so the chain stays linear.
                await session.execute(
                    text("SELECT pg_advisory_xact_lock(:key)"), {"key": _CHAIN_LOCK_KEY}
                )
            duplicate = await session.scalar(
                select(AuditRecord.seq).where(AuditRecord.event_id == envelope.id)
            )
            if duplicate is not None:
                return False
            prev_hash = await session.scalar(
                select(AuditRecord.hash).order_by(AuditRecord.seq.desc()).limit(1)
            )
            prev_hash = prev_hash or GENESIS_HASH
            recorded_at = utcnow()
            record_json = canonical_record(envelope, recorded_at)
            session.add(
                AuditRecord(
                    event_id=envelope.id,
                    event_type=envelope.type,
                    producer=envelope.producer,
                    actor_id=envelope.actor_id,
                    subject_id=envelope.subject_id,
                    occurred_at=envelope.occurred_at,
                    recorded_at=recorded_at,
                    record_json=record_json,
                    prev_hash=prev_hash,
                    hash=chain_hash(prev_hash, record_json),
                )
            )
            await session.commit()
            return True

    async def verify(self, batch_size: int = 1000) -> VerificationResult:
        expected_prev = GENESIS_HASH
        checked = 0
        last_seq: int | None = None
        async with self._sessionmaker() as session:
            while True:
                stmt = select(AuditRecord).order_by(AuditRecord.seq).limit(batch_size)
                if last_seq is not None:
                    stmt = stmt.where(AuditRecord.seq > last_seq)
                records = list(await session.scalars(stmt))
                if not records:
                    break
                for record in records:
                    event = json.loads(record.record_json)["event"]
                    consistent = (
                        record.prev_hash == expected_prev
                        and record.hash == chain_hash(record.prev_hash, record.record_json)
                        and event["id"] == str(record.event_id)
                        and event["type"] == record.event_type
                    )
                    if not consistent:
                        log.error("audit_chain_broken", seq=record.seq, security=True)
                        return VerificationResult(
                            False, checked, last_seq, expected_prev, record.seq
                        )
                    expected_prev = record.hash
                    last_seq = record.seq
                    checked += 1
        return VerificationResult(True, checked, last_seq, expected_prev)
