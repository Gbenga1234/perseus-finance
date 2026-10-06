from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from perseus_common.db import DbSession
from perseus_common.security import Principal, require_roles
from pydantic import BaseModel
from sqlalchemy import select

from audit_service.chain import GENESIS_HASH, AuditLog
from audit_service.models import AuditRecord

router = APIRouter(prefix="/v1/audit", tags=["audit"])

Auditor = Annotated[Principal, Depends(require_roles("auditor", "admin"))]


class AuditRecordOut(BaseModel):
    seq: int
    event_id: uuid.UUID
    event_type: str
    producer: str
    actor_id: str | None
    subject_id: str | None
    occurred_at: datetime
    recorded_at: datetime
    data: dict[str, Any]
    hash: str


class VerificationOut(BaseModel):
    valid: bool
    records_checked: int
    head_seq: int | None
    head_hash: str
    first_invalid_seq: int | None


class HeadOut(BaseModel):
    seq: int | None
    hash: str


@router.get("/events", response_model=list[AuditRecordOut])
async def search_events(
    _auditor: Auditor,
    session: DbSession,
    event_type: Annotated[str | None, Query(max_length=100)] = None,
    actor_id: Annotated[str | None, Query(max_length=64)] = None,
    subject_id: Annotated[str | None, Query(max_length=64)] = None,
    after_seq: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AuditRecordOut]:
    stmt = select(AuditRecord).where(AuditRecord.seq > after_seq).order_by(AuditRecord.seq)
    if event_type:
        stmt = stmt.where(AuditRecord.event_type == event_type)
    if actor_id:
        stmt = stmt.where(AuditRecord.actor_id == actor_id)
    if subject_id:
        stmt = stmt.where(AuditRecord.subject_id == subject_id)
    records = await session.scalars(stmt.limit(limit))
    return [
        AuditRecordOut(
            seq=r.seq,
            event_id=r.event_id,
            event_type=r.event_type,
            producer=r.producer,
            actor_id=r.actor_id,
            subject_id=r.subject_id,
            occurred_at=r.occurred_at,
            recorded_at=r.recorded_at,
            data=json.loads(r.record_json)["event"]["data"],
            hash=r.hash,
        )
        for r in records
    ]


@router.get("/verify", response_model=VerificationOut)
async def verify_chain(_auditor: Auditor, request: Request) -> VerificationOut:
    audit_log: AuditLog = request.app.state.audit_log
    result = await audit_log.verify()
    return VerificationOut(**result.__dict__)


@router.get("/head", response_model=HeadOut)
async def chain_head(_auditor: Auditor, session: DbSession) -> HeadOut:
    record = await session.scalar(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1))
    return (
        HeadOut(seq=record.seq, hash=record.hash)
        if record
        else HeadOut(seq=None, hash=GENESIS_HASH)
    )
