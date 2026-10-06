from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from perseus_common.db import DbSession
from perseus_common.errors import UpstreamError
from perseus_common.logging import get_logger
from perseus_common.outbox import enqueue_event
from perseus_common.security import Principal, require_roles, require_service_scopes
from perseus_common.timeutil import utcnow
from pydantic import BaseModel, ConfigDict, Field
from redis.exceptions import RedisError
from sqlalchemy import select

from fraud_service.config import Settings
from fraud_service.models import Assessment, OutboxEvent
from fraud_service.rules import RiskContext, evaluate
from fraud_service.signals import SignalStore

log = get_logger(__name__)

internal_router = APIRouter(prefix="/internal", tags=["internal"])
router = APIRouter(prefix="/v1/fraud", tags=["fraud"])


class AssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transaction_id: uuid.UUID
    user_id: str = Field(min_length=1, max_length=64)
    source_account_id: uuid.UUID
    destination_account_id: uuid.UUID
    amount_minor: int = Field(gt=0, le=10**17)
    currency: str = Field(pattern=r"^[A-Z]{3}$")


class AssessmentResponse(BaseModel):
    assessment_id: uuid.UUID
    decision: Literal["allow", "review", "deny"]
    score: int
    rules: list[str]


class AssessmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    transaction_id: uuid.UUID
    user_id: str
    amount_minor: int
    currency: str
    score: int
    decision: str
    rules: list[str]
    created_at: datetime


ServiceCaller = Annotated[Principal, Depends(require_service_scopes("fraud:assess"))]
Analyst = Annotated[Principal, Depends(require_roles("admin", "auditor"))]


@internal_router.post("/assessments", response_model=AssessmentResponse)
async def assess(
    body: AssessmentRequest, caller: ServiceCaller, request: Request, session: DbSession
) -> AssessmentResponse:
    settings: Settings = request.app.state.settings
    signals: SignalStore = request.app.state.signals
    now = utcnow()
    day = now.strftime("%Y-%m-%d")
    destination = str(body.destination_account_id)
    try:
        attempts = await signals.record_attempt(
            body.user_id, time.time(), settings.velocity_window_seconds
        )
        daily_total = await signals.daily_total(body.user_id, day)
        known_payee = await signals.is_known_payee(body.user_id, destination)
    except (RedisError, OSError) as exc:
        # The ledger treats this as "cannot assess" and blocks the transfer (fail closed).
        raise UpstreamError("Risk signals unavailable") from exc

    result = evaluate(
        RiskContext(
            amount_minor=body.amount_minor,
            attempts_in_window=attempts,
            daily_total_minor=daily_total,
            known_payee=known_payee,
        ),
        settings,
    )
    rules = [hit.rule for hit in result.hits]
    assessment = Assessment(
        id=uuid.uuid4(),
        transaction_id=body.transaction_id,
        user_id=body.user_id,
        source_account_id=body.source_account_id,
        destination_account_id=body.destination_account_id,
        amount_minor=body.amount_minor,
        currency=body.currency,
        score=result.score,
        decision=result.decision,
        rules=rules,
        requested_by=caller.subject,
        created_at=now,
    )
    session.add(assessment)
    if result.decision != "allow":
        enqueue_event(
            session,
            OutboxEvent,
            producer=settings.service_name,
            event_type="fraud.flagged",
            actor_id=caller.subject,
            subject_id=str(body.transaction_id),
            data={
                "assessment_id": str(assessment.id),
                "transaction_id": str(body.transaction_id),
                "user_id": body.user_id,
                "decision": result.decision,
                "score": result.score,
                "rules": rules,
            },
        )
        log.info("transfer_flagged", decision=result.decision, score=result.score, rules=rules)
    await session.commit()

    if result.decision != "deny":
        try:
            await signals.record_accepted(body.user_id, day, body.amount_minor, destination)
        except (RedisError, OSError):
            log.warning("signal_record_failed", user_id=body.user_id)

    return AssessmentResponse(
        assessment_id=assessment.id, decision=result.decision, score=result.score, rules=rules
    )


@router.get("/assessments", response_model=list[AssessmentOut])
async def list_assessments(
    _analyst: Analyst,
    session: DbSession,
    decision: Annotated[Literal["allow", "review", "deny"] | None, Query()] = None,
    user_id: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[Assessment]:
    stmt = select(Assessment).order_by(Assessment.created_at.desc()).limit(limit)
    if decision:
        stmt = stmt.where(Assessment.decision == decision)
    if user_id:
        stmt = stmt.where(Assessment.user_id == user_id)
    return list(await session.scalars(stmt))
