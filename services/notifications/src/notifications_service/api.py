from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from perseus_common.db import DbSession
from perseus_common.security import CurrentUser
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from notifications_service.models import Notification

router = APIRouter(prefix="/v1/notifications", tags=["notifications"])


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    template: str
    channel: str
    subject: str | None
    status: str
    created_at: datetime
    sent_at: datetime | None


@router.get("", response_model=list[NotificationOut])
async def list_notifications(
    user: CurrentUser,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[Notification]:
    rows = await session.scalars(
        select(Notification)
        .where(Notification.user_id == user.subject)
        .order_by(Notification.created_at.desc())
        .limit(limit)
    )
    return list(rows)
