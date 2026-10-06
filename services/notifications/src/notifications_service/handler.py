"""Maps domain events to customer notifications and delivers them idempotently."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from perseus_common.events import EventEnvelope
from perseus_common.logging import get_logger
from perseus_common.money import format_minor_units
from perseus_common.timeutil import utcnow
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from notifications_service.models import Notification, Recipient
from notifications_service.sender import EmailSender
from notifications_service.templates import render

log = get_logger(__name__)

_USER_TEMPLATES = {
    "user.registered": "welcome",
    "user.registration_attempted": "registration_attempt",
    "user.locked": "account_locked",
    "user.password_changed": "password_changed",
    "user.mfa_enabled": "mfa_enabled",
    "user.refresh_token_reuse_detected": "suspicious_session",  # nosec B105
}
_REJECTION_REASONS = {
    "insufficient_funds": "insufficient funds",
    "risk_declined": "it did not pass our security checks",
    "account_not_active": "an account involved is not active",
}


class DeliveryError(Exception):
    pass


@dataclass(frozen=True)
class Delivery:
    user_id: str
    template: str
    context: dict[str, Any] = field(default_factory=dict)


def _money(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "amount": format_minor_units(int(data["amount_minor"]), str(data["currency"])),
        "currency": data["currency"],
        "transaction_id": data["transaction_id"],
    }


def plan_deliveries(event: EventEnvelope) -> list[Delivery]:
    data = event.data
    if event.type in _USER_TEMPLATES:
        return [Delivery(str(data["user_id"]), _USER_TEMPLATES[event.type])]
    if event.type == "transfer.completed":
        deliveries = [Delivery(str(data["source_owner_id"]), "transfer_sent", _money(data))]
        if data.get("destination_owner_id"):
            deliveries.append(
                Delivery(str(data["destination_owner_id"]), "transfer_received", _money(data))
            )
        return deliveries
    if event.type == "transfer.held":
        return [Delivery(str(data["source_owner_id"]), "transfer_held", _money(data))]
    if event.type == "transfer.rejected":
        reason = _REJECTION_REASONS.get(str(data.get("reason")), "it could not be processed")
        context = {**_money(data), "reason": reason}
        return [Delivery(str(data["source_owner_id"]), "transfer_rejected", context)]
    if event.type == "deposit.completed":
        return [Delivery(str(data["destination_owner_id"]), "deposit_received", _money(data))]
    if event.type == "account.frozen":
        return [Delivery(str(data["owner_id"]), "account_frozen")]
    return []


class NotificationHandler:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession], sender: EmailSender) -> None:
        self._sessionmaker = sessionmaker
        self._sender = sender

    async def __call__(self, event: EventEnvelope) -> None:
        if event.type == "user.registered":
            await self._upsert_recipient(event.data)
        failures = 0
        for delivery in plan_deliveries(event):
            if not await self._deliver(event, delivery):
                failures += 1
        if failures:
            raise DeliveryError(f"{failures} notification(s) failed for event {event.id}")

    async def _upsert_recipient(self, data: dict[str, Any]) -> None:
        async with self._sessionmaker() as session:
            user_id = str(data["user_id"])
            recipient = await session.get(Recipient, user_id)
            if recipient is None:
                recipient = Recipient(user_id=user_id)
                session.add(recipient)
            recipient.email = str(data["email"])
            recipient.full_name = str(data["full_name"])
            await session.commit()

    async def _deliver(self, event: EventEnvelope, delivery: Delivery) -> bool:
        # Phase 1 (short transaction): claim the notification and render it.
        async with self._sessionmaker() as session:
            notification = await session.scalar(
                select(Notification).where(
                    Notification.event_id == event.id,
                    Notification.user_id == delivery.user_id,
                    Notification.template == delivery.template,
                )
            )
            if notification is not None and notification.status in ("sent", "skipped"):
                return True
            if notification is None:
                notification = Notification(
                    id=uuid.uuid4(),
                    event_id=event.id,
                    user_id=delivery.user_id,
                    template=delivery.template,
                    status="pending",
                    attempts=0,
                )
                session.add(notification)

            recipient = await session.get(Recipient, delivery.user_id)
            if recipient is None:
                notification.status = "skipped"
                notification.last_error = "unknown_recipient"
                await session.commit()
                return True

            subject, body = render(delivery.template, name=recipient.full_name, **delivery.context)
            notification.subject = subject
            notification.attempts += 1
            notification.status = "sending"
            notification_id, email = notification.id, recipient.email
            await session.commit()

        # Phase 2: network I/O happens outside any database transaction, so a slow mail
        # server can never hold row locks or hit idle-in-transaction timeouts.
        error: str | None = None
        try:
            await self._sender.send(email, subject, body)
        except Exception as exc:  # any transport failure -> retry later
            error = type(exc).__name__
            log.warning("notification_failed", template=delivery.template, error=error)

        # Phase 3 (short transaction): record the outcome.
        async with self._sessionmaker() as session:
            await session.execute(
                update(Notification)
                .where(Notification.id == notification_id)
                .values(
                    status="failed" if error else "sent",
                    last_error=error,
                    sent_at=None if error else utcnow(),
                )
            )
            await session.commit()
        return error is None
