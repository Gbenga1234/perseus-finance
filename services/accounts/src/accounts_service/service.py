from __future__ import annotations

import secrets
import uuid
from typing import Any

from perseus_common.errors import ConflictError, NotFoundError, UnprocessableError
from perseus_common.outbox import enqueue_event
from perseus_common.security import Principal
from perseus_common.timeutil import utcnow
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from accounts_service.config import Settings
from accounts_service.ledger import LedgerGateway
from accounts_service.models import Account, AccountStatus, OutboxEvent

_MAX_NUMBER_ATTEMPTS = 5


def luhn_check_digit(digits: str) -> str:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 0:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return str((10 - total % 10) % 10)


def generate_account_number() -> str:
    body = "".join(secrets.choice("0123456789") for _ in range(9))
    return body + luhn_check_digit(body)


class AccountService:
    def __init__(self, session: AsyncSession, settings: Settings, ledger: LedgerGateway) -> None:
        self.session = session
        self.settings = settings
        self.ledger = ledger

    def _emit(self, event_type: str, account: Account, actor: Principal, **extra: Any) -> None:
        enqueue_event(
            self.session,
            OutboxEvent,
            producer=self.settings.service_name,
            event_type=event_type,
            actor_id=actor.subject,
            subject_id=str(account.id),
            data={
                "account_id": str(account.id),
                "owner_id": str(account.owner_id),
                "currency": account.currency,
                "status": account.status,
                **extra,
            },
        )

    async def get_visible(self, account_id: uuid.UUID, principal: Principal) -> Account:
        """Fetch an account the caller may see. Returns 404 (not 403) for other users'
        accounts so account ids cannot be probed."""
        account = await self.session.get(Account, account_id)
        if account is None or (
            str(account.owner_id) != principal.subject and not principal.is_admin
        ):
            raise NotFoundError("Account not found.")
        return account

    async def list_for_owner(self, owner_id: uuid.UUID) -> list[Account]:
        rows = await self.session.scalars(
            select(Account).where(Account.owner_id == owner_id).order_by(Account.created_at)
        )
        return list(rows)

    async def open(
        self, principal: Principal, currency: str, kind: str, nickname: str | None
    ) -> Account:
        owner_id = uuid.UUID(principal.subject)
        open_count = await self.session.scalar(
            select(func.count())
            .select_from(Account)
            .where(Account.owner_id == owner_id, Account.status != AccountStatus.CLOSED)
        )
        if (open_count or 0) >= self.settings.max_accounts_per_user:
            raise UnprocessableError("Maximum number of accounts reached.", code="account_limit")

        for _ in range(_MAX_NUMBER_ATTEMPTS):
            account = Account(
                id=uuid.uuid4(),
                owner_id=owner_id,
                account_number=generate_account_number(),
                currency=currency,
                kind=kind,
                status=AccountStatus.ACTIVE,
                nickname=nickname,
            )
            self.session.add(account)
            self._emit("account.opened", account, principal, kind=kind)
            try:
                await self.session.commit()
                return account
            except IntegrityError:
                await self.session.rollback()  # account number collision; retry
        raise ConflictError("Could not allocate an account number, please retry.")

    async def rename(self, account: Account, nickname: str | None) -> Account:
        account.nickname = nickname
        await self.session.commit()
        return account

    async def freeze(self, account: Account, principal: Principal, reason: str) -> Account:
        if account.status != AccountStatus.ACTIVE:
            raise ConflictError("Only active accounts can be frozen.", code="invalid_status")
        account.status = AccountStatus.FROZEN
        account.frozen_reason = reason
        self._emit("account.frozen", account, principal, reason=reason)
        await self.session.commit()
        return account

    async def unfreeze(self, account: Account, principal: Principal) -> Account:
        if account.status != AccountStatus.FROZEN:
            raise ConflictError("Account is not frozen.", code="invalid_status")
        account.status = AccountStatus.ACTIVE
        account.frozen_reason = None
        self._emit("account.unfrozen", account, principal)
        await self.session.commit()
        return account

    async def close(self, account: Account, principal: Principal) -> Account:
        if account.status != AccountStatus.ACTIVE:
            raise ConflictError("Only active accounts can be closed.", code="invalid_status")
        if await self.ledger.balance_minor(account.id) != 0:
            raise ConflictError("Account balance must be zero to close.", code="balance_not_zero")
        account.status = AccountStatus.CLOSED
        account.closed_at = utcnow()
        self._emit("account.closed", account, principal)
        await self.session.commit()
        return account
