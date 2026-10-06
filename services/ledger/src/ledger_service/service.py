"""Ledger business logic: double-entry posting with pessimistic row locking."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from perseus_common.errors import ConflictError, NotFoundError, UnprocessableError
from perseus_common.logging import get_logger
from perseus_common.money import MoneyError, to_minor_units
from perseus_common.outbox import enqueue_event
from perseus_common.security import Principal
from perseus_common.timeutil import utcnow
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ledger_service.config import Settings
from ledger_service.gateways import AccountInfo, AccountsGateway, FraudGateway
from ledger_service.models import (
    Balance,
    Entry,
    OutboxEvent,
    Transaction,
    TransactionKind,
    TransactionStatus,
    settlement_account_id,
)
from ledger_service.schemas import DepositRequest, TransferRequest

log = get_logger(__name__)

ACTIVE = "active"


class InsufficientFundsError(Exception):
    pass


@dataclass(frozen=True)
class Outcome:
    transaction: Transaction
    status_code: int
    error_code: str | None = None
    detail: str | None = None


class LedgerService:
    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        accounts: AccountsGateway,
        fraud: FraudGateway,
    ) -> None:
        self.session = session
        self.settings = settings
        self.accounts = accounts
        self.fraud = fraud

    # -- helpers -------------------------------------------------------------------

    def _emit(self, event_type: str, tx: Transaction, actor: str, **extra: Any) -> None:
        enqueue_event(
            self.session,
            OutboxEvent,
            producer=self.settings.service_name,
            event_type=event_type,
            actor_id=actor,
            subject_id=str(tx.id),
            data={
                "transaction_id": str(tx.id),
                "kind": tx.kind,
                "status": tx.status,
                "source_account_id": str(tx.source_account_id),
                "destination_account_id": str(tx.destination_account_id),
                "source_owner_id": tx.source_owner_id,
                "destination_owner_id": tx.destination_owner_id,
                "amount_minor": tx.amount_minor,
                "currency": tx.currency,
                **extra,
            },
        )

    @staticmethod
    def _amount(amount: str, currency: str) -> int:
        try:
            return to_minor_units(amount, currency)
        except MoneyError as exc:
            raise UnprocessableError(str(exc), code="invalid_amount") from exc

    async def _require_account(self, account_id: uuid.UUID, label: str) -> AccountInfo:
        info = await self.accounts.get_account(account_id)
        if info is None:
            raise NotFoundError(f"{label} account not found.", code="account_not_found")
        return info

    @staticmethod
    def _require_active(*accounts: AccountInfo) -> None:
        for account in accounts:
            if account.status != ACTIVE:
                raise ConflictError("Account is not active.", code="account_not_active")

    async def _ensure_balance(
        self, account_id: uuid.UUID, currency: str, *, allow_negative: bool = False
    ) -> None:
        values = {
            "account_id": account_id,
            "currency": currency,
            "balance_minor": 0,
            "allow_negative": allow_negative,
            "version": 0,
            "updated_at": utcnow(),
        }
        insert = (
            pg_insert if self.session.get_bind().dialect.name == "postgresql" else sqlite_insert
        )
        await self.session.execute(insert(Balance).values(**values).on_conflict_do_nothing())

    async def _post(self, tx: Transaction) -> None:
        """Move ``tx.amount_minor`` from source to destination atomically.

        Balance rows are locked in a deterministic (sorted) order so concurrent
        transfers touching the same accounts cannot deadlock.
        """
        is_deposit = tx.kind == TransactionKind.DEPOSIT
        await self._ensure_balance(tx.source_account_id, tx.currency, allow_negative=is_deposit)
        await self._ensure_balance(tx.destination_account_id, tx.currency)

        rows = await self.session.scalars(
            select(Balance)
            .where(Balance.account_id.in_([tx.source_account_id, tx.destination_account_id]))
            .order_by(Balance.account_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        balances = {row.account_id: row for row in rows}
        source = balances[tx.source_account_id]
        destination = balances[tx.destination_account_id]
        if source.currency != tx.currency or destination.currency != tx.currency:
            raise ConflictError("Currency mismatch on ledger account.", code="currency_mismatch")
        if not source.allow_negative and source.balance_minor < tx.amount_minor:
            raise InsufficientFundsError

        now = utcnow()
        source.balance_minor -= tx.amount_minor
        destination.balance_minor += tx.amount_minor
        for balance in (source, destination):
            balance.version += 1
            balance.updated_at = now
        self.session.add_all(
            [
                Entry(
                    transaction_id=tx.id,
                    account_id=source.account_id,
                    amount_minor=-tx.amount_minor,
                    balance_after=source.balance_minor,
                    currency=tx.currency,
                    created_at=now,
                ),
                Entry(
                    transaction_id=tx.id,
                    account_id=destination.account_id,
                    amount_minor=tx.amount_minor,
                    balance_after=destination.balance_minor,
                    currency=tx.currency,
                    created_at=now,
                ),
            ]
        )
        tx.status = TransactionStatus.COMPLETED
        tx.completed_at = now

    def _reject(self, tx: Transaction, actor: str, reason: str) -> None:
        tx.status = TransactionStatus.REJECTED
        tx.failure_reason = reason
        event = "deposit.rejected" if tx.kind == TransactionKind.DEPOSIT else "transfer.rejected"
        self._emit(event, tx, actor, reason=reason)

    async def _settle(self, tx: Transaction, actor: str) -> Outcome:
        try:
            await self._post(tx)
        except InsufficientFundsError:
            self._reject(tx, actor, "insufficient_funds")
            return Outcome(tx, 422, "insufficient_funds", "Insufficient funds.")
        event = "deposit.completed" if tx.kind == TransactionKind.DEPOSIT else "transfer.completed"
        self._emit(event, tx, actor)
        return Outcome(tx, 201)

    # -- use cases ------------------------------------------------------------------

    async def transfer(self, principal: Principal, req: TransferRequest) -> Outcome:
        amount = self._amount(req.amount, req.currency)
        if req.source_account_id == req.destination_account_id:
            raise UnprocessableError("Cannot transfer to the same account.", code="same_account")

        source = await self._require_account(req.source_account_id, "Source")
        if source.owner_id != principal.subject:
            # Do not reveal that someone else's account exists.
            raise NotFoundError("Source account not found.", code="account_not_found")
        destination = await self._require_account(req.destination_account_id, "Destination")
        self._require_active(source, destination)
        if source.currency != req.currency or destination.currency != req.currency:
            raise UnprocessableError("Currency does not match accounts.", code="currency_mismatch")

        tx = Transaction(
            id=uuid.uuid4(),
            kind=TransactionKind.TRANSFER,
            status=TransactionStatus.PENDING_REVIEW,
            source_account_id=source.id,
            destination_account_id=destination.id,
            amount_minor=amount,
            currency=req.currency,
            description=req.description,
            initiated_by=principal.subject,
            source_owner_id=source.owner_id,
            destination_owner_id=destination.owner_id,
            created_at=utcnow(),
        )
        risk = await self.fraud.assess(
            transaction_id=tx.id,
            user_id=principal.subject,
            source_account_id=source.id,
            destination_account_id=destination.id,
            amount_minor=amount,
            currency=req.currency,
        )
        tx.risk_score = risk.score
        tx.risk_decision = risk.decision
        tx.assessment_id = risk.assessment_id
        self.session.add(tx)
        # Insert the parent row now: entries reference it and there is no ORM relationship
        # to tell the unit of work about that ordering.
        await self.session.flush()

        if risk.decision == "deny":
            self._reject(tx, principal.subject, "risk_declined")
            log.warning("transfer_declined_by_risk", transaction_id=str(tx.id), score=risk.score)
            return Outcome(tx, 422, "transfer_declined", "The transfer was declined.")
        if risk.decision == "review":
            self._emit("transfer.held", tx, principal.subject)
            return Outcome(tx, 202)
        return await self._settle(tx, principal.subject)

    async def deposit(self, principal: Principal, req: DepositRequest) -> Outcome:
        amount = self._amount(req.amount, req.currency)
        account = await self._require_account(req.account_id, "Destination")
        self._require_active(account)
        if account.currency != req.currency:
            raise UnprocessableError("Currency does not match account.", code="currency_mismatch")
        tx = Transaction(
            id=uuid.uuid4(),
            kind=TransactionKind.DEPOSIT,
            status=TransactionStatus.PENDING_REVIEW,
            source_account_id=settlement_account_id(req.currency),
            destination_account_id=account.id,
            amount_minor=amount,
            currency=req.currency,
            description=f"Deposit ref {req.reference}",
            initiated_by=principal.subject,
            destination_owner_id=account.owner_id,
            created_at=utcnow(),
        )
        self.session.add(tx)
        await self.session.flush()  # parent row must exist before its entries
        return await self._settle(tx, principal.subject)

    async def _pending_for_update(self, transaction_id: uuid.UUID) -> Transaction:
        tx = await self.session.scalar(
            select(Transaction).where(Transaction.id == transaction_id).with_for_update()
        )
        if tx is None:
            raise NotFoundError("Transaction not found.")
        if tx.status != TransactionStatus.PENDING_REVIEW:
            raise ConflictError("Transaction is not awaiting review.", code="invalid_status")
        return tx

    async def approve(self, principal: Principal, transaction_id: uuid.UUID) -> Outcome:
        tx = await self._pending_for_update(transaction_id)
        tx.reviewed_by = principal.subject
        source = await self._require_account(tx.source_account_id, "Source")
        destination = await self._require_account(tx.destination_account_id, "Destination")
        if source.status != ACTIVE or destination.status != ACTIVE:
            self._reject(tx, principal.subject, "account_not_active")
            outcome = Outcome(tx, 409, "account_not_active", "An account is no longer active.")
        else:
            outcome = await self._settle(tx, principal.subject)
            if outcome.status_code == 201:
                outcome = Outcome(tx, 200)
        await self.session.commit()
        return outcome

    async def reject(self, principal: Principal, transaction_id: uuid.UUID, reason: str) -> Outcome:
        tx = await self._pending_for_update(transaction_id)
        tx.reviewed_by = principal.subject
        self._reject(tx, principal.subject, reason)
        await self.session.commit()
        return Outcome(tx, 200)

    async def get_visible_transaction(
        self, transaction_id: uuid.UUID, principal: Principal
    ) -> Transaction:
        tx = await self.session.get(Transaction, transaction_id)
        parties = {tx.initiated_by, tx.source_owner_id, tx.destination_owner_id} if tx else set()
        if tx is None or (principal.subject not in parties and not principal.is_admin):
            raise NotFoundError("Transaction not found.")
        return tx

    async def visible_account(self, account_id: uuid.UUID, principal: Principal) -> AccountInfo:
        info = await self.accounts.get_account(account_id)
        if info is None or (info.owner_id != principal.subject and not principal.is_admin):
            raise NotFoundError("Account not found.")
        return info

    async def balance(self, account_id: uuid.UUID) -> Balance | None:
        return await self.session.get(Balance, account_id)

    async def entries(self, account_id: uuid.UUID, limit: int, offset: int) -> list[Entry]:
        rows = await self.session.scalars(
            select(Entry)
            .where(Entry.account_id == account_id)
            .order_by(Entry.created_at.desc(), Entry.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(rows)

    async def pending_reviews(self, limit: int) -> list[Transaction]:
        rows = await self.session.scalars(
            select(Transaction)
            .where(Transaction.status == TransactionStatus.PENDING_REVIEW)
            .order_by(Transaction.created_at)
            .limit(limit)
        )
        return list(rows)
