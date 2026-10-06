from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import JSONResponse
from perseus_common.db import DbSession
from perseus_common.errors import PROBLEM_JSON, NotFoundError, problem_body
from perseus_common.money import format_minor_units
from perseus_common.security import CurrentUser, Principal, require_roles, require_service_scopes
from sqlalchemy.ext.asyncio import AsyncSession

from ledger_service.idempotency import execute_idempotent, fingerprint
from ledger_service.models import Balance
from ledger_service.schemas import (
    BalanceOut,
    DepositRequest,
    EntryOut,
    InternalBalanceOut,
    RejectRequest,
    TransactionOut,
    TransferRequest,
)
from ledger_service.service import LedgerService, Outcome

router = APIRouter(prefix="/v1/ledger", tags=["ledger"])
internal_router = APIRouter(prefix="/internal", tags=["internal"])

Customer = Annotated[Principal, Depends(require_roles("customer"))]
Admin = Annotated[Principal, Depends(require_roles("admin"))]
IdempotencyKey = Annotated[
    str,
    Header(alias="Idempotency-Key", min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_\-]+$"),
]


def build_service(request: Request, session: AsyncSession) -> LedgerService:
    state = request.app.state
    return LedgerService(session, state.settings, state.accounts_gateway, state.fraud_gateway)


def get_service(request: Request, session: DbSession) -> LedgerService:
    return build_service(request, session)


Service = Annotated[LedgerService, Depends(get_service)]


def outcome_body(request: Request, outcome: Outcome) -> tuple[int, dict[str, Any]]:
    tx_body = TransactionOut.from_model(outcome.transaction).model_dump(mode="json")
    if outcome.status_code < 400:
        return outcome.status_code, tx_body
    title = "Transfer Declined" if outcome.status_code == 422 else "Conflict"
    return outcome.status_code, problem_body(
        request,
        outcome.status_code,
        title,
        outcome.detail or title,
        outcome.error_code or "rejected",
        {"transaction": tx_body},
    )


async def _idempotent(
    request: Request, principal: Principal, key: str, payload: dict[str, Any], op: Any
) -> JSONResponse:
    state = request.app.state
    return await execute_idempotent(
        state.sessionmaker,
        principal_id=principal.subject,
        key=key,
        request_hash=fingerprint(request.url.path, payload),
        stale_after_seconds=state.settings.idempotency_stale_seconds,
        operation=op,
    )


@router.post(
    "/transfers",
    status_code=201,
    response_model=TransactionOut,
    responses={202: {"description": "Held for review"}, 422: {"description": "Declined"}},
)
async def create_transfer(
    request: Request, body: TransferRequest, user: Customer, key: IdempotencyKey
) -> JSONResponse:
    async def op(session: AsyncSession) -> tuple[int, dict[str, Any]]:
        outcome = await build_service(request, session).transfer(user, body)
        return outcome_body(request, outcome)

    return await _idempotent(request, user, key, body.model_dump(mode="json"), op)


@router.post("/deposits", status_code=201, response_model=TransactionOut)
async def create_deposit(
    request: Request, body: DepositRequest, admin: Admin, key: IdempotencyKey
) -> JSONResponse:
    async def op(session: AsyncSession) -> tuple[int, dict[str, Any]]:
        outcome = await build_service(request, session).deposit(admin, body)
        return outcome_body(request, outcome)

    return await _idempotent(request, admin, key, body.model_dump(mode="json"), op)


@router.get("/transfers/pending-review", response_model=list[TransactionOut])
async def pending_reviews(
    _admin: Admin, service: Service, limit: Annotated[int, Query(ge=1, le=100)] = 50
) -> list[TransactionOut]:
    return [TransactionOut.from_model(tx) for tx in await service.pending_reviews(limit)]


@router.get("/transfers/{transaction_id}", response_model=TransactionOut)
async def get_transaction(
    transaction_id: uuid.UUID, user: CurrentUser, service: Service
) -> TransactionOut:
    return TransactionOut.from_model(await service.get_visible_transaction(transaction_id, user))


@router.post("/transfers/{transaction_id}/approve", response_model=TransactionOut)
async def approve_transfer(
    request: Request, transaction_id: uuid.UUID, admin: Admin, service: Service
) -> JSONResponse:
    status_code, body = outcome_body(request, await service.approve(admin, transaction_id))
    media_type = PROBLEM_JSON if status_code >= 400 else "application/json"
    return JSONResponse(body, status_code=status_code, media_type=media_type)


@router.post("/transfers/{transaction_id}/reject", response_model=TransactionOut)
async def reject_transfer(
    transaction_id: uuid.UUID, body: RejectRequest, admin: Admin, service: Service
) -> TransactionOut:
    outcome = await service.reject(admin, transaction_id, body.reason)
    return TransactionOut.from_model(outcome.transaction)


@router.get("/accounts/{account_id}/balance", response_model=BalanceOut)
async def get_balance(account_id: uuid.UUID, user: CurrentUser, service: Service) -> BalanceOut:
    info = await service.visible_account(account_id, user)
    balance = await service.balance(account_id)
    minor = balance.balance_minor if balance else 0
    return BalanceOut(
        account_id=account_id,
        currency=info.currency,
        balance=format_minor_units(minor, info.currency),
        balance_minor=minor,
    )


@router.get("/accounts/{account_id}/entries", response_model=list[EntryOut])
async def list_entries(
    account_id: uuid.UUID,
    user: CurrentUser,
    service: Service,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> list[EntryOut]:
    await service.visible_account(account_id, user)
    return [EntryOut.from_model(e) for e in await service.entries(account_id, limit, offset)]


@internal_router.get(
    "/balances/{account_id}",
    response_model=InternalBalanceOut,
    dependencies=[Depends(require_service_scopes("ledger:balance:read"))],
)
async def internal_balance(account_id: uuid.UUID, session: DbSession) -> Balance:
    balance = await session.get(Balance, account_id)
    if balance is None:
        raise NotFoundError("No ledger balance for account.")
    return balance
