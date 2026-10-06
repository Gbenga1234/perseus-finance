from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from perseus_common.db import DbSession
from perseus_common.errors import NotFoundError
from perseus_common.security import (
    CurrentUser,
    Principal,
    require_roles,
    require_service_scopes,
)

from accounts_service.models import Account
from accounts_service.schemas import (
    AccountOut,
    CreateAccountRequest,
    FreezeRequest,
    InternalAccountOut,
    UpdateAccountRequest,
)
from accounts_service.service import AccountService

router = APIRouter(prefix="/v1/accounts", tags=["accounts"])
internal_router = APIRouter(prefix="/internal/accounts", tags=["internal"])

Customer = Annotated[Principal, Depends(require_roles("customer", "admin"))]
Admin = Annotated[Principal, Depends(require_roles("admin"))]


def get_service(request: Request, session: DbSession) -> AccountService:
    return AccountService(session, request.app.state.settings, request.app.state.ledger)


Service = Annotated[AccountService, Depends(get_service)]


@router.post("", status_code=status.HTTP_201_CREATED, response_model=AccountOut)
async def open_account(body: CreateAccountRequest, user: Customer, service: Service) -> Account:
    return await service.open(user, body.currency, body.kind, body.nickname)


@router.get("", response_model=list[AccountOut])
async def list_accounts(user: CurrentUser, service: Service) -> list[Account]:
    return await service.list_for_owner(uuid.UUID(user.subject))


@router.get("/{account_id}", response_model=AccountOut)
async def get_account(account_id: uuid.UUID, user: CurrentUser, service: Service) -> Account:
    return await service.get_visible(account_id, user)


@router.patch("/{account_id}", response_model=AccountOut)
async def update_account(
    account_id: uuid.UUID, body: UpdateAccountRequest, user: Customer, service: Service
) -> Account:
    account = await service.get_visible(account_id, user)
    if str(account.owner_id) != user.subject:
        raise NotFoundError("Account not found.")
    return await service.rename(account, body.nickname)


@router.post("/{account_id}/close", response_model=AccountOut)
async def close_account(account_id: uuid.UUID, user: Customer, service: Service) -> Account:
    account = await service.get_visible(account_id, user)
    if str(account.owner_id) != user.subject:
        raise NotFoundError("Account not found.")
    return await service.close(account, user)


@router.post("/{account_id}/freeze", response_model=AccountOut)
async def freeze_account(
    account_id: uuid.UUID, body: FreezeRequest, admin: Admin, service: Service
) -> Account:
    account = await service.get_visible(account_id, admin)
    return await service.freeze(account, admin, body.reason)


@router.post("/{account_id}/unfreeze", response_model=AccountOut)
async def unfreeze_account(account_id: uuid.UUID, admin: Admin, service: Service) -> Account:
    account = await service.get_visible(account_id, admin)
    return await service.unfreeze(account, admin)


@internal_router.get(
    "/{account_id}",
    response_model=InternalAccountOut,
    dependencies=[Depends(require_service_scopes("accounts:read"))],
)
async def internal_get_account(account_id: uuid.UUID, session: DbSession) -> Account:
    account = await session.get(Account, account_id)
    if account is None:
        raise NotFoundError("Account not found.")
    return account
