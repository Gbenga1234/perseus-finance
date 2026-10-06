"""Clients for the accounts and fraud services."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Literal, Protocol

from perseus_common.errors import UpstreamError
from perseus_common.http_client import ServiceClient

Decision = Literal["allow", "review", "deny"]


@dataclass(frozen=True)
class AccountInfo:
    id: uuid.UUID
    owner_id: str
    currency: str
    status: str


@dataclass(frozen=True)
class RiskAssessment:
    assessment_id: uuid.UUID
    decision: Decision
    score: int


class AccountsGateway(Protocol):
    async def get_account(self, account_id: uuid.UUID) -> AccountInfo | None: ...


class FraudGateway(Protocol):
    async def assess(
        self,
        *,
        transaction_id: uuid.UUID,
        user_id: str,
        source_account_id: uuid.UUID,
        destination_account_id: uuid.UUID,
        amount_minor: int,
        currency: str,
    ) -> RiskAssessment: ...


class HttpAccountsGateway:
    def __init__(self, client: ServiceClient) -> None:
        self._client = client

    async def get_account(self, account_id: uuid.UUID) -> AccountInfo | None:
        data = await self._client.get(f"/internal/accounts/{account_id}")
        if data is None:
            return None
        return AccountInfo(
            id=uuid.UUID(str(data["id"])),
            owner_id=str(data["owner_id"]),
            currency=str(data["currency"]),
            status=str(data["status"]),
        )


class HttpFraudGateway:
    def __init__(self, client: ServiceClient) -> None:
        self._client = client

    async def assess(
        self,
        *,
        transaction_id: uuid.UUID,
        user_id: str,
        source_account_id: uuid.UUID,
        destination_account_id: uuid.UUID,
        amount_minor: int,
        currency: str,
    ) -> RiskAssessment:
        data = await self._client.post(
            "/internal/assessments",
            json={
                "transaction_id": str(transaction_id),
                "user_id": user_id,
                "source_account_id": str(source_account_id),
                "destination_account_id": str(destination_account_id),
                "amount_minor": amount_minor,
                "currency": currency,
            },
        )
        decision = data.get("decision")
        # Fail closed: anything unexpected from the risk engine blocks the transfer.
        if decision not in ("allow", "review", "deny"):
            raise UpstreamError("Risk assessment unavailable")
        return RiskAssessment(
            assessment_id=uuid.UUID(str(data["assessment_id"])),
            decision=decision,
            score=int(data["score"]),
        )
