from __future__ import annotations

import uuid
from typing import Protocol

from perseus_common.http_client import ServiceClient


class LedgerGateway(Protocol):
    async def balance_minor(self, account_id: uuid.UUID) -> int: ...


class HttpLedgerGateway:
    def __init__(self, client: ServiceClient) -> None:
        self._client = client

    async def balance_minor(self, account_id: uuid.UUID) -> int:
        data = await self._client.get(f"/internal/balances/{account_id}")
        return int(data["balance_minor"]) if data else 0
