from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from perseus_common.app import create_app
from perseus_common.background import BackgroundWorkers
from perseus_common.http_client import ServiceClient, build_token_provider
from perseus_common.outbox import OutboxRelay

from accounts_service.api import internal_router, router
from accounts_service.config import Settings, get_settings
from accounts_service.ledger import HttpLedgerGateway
from accounts_service.models import OutboxEvent


@asynccontextmanager
async def accounts_lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    tokens = build_token_provider(app.state.http, settings)
    app.state.ledger = HttpLedgerGateway(
        ServiceClient(app.state.http, settings.ledger_base_url, tokens)
    )
    workers = BackgroundWorkers()
    if settings.run_background_workers:
        relay = OutboxRelay(app.state.sessionmaker, OutboxEvent, app.state.event_publisher)
        workers.start("outbox-relay", relay.run)
    try:
        yield
    finally:
        await workers.stop()


def build_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    return create_app(
        settings,
        title="Perseus Accounts Service",
        description="Customer account lifecycle.",
        routers=[router, internal_router],
        service_lifespan=accounts_lifespan,
    )
