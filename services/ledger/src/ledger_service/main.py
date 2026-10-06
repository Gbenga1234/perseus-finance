from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from perseus_common.app import create_app
from perseus_common.background import BackgroundWorkers
from perseus_common.http_client import ServiceClient, build_token_provider
from perseus_common.outbox import OutboxRelay

from ledger_service.api import internal_router, router
from ledger_service.config import Settings, get_settings
from ledger_service.gateways import HttpAccountsGateway, HttpFraudGateway
from ledger_service.models import OutboxEvent


@asynccontextmanager
async def ledger_lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    tokens = build_token_provider(app.state.http, settings)
    app.state.accounts_gateway = HttpAccountsGateway(
        ServiceClient(app.state.http, settings.accounts_base_url, tokens)
    )
    app.state.fraud_gateway = HttpFraudGateway(
        ServiceClient(app.state.http, settings.fraud_base_url, tokens)
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
        title="Perseus Ledger Service",
        description="Double-entry ledger, transfers and deposits.",
        routers=[router, internal_router],
        service_lifespan=ledger_lifespan,
    )
