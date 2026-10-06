from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from perseus_common.app import create_app
from perseus_common.background import BackgroundWorkers
from perseus_common.outbox import OutboxRelay

from fraud_service.api import internal_router, router
from fraud_service.config import Settings, get_settings
from fraud_service.models import OutboxEvent
from fraud_service.signals import RedisSignalStore


@asynccontextmanager
async def fraud_lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    app.state.signals = RedisSignalStore(app.state.redis)
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
        title="Perseus Fraud Service",
        description="Real-time transaction risk scoring.",
        routers=[internal_router, router],
        service_lifespan=fraud_lifespan,
    )
