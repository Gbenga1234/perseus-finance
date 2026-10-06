from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from perseus_common.app import create_app
from perseus_common.background import BackgroundWorkers
from perseus_common.events import EventConsumer, EventEnvelope

from audit_service.api import router
from audit_service.chain import AuditLog
from audit_service.config import Settings, get_settings


@asynccontextmanager
async def audit_lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    audit_log = AuditLog(app.state.sessionmaker)
    app.state.audit_log = audit_log
    workers = BackgroundWorkers()
    if settings.run_background_workers:

        async def handle(event: EventEnvelope) -> None:
            await audit_log.append(event)

        consumer = EventConsumer(
            app.state.redis,
            stream=settings.event_stream,
            group=settings.consumer_group,
            signer=app.state.event_signer,
            handler=handle,
        )
        workers.start("event-consumer", consumer.run)
    try:
        yield
    finally:
        await workers.stop()


def build_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    return create_app(
        settings,
        title="Perseus Audit Service",
        description="Tamper-evident audit trail.",
        routers=[router],
        service_lifespan=audit_lifespan,
    )
