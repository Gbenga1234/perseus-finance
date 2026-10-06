from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from perseus_common.app import create_app
from perseus_common.background import BackgroundWorkers
from perseus_common.events import EventConsumer

from notifications_service.api import router
from notifications_service.config import Settings, get_settings
from notifications_service.handler import NotificationHandler
from notifications_service.sender import SmtpEmailSender


@asynccontextmanager
async def notifications_lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    workers = BackgroundWorkers()
    if settings.run_background_workers:
        handler = NotificationHandler(app.state.sessionmaker, SmtpEmailSender(settings))
        consumer = EventConsumer(
            app.state.redis,
            stream=settings.event_stream,
            group=settings.consumer_group,
            signer=app.state.event_signer,
            handler=handler,
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
        title="Perseus Notifications Service",
        description="Event-driven customer notifications.",
        routers=[router],
        service_lifespan=notifications_lifespan,
    )
