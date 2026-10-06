from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from perseus_common.app import create_app
from perseus_common.background import BackgroundWorkers
from perseus_common.config import normalize_pem
from perseus_common.outbox import OutboxRelay
from perseus_common.security import StaticKeyProvider, TokenVerifier

from auth_service.api import jwks_router, oauth_router, router
from auth_service.config import Settings, get_settings
from auth_service.crypto import FieldCipher, ServiceClientRegistry, SigningKey, TokenIssuer
from auth_service.models import OutboxEvent


def configure_auth_state(app: FastAPI, settings: Settings) -> None:
    key = SigningKey(normalize_pem(settings.jwt_private_key.get_secret_value()))
    app.state.signing_key = key
    app.state.token_issuer = TokenIssuer(key, settings)
    # The issuer verifies its own tokens locally instead of via JWKS over HTTP.
    app.state.token_verifier = TokenVerifier(
        StaticKeyProvider({key.kid: key.public_key}), settings.jwt_issuer
    )
    app.state.field_cipher = FieldCipher(settings.mfa_encryption_key.get_secret_value())
    app.state.service_clients = ServiceClientRegistry(settings.service_clients.get_secret_value())


@asynccontextmanager
async def auth_lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    configure_auth_state(app, settings)
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
        title="Perseus Auth Service",
        description="Identity, authentication and token issuance.",
        routers=[router, oauth_router, jwks_router],
        service_lifespan=auth_lifespan,
    )
