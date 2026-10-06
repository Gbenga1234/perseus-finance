"""Application factory applying the same hardened baseline to every service."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager

import httpx
from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from redis.asyncio import Redis
from sqlalchemy import text
from starlette.middleware.trustedhost import TrustedHostMiddleware

from perseus_common.config import ServiceSettings
from perseus_common.db import create_engine, create_sessionmaker
from perseus_common.errors import install_error_handlers
from perseus_common.events import EventSigner, RedisEventPublisher
from perseus_common.logging import configure_logging, get_logger
from perseus_common.middleware import (
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from perseus_common.security import JWKSKeyProvider, TokenVerifier

log = get_logger(__name__)

ServiceLifespan = Callable[[FastAPI], AbstractAsyncContextManager[None]]

operations_router = APIRouter(include_in_schema=False)


@operations_router.get("/health/live")
async def liveness() -> dict[str, str]:
    return {"status": "ok"}


@operations_router.get("/health/ready")
async def readiness(request: Request) -> JSONResponse:
    checks: dict[str, str] = {}
    state = request.app.state
    try:
        async with state.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # readiness must never raise
        log.warning("readiness_db_failed", error=type(exc).__name__)
        checks["database"] = "unavailable"
    redis: Redis | None = getattr(state, "redis", None)
    if redis is not None:
        try:
            await redis.ping()
            checks["redis"] = "ok"
        except Exception as exc:
            log.warning("readiness_redis_failed", error=type(exc).__name__)
            checks["redis"] = "unavailable"
    ready = all(v == "ok" for v in checks.values())
    return JSONResponse(
        {"status": "ok" if ready else "degraded", "checks": checks},
        status_code=200 if ready else 503,
    )


@operations_router.get("/metrics")
async def metrics() -> Response:
    # Only reachable on the internal network; the edge proxy never routes /metrics.
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def create_redis(settings: ServiceSettings) -> Redis:
    password = settings.redis_password.get_secret_value() if settings.redis_password else None
    return Redis.from_url(
        settings.redis_url,
        password=password,
        decode_responses=True,
        socket_timeout=10,
        socket_connect_timeout=5,
        health_check_interval=30,
    )


async def init_runtime(app: FastAPI, settings: ServiceSettings, stack: AsyncExitStack) -> None:
    """Create shared infrastructure clients and register their cleanup."""
    state = app.state
    state.engine = create_engine(settings)
    stack.push_async_callback(state.engine.dispose)
    state.sessionmaker = create_sessionmaker(state.engine)

    state.redis = create_redis(settings)
    stack.push_async_callback(state.redis.aclose)

    state.http = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.upstream_timeout_seconds, connect=2.0),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        follow_redirects=False,
    )
    stack.push_async_callback(state.http.aclose)

    state.token_verifier = TokenVerifier(
        JWKSKeyProvider(state.http, settings.jwks_url), settings.jwt_issuer
    )
    state.event_signer = EventSigner(settings.event_signing_key.get_secret_value())
    state.event_publisher = RedisEventPublisher(
        state.redis, settings.event_stream, state.event_signer
    )


def create_app(
    settings: ServiceSettings,
    *,
    title: str,
    description: str,
    routers: Sequence[APIRouter],
    version: str = "1.0.0",
    service_lifespan: ServiceLifespan | None = None,
) -> FastAPI:
    configure_logging(settings.service_name, settings.log_level, json_logs=settings.json_logs)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with AsyncExitStack() as stack:
            await init_runtime(app, settings, stack)
            if service_lifespan is not None:
                await stack.enter_async_context(service_lifespan(app))
            log.info("service_started", environment=settings.environment)
            yield
            log.info("service_stopping")

    app = FastAPI(
        title=title,
        description=description,
        version=version,
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    app.state.settings = settings
    install_error_handlers(app)

    # Starlette runs the last-added middleware first.
    if settings.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allowed_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
            max_age=600,
        )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    app.add_middleware(
        SecurityHeadersMiddleware,
        docs_enabled=settings.docs_enabled,
        hsts=settings.is_production_like,
    )
    app.add_middleware(RequestContextMiddleware, service_name=settings.service_name)

    app.include_router(operations_router)
    for router in routers:
        app.include_router(router)
    return app
