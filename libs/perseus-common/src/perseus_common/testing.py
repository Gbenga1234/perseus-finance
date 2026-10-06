"""Helpers shared by the services' test suites (never imported by production code)."""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from sqlalchemy import MetaData, event
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import StaticPool

from perseus_common.db import create_sessionmaker
from perseus_common.events import EventEnvelope, EventSigner
from perseus_common.security import StaticKeyProvider, TokenVerifier

TEST_ISSUER = "https://auth.perseus.test"
TEST_SIGNING_KEY = "test-event-signing-key-0123456789abcdef"


@dataclass
class TestKeys:
    __test__ = False  # not a pytest test class
    kid: str = "test-key"
    private_key: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )

    @property
    def private_pem(self) -> str:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    def verifier(self, issuer: str = TEST_ISSUER) -> TokenVerifier:
        return TokenVerifier(StaticKeyProvider({self.kid: self.private_key.public_key()}), issuer)

    def mint(
        self,
        subject: str,
        *,
        roles: Iterable[str] = ("customer",),
        scopes: Iterable[str] = (),
        audience: str = "perseus-api",
        typ: str = "access",
        issuer: str = TEST_ISSUER,
        ttl: int = 300,
    ) -> str:
        now = int(time.time())
        claims = {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
            "jti": uuid.uuid4().hex,
            "typ": typ,
            "roles": list(roles),
            "scope": " ".join(scopes),
        }
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": self.kid})

    def service_token(self, client_id: str, scopes: Iterable[str]) -> str:
        return self.mint(
            client_id, roles=(), scopes=scopes, audience="perseus-internal", typ="service"
        )


class RecordingPublisher:
    def __init__(self) -> None:
        self.bodies: list[str] = []

    async def publish_raw(self, body: str) -> None:
        self.bodies.append(body)

    @property
    def events(self) -> list[EventEnvelope]:
        return [EventEnvelope.model_validate_json(b) for b in self.bodies]


async def init_test_state(app: FastAPI, metadata: MetaData, keys: TestKeys) -> AsyncEngine:
    """Wire an app's state for in-process tests (SQLite, static keys, no Redis)."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)

    @event.listens_for(engine.sync_engine, "connect")
    def _enforce_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
        # SQLite ignores foreign keys unless asked; PostgreSQL always enforces them.
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    app.state.engine = engine
    app.state.sessionmaker = create_sessionmaker(engine)
    app.state.token_verifier = keys.verifier()
    app.state.event_signer = EventSigner(TEST_SIGNING_KEY)
    app.state.event_publisher = RecordingPublisher()
    app.state.redis = None
    return engine
