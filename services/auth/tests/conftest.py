import hashlib
import json
from collections.abc import AsyncIterator

import httpx
import pytest
from auth_service.config import Settings
from auth_service.main import build_app, configure_auth_state
from auth_service.models import Base
from cryptography.fernet import Fernet
from fastapi import FastAPI
from perseus_common.testing import TEST_ISSUER, TEST_SIGNING_KEY, TestKeys, init_test_state

CLIENT_SECRET = "ledger-client-secret-value-0123456789"
PASSWORD = "Correct-Horse-Battery-9"


@pytest.fixture(scope="session")
def keys() -> TestKeys:
    return TestKeys()


@pytest.fixture
def settings(keys: TestKeys) -> Settings:
    clients = {
        "ledger-service": {
            "secret_sha256": hashlib.sha256(CLIENT_SECRET.encode()).hexdigest(),
            "scopes": ["accounts:read", "fraud:assess"],
        }
    }
    return Settings(
        environment="test",
        jwt_issuer=TEST_ISSUER,
        jwt_private_key=keys.private_pem,
        mfa_encryption_key=Fernet.generate_key().decode(),
        event_signing_key=TEST_SIGNING_KEY,
        service_clients=json.dumps(clients),
        allowed_hosts=["test"],
        run_background_workers=False,
        json_logs=False,
    )


@pytest.fixture
async def app(settings: Settings, keys: TestKeys) -> AsyncIterator[FastAPI]:
    app = build_app(settings)
    engine = await init_test_state(app, Base.metadata, keys)
    configure_auth_state(app, settings)
    yield app
    await engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class AuthHelper:
    password = PASSWORD
    client_secret = CLIENT_SECRET

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

    async def register(self, email: str, password: str = PASSWORD) -> dict:
        resp = await self.client.post(
            "/v1/auth/register", json={"email": email, "password": password, "full_name": "Ada L"}
        )
        assert resp.status_code == 202, resp.text
        return resp.json()

    async def login(self, email: str, password: str = PASSWORD) -> dict:
        resp = await self.client.post("/v1/auth/login", json={"email": email, "password": password})
        assert resp.status_code == 200, resp.text
        return resp.json()


@pytest.fixture
def auth(client: httpx.AsyncClient) -> AuthHelper:
    return AuthHelper(client)
