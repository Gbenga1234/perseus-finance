from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from fraud_service.config import Settings
from fraud_service.main import build_app
from fraud_service.models import Base
from fraud_service.signals import InMemorySignalStore
from perseus_common.testing import TEST_ISSUER, TEST_SIGNING_KEY, TestKeys, init_test_state


@pytest.fixture(scope="session")
def keys() -> TestKeys:
    return TestKeys()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        environment="test",
        jwt_issuer=TEST_ISSUER,
        event_signing_key=TEST_SIGNING_KEY,
        allowed_hosts=["test"],
        run_background_workers=False,
        json_logs=False,
    )


@pytest.fixture
async def app(settings, keys) -> AsyncIterator[FastAPI]:
    app = build_app(settings)
    engine = await init_test_state(app, Base.metadata, keys)
    app.state.signals = InMemorySignalStore()
    yield app
    await engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def service_headers(keys) -> dict[str, str]:
    return {"Authorization": f"Bearer {keys.service_token('ledger-service', ['fraud:assess'])}"}
