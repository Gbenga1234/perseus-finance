from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from notifications_service.config import Settings
from notifications_service.handler import NotificationHandler
from notifications_service.main import build_app
from notifications_service.models import Base
from perseus_common.testing import TEST_ISSUER, TEST_SIGNING_KEY, TestKeys, init_test_state


class FakeSender:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str, str]] = []
        self.fail = False

    async def send(self, to: str, subject: str, body: str) -> None:
        if self.fail:
            raise ConnectionError("smtp down")
        self.sent.append((to, subject, body))


@pytest.fixture(scope="session")
def keys() -> TestKeys:
    return TestKeys()


@pytest.fixture
async def app(keys) -> AsyncIterator[FastAPI]:
    settings = Settings(
        environment="test",
        jwt_issuer=TEST_ISSUER,
        event_signing_key=TEST_SIGNING_KEY,
        allowed_hosts=["test"],
        run_background_workers=False,
        json_logs=False,
    )
    app = build_app(settings)
    engine = await init_test_state(app, Base.metadata, keys)
    yield app
    await engine.dispose()


@pytest.fixture
def sender() -> FakeSender:
    return FakeSender()


@pytest.fixture
def handler(app, sender) -> NotificationHandler:
    return NotificationHandler(app.state.sessionmaker, sender)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
