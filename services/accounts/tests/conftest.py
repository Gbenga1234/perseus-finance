import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from accounts_service.config import Settings
from accounts_service.main import build_app
from accounts_service.models import Base
from fastapi import FastAPI
from perseus_common.testing import TEST_ISSUER, TEST_SIGNING_KEY, TestKeys, init_test_state


class FakeLedger:
    def __init__(self) -> None:
        self.balances: dict[uuid.UUID, int] = {}

    async def balance_minor(self, account_id: uuid.UUID) -> int:
        return self.balances.get(account_id, 0)


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
        max_accounts_per_user=3,
    )


@pytest.fixture
def ledger() -> FakeLedger:
    return FakeLedger()


@pytest.fixture
async def app(settings: Settings, keys: TestKeys, ledger: FakeLedger) -> AsyncIterator[FastAPI]:
    app = build_app(settings)
    engine = await init_test_state(app, Base.metadata, keys)
    app.state.ledger = ledger
    yield app
    await engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def user_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def user_headers(keys: TestKeys, user_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {keys.mint(user_id)}"}


@pytest.fixture
def admin_headers(keys: TestKeys) -> dict[str, str]:
    return {"Authorization": f"Bearer {keys.mint(str(uuid.uuid4()), roles=['admin'])}"}
