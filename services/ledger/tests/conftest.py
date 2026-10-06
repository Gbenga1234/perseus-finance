import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from ledger_service.config import Settings
from ledger_service.gateways import AccountInfo, RiskAssessment
from ledger_service.main import build_app
from ledger_service.models import Base
from perseus_common.errors import UpstreamError
from perseus_common.testing import TEST_ISSUER, TEST_SIGNING_KEY, TestKeys, init_test_state


class FakeAccounts:
    def __init__(self) -> None:
        self.accounts: dict[uuid.UUID, AccountInfo] = {}

    def add(self, owner_id: str, currency: str = "USD", status: str = "active") -> uuid.UUID:
        account_id = uuid.uuid4()
        self.accounts[account_id] = AccountInfo(account_id, owner_id, currency, status)
        return account_id

    async def get_account(self, account_id: uuid.UUID) -> AccountInfo | None:
        return self.accounts.get(account_id)


class FakeFraud:
    def __init__(self) -> None:
        self.decision = "allow"
        self.available = True
        self.calls = 0

    async def assess(self, **kwargs) -> RiskAssessment:
        self.calls += 1
        if not self.available:
            raise UpstreamError("fraud down")
        score = {"allow": 5, "review": 60, "deny": 95}[self.decision]
        return RiskAssessment(uuid.uuid4(), self.decision, score)


@pytest.fixture(scope="session")
def keys() -> TestKeys:
    return TestKeys()


@pytest.fixture
def accounts() -> FakeAccounts:
    return FakeAccounts()


@pytest.fixture
def fraud() -> FakeFraud:
    return FakeFraud()


@pytest.fixture
async def app(keys, accounts, fraud) -> AsyncIterator[FastAPI]:
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
    app.state.accounts_gateway = accounts
    app.state.fraud_gateway = fraud
    yield app
    await engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class Actors:
    def __init__(self, keys: TestKeys) -> None:
        self.alice = str(uuid.uuid4())
        self.bob = str(uuid.uuid4())
        self.keys = keys

    def headers(self, subject: str, key: str | None = None, roles=("customer",)) -> dict:
        headers = {"Authorization": f"Bearer {self.keys.mint(subject, roles=roles)}"}
        if key:
            headers["Idempotency-Key"] = key
        return headers

    def admin(self, key: str | None = None) -> dict:
        return self.headers("admin-1", key, roles=("admin",))


@pytest.fixture
def actors(keys) -> Actors:
    return Actors(keys)
