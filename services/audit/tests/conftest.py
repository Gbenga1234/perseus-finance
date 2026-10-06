from collections.abc import AsyncIterator

import httpx
import pytest
from audit_service.chain import AuditLog
from audit_service.config import Settings
from audit_service.main import build_app
from audit_service.models import Base
from fastapi import FastAPI
from perseus_common.testing import TEST_ISSUER, TEST_SIGNING_KEY, TestKeys, init_test_state


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
    app.state.audit_log = AuditLog(app.state.sessionmaker)
    yield app
    await engine.dispose()


@pytest.fixture
def audit_log(app) -> AuditLog:
    return app.state.audit_log


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def auditor_headers(keys) -> dict[str, str]:
    return {"Authorization": f"Bearer {keys.mint('auditor-1', roles=['auditor'])}"}
