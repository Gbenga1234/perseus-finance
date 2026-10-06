import uuid

import pytest
from ledger_service.models import Balance, Entry, OutboxEvent
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError


def new_key() -> str:
    return uuid.uuid4().hex


async def deposit(client, actors, account_id, amount="100.00", currency="USD"):
    resp = await client.post(
        "/v1/ledger/deposits",
        headers=actors.admin(new_key()),
        json={
            "account_id": str(account_id),
            "amount": amount,
            "currency": currency,
            "reference": "wire-123",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def balance(client, actors, owner, account_id) -> int:
    resp = await client.get(
        f"/v1/ledger/accounts/{account_id}/balance", headers=actors.headers(owner)
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["balance_minor"]


def transfer_body(src, dst, amount="25.00", currency="USD"):
    return {
        "source_account_id": str(src),
        "destination_account_id": str(dst),
        "amount": amount,
        "currency": currency,
        "description": "rent",
    }


@pytest.fixture
def two_accounts(accounts, actors):
    return accounts.add(actors.alice), accounts.add(actors.bob)


async def test_deposit_requires_admin(client, actors, two_accounts):
    src, _ = two_accounts
    resp = await client.post(
        "/v1/ledger/deposits",
        headers=actors.headers(actors.alice, new_key()),
        json={"account_id": str(src), "amount": "5.00", "currency": "USD", "reference": "x"},
    )
    assert resp.status_code == 403


async def test_successful_transfer_posts_balanced_entries(client, actors, two_accounts, app):
    src, dst = two_accounts
    await deposit(client, actors, src)
    resp = await client.post(
        "/v1/ledger/transfers",
        headers=actors.headers(actors.alice, new_key()),
        json=transfer_body(src, dst),
    )
    assert resp.status_code == 201, resp.text
    tx = resp.json()
    assert tx["status"] == "completed" and tx["amount"] == "25.00"
    assert "risk_score" not in tx  # risk signals are never exposed to customers

    assert await balance(client, actors, actors.alice, src) == 7500
    assert await balance(client, actors, actors.bob, dst) == 2500

    async with app.state.sessionmaker() as session:
        total = await session.scalar(
            select(func.sum(Entry.amount_minor)).where(Entry.transaction_id == uuid.UUID(tx["id"]))
        )
        assert total == 0
        types = (await session.scalars(select(OutboxEvent.event_type))).all()
    assert sorted(types) == ["deposit.completed", "transfer.completed"]

    # Recipient can view the transaction; a stranger cannot.
    url = f"/v1/ledger/transfers/{tx['id']}"
    assert (await client.get(url, headers=actors.headers(actors.bob))).status_code == 200
    stranger = actors.headers(str(uuid.uuid4()))
    assert (await client.get(url, headers=stranger)).status_code == 404


async def test_insufficient_funds_is_recorded_and_balance_unchanged(
    client, actors, two_accounts, app
):
    src, dst = two_accounts
    await deposit(client, actors, src, "10.00")
    resp = await client.post(
        "/v1/ledger/transfers",
        headers=actors.headers(actors.alice, new_key()),
        json=transfer_body(src, dst, "10.01"),
    )
    assert resp.status_code == 422
    assert resp.json()["code"] == "insufficient_funds"
    assert resp.json()["transaction"]["status"] == "rejected"
    assert await balance(client, actors, actors.alice, src) == 1000


async def test_idempotent_retry_returns_original_response(client, actors, two_accounts, app):
    src, dst = two_accounts
    await deposit(client, actors, src)
    key = new_key()
    first = await client.post(
        "/v1/ledger/transfers",
        headers=actors.headers(actors.alice, key),
        json=transfer_body(src, dst),
    )
    retry = await client.post(
        "/v1/ledger/transfers",
        headers=actors.headers(actors.alice, key),
        json=transfer_body(src, dst),
    )
    assert retry.status_code == first.status_code == 201
    assert retry.json() == first.json()
    assert retry.headers["idempotent-replayed"] == "true"
    assert await balance(client, actors, actors.alice, src) == 7500

    reused = await client.post(
        "/v1/ledger/transfers",
        headers=actors.headers(actors.alice, key),
        json=transfer_body(src, dst, "1.00"),
    )
    assert reused.status_code == 422
    assert reused.json()["code"] == "idempotency_key_reused"


async def test_idempotency_key_is_required(client, actors, two_accounts):
    src, dst = two_accounts
    resp = await client.post(
        "/v1/ledger/transfers", headers=actors.headers(actors.alice), json=transfer_body(src, dst)
    )
    assert resp.status_code == 422


async def test_cannot_spend_from_someone_elses_account(client, actors, two_accounts):
    src, dst = two_accounts
    await deposit(client, actors, src)
    resp = await client.post(
        "/v1/ledger/transfers",
        headers=actors.headers(actors.bob, new_key()),
        json=transfer_body(src, dst),
    )
    assert resp.status_code == 404


@pytest.mark.parametrize(
    ("amount", "expected"),
    [(25, 422), ("10.001", 422), ("-5.00", 422), ("0.00", 422), ("1e3", 422)],
)
async def test_amount_validation(client, actors, two_accounts, amount, expected):
    src, dst = two_accounts
    await deposit(client, actors, src)
    body = transfer_body(src, dst)
    body["amount"] = amount
    resp = await client.post(
        "/v1/ledger/transfers", headers=actors.headers(actors.alice, new_key()), json=body
    )
    assert resp.status_code == expected


async def test_frozen_destination_and_currency_mismatch(client, actors, accounts):
    src = accounts.add(actors.alice)
    frozen = accounts.add(actors.bob, status="frozen")
    euro = accounts.add(actors.bob, currency="EUR")
    await deposit(client, actors, src)
    resp = await client.post(
        "/v1/ledger/transfers",
        headers=actors.headers(actors.alice, new_key()),
        json=transfer_body(src, frozen),
    )
    assert resp.status_code == 409
    resp = await client.post(
        "/v1/ledger/transfers",
        headers=actors.headers(actors.alice, new_key()),
        json=transfer_body(src, euro),
    )
    assert resp.status_code == 422
    assert resp.json()["code"] == "currency_mismatch"


async def test_risk_deny_and_review_then_approve(client, actors, two_accounts, fraud):
    src, dst = two_accounts
    await deposit(client, actors, src)

    fraud.decision = "deny"
    denied = await client.post(
        "/v1/ledger/transfers",
        headers=actors.headers(actors.alice, new_key()),
        json=transfer_body(src, dst),
    )
    assert denied.status_code == 422 and denied.json()["code"] == "transfer_declined"

    fraud.decision = "review"
    held = await client.post(
        "/v1/ledger/transfers",
        headers=actors.headers(actors.alice, new_key()),
        json=transfer_body(src, dst),
    )
    assert held.status_code == 202 and held.json()["status"] == "pending_review"
    assert await balance(client, actors, actors.alice, src) == 10000

    tx_id = held.json()["id"]
    by_customer = await client.post(
        f"/v1/ledger/transfers/{tx_id}/approve", headers=actors.headers(actors.alice)
    )
    assert by_customer.status_code == 403
    approved = await client.post(f"/v1/ledger/transfers/{tx_id}/approve", headers=actors.admin())
    assert approved.status_code == 200 and approved.json()["status"] == "completed"
    again = await client.post(f"/v1/ledger/transfers/{tx_id}/approve", headers=actors.admin())
    assert again.status_code == 409
    assert await balance(client, actors, actors.alice, src) == 7500


async def test_fraud_outage_fails_closed_and_releases_key(client, actors, two_accounts, fraud):
    src, dst = two_accounts
    await deposit(client, actors, src)
    key = new_key()
    fraud.available = False
    resp = await client.post(
        "/v1/ledger/transfers",
        headers=actors.headers(actors.alice, key),
        json=transfer_body(src, dst),
    )
    assert resp.status_code == 503
    assert await balance(client, actors, actors.alice, src) == 10000

    fraud.available = True
    retry = await client.post(
        "/v1/ledger/transfers",
        headers=actors.headers(actors.alice, key),
        json=transfer_body(src, dst),
    )
    assert retry.status_code == 201


async def test_balance_is_private(client, actors, two_accounts):
    src, _ = two_accounts
    resp = await client.get(
        f"/v1/ledger/accounts/{src}/balance", headers=actors.headers(actors.bob)
    )
    assert resp.status_code == 404


async def test_database_rejects_negative_balance(app):
    async with app.state.sessionmaker() as session:
        session.add(
            Balance(
                account_id=uuid.uuid4(),
                currency="USD",
                balance_minor=-1,
                allow_negative=False,
                version=0,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


async def test_internal_balance_requires_scope(client, keys, two_accounts, actors):
    src, _ = two_accounts
    await deposit(client, actors, src)
    url = f"/internal/balances/{src}"
    wrong = {"Authorization": f"Bearer {keys.service_token('fraud-service', ['fraud:assess'])}"}
    assert (await client.get(url, headers=wrong)).status_code == 403
    ok = {
        "Authorization": f"Bearer {keys.service_token('accounts-service', ['ledger:balance:read'])}"
    }
    resp = await client.get(url, headers=ok)
    assert resp.status_code == 200 and resp.json()["balance_minor"] == 10000
