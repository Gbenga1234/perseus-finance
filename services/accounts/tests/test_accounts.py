import uuid

from accounts_service.service import generate_account_number, luhn_check_digit


async def open_account(client, headers, currency="USD"):
    resp = await client.post("/v1/accounts", headers=headers, json={"currency": currency})
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_account_numbers_carry_valid_luhn_digit():
    for _ in range(50):
        number = generate_account_number()
        assert len(number) == 10
        assert luhn_check_digit(number[:-1]) == number[-1]


async def test_open_list_and_get(client, user_headers, user_id):
    account = await open_account(client, user_headers)
    assert account["owner_id"] == user_id and account["status"] == "active"

    listed = await client.get("/v1/accounts", headers=user_headers)
    assert [a["id"] for a in listed.json()] == [account["id"]]

    fetched = await client.get(f"/v1/accounts/{account['id']}", headers=user_headers)
    assert fetched.status_code == 200


async def test_requires_authentication(client):
    assert (await client.get("/v1/accounts")).status_code == 401


async def test_other_users_cannot_see_account(client, user_headers, keys):
    account = await open_account(client, user_headers)
    intruder = {"Authorization": f"Bearer {keys.mint(str(uuid.uuid4()))}"}
    resp = await client.get(f"/v1/accounts/{account['id']}", headers=intruder)
    assert resp.status_code == 404
    resp = await client.post(f"/v1/accounts/{account['id']}/close", headers=intruder)
    assert resp.status_code == 404


async def test_rejects_unsupported_currency_and_extra_fields(client, user_headers):
    resp = await client.post("/v1/accounts", headers=user_headers, json={"currency": "XXX"})
    assert resp.status_code == 422
    resp = await client.post(
        "/v1/accounts", headers=user_headers, json={"currency": "USD", "status": "frozen"}
    )
    assert resp.status_code == 422


async def test_account_limit(client, user_headers, settings):
    for _ in range(settings.max_accounts_per_user):
        await open_account(client, user_headers)
    resp = await client.post("/v1/accounts", headers=user_headers, json={"currency": "USD"})
    assert resp.status_code == 422
    assert resp.json()["code"] == "account_limit"


async def test_freeze_is_admin_only(client, user_headers, admin_headers, app):
    account = await open_account(client, user_headers)
    url = f"/v1/accounts/{account['id']}/freeze"
    denied = await client.post(url, headers=user_headers, json={"reason": "suspicious"})
    assert denied.status_code == 403

    frozen = await client.post(url, headers=admin_headers, json={"reason": "suspicious"})
    assert frozen.status_code == 200 and frozen.json()["status"] == "frozen"

    events = [e.type for e in await _published(app)]
    assert events == ["account.opened", "account.frozen"]


async def test_close_requires_zero_balance(client, user_headers, ledger):
    account = await open_account(client, user_headers)
    ledger.balances[uuid.UUID(account["id"])] = 500
    resp = await client.post(f"/v1/accounts/{account['id']}/close", headers=user_headers)
    assert resp.status_code == 409
    assert resp.json()["code"] == "balance_not_zero"

    ledger.balances[uuid.UUID(account["id"])] = 0
    resp = await client.post(f"/v1/accounts/{account['id']}/close", headers=user_headers)
    assert resp.status_code == 200 and resp.json()["status"] == "closed"


async def test_internal_endpoint_requires_service_token_with_scope(client, user_headers, keys):
    account = await open_account(client, user_headers)
    url = f"/internal/accounts/{account['id']}"

    assert (await client.get(url, headers=user_headers)).status_code == 401

    no_scope = {"Authorization": f"Bearer {keys.service_token('fraud-service', [])}"}
    assert (await client.get(url, headers=no_scope)).status_code == 403

    ok = {"Authorization": f"Bearer {keys.service_token('ledger-service', ['accounts:read'])}"}
    resp = await client.get(url, headers=ok)
    assert resp.status_code == 200
    assert resp.json()["currency"] == "USD"


async def _published(app):
    from accounts_service.models import OutboxEvent
    from perseus_common.outbox import OutboxRelay

    relay = OutboxRelay(app.state.sessionmaker, OutboxEvent, app.state.event_publisher)
    await relay.run_once()
    return app.state.event_publisher.events
