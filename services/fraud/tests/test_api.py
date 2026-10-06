import uuid


def body(amount=5_000, user="user-1", dest=None):
    return {
        "transaction_id": str(uuid.uuid4()),
        "user_id": user,
        "source_account_id": str(uuid.uuid4()),
        "destination_account_id": dest or str(uuid.uuid4()),
        "amount_minor": amount,
        "currency": "USD",
    }


async def test_assessment_requires_service_scope(client, keys):
    user = {"Authorization": f"Bearer {keys.mint('user-1')}"}
    assert (
        await client.post("/internal/assessments", json=body(), headers=user)
    ).status_code == 401
    wrong = {"Authorization": f"Bearer {keys.service_token('accounts-service', ['accounts:read'])}"}
    assert (
        await client.post("/internal/assessments", json=body(), headers=wrong)
    ).status_code == 403


async def test_known_payee_lowers_risk_and_velocity_escalates(client, service_headers, settings):
    dest = str(uuid.uuid4())
    first = await client.post(
        "/internal/assessments", json=body(dest=dest), headers=service_headers
    )
    assert first.json()["rules"] == ["new_payee"]
    second = await client.post(
        "/internal/assessments", json=body(dest=dest), headers=service_headers
    )
    assert second.json()["rules"] == [] and second.json()["decision"] == "allow"

    for _ in range(settings.velocity_max_transfers):
        resp = await client.post(
            "/internal/assessments", json=body(dest=dest), headers=service_headers
        )
    assert "velocity" in resp.json()["rules"]


async def test_flagged_assessment_emits_event_and_is_listed(client, service_headers, keys, app):
    resp = await client.post(
        "/internal/assessments", json=body(amount=10**12), headers=service_headers
    )
    assert resp.json()["decision"] == "deny"

    from fraud_service.models import OutboxEvent
    from sqlalchemy import select

    async with app.state.sessionmaker() as session:
        assert (await session.scalars(select(OutboxEvent.event_type))).all() == ["fraud.flagged"]

    customer = {"Authorization": f"Bearer {keys.mint('user-1')}"}
    assert (await client.get("/v1/fraud/assessments", headers=customer)).status_code == 403
    admin = {"Authorization": f"Bearer {keys.mint('admin', roles=['admin'])}"}
    listed = await client.get("/v1/fraud/assessments?decision=deny", headers=admin)
    assert listed.status_code == 200 and len(listed.json()) == 1
