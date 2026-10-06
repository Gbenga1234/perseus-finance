import json

from audit_service.models import AuditRecord
from perseus_common.events import EventEnvelope
from sqlalchemy import select, update


def event(i: int) -> EventEnvelope:
    return EventEnvelope(
        type="transfer.completed",
        producer="ledger-service",
        actor_id="user-1",
        subject_id=f"tx-{i}",
        data={"amount_minor": i},
    )


async def test_chain_is_valid_and_deduplicated(audit_log):
    events = [event(i) for i in range(5)]
    for e in events:
        assert await audit_log.append(e) is True
    assert await audit_log.append(events[0]) is False  # redelivery

    result = await audit_log.verify(batch_size=2)
    assert result.valid and result.records_checked == 5


async def test_tampering_is_detected(audit_log, app):
    for i in range(4):
        await audit_log.append(event(i))
    async with app.state.sessionmaker() as session:
        record = await session.scalar(select(AuditRecord).where(AuditRecord.seq == 2))
        doc = json.loads(record.record_json)
        doc["event"]["data"]["amount_minor"] = 1_000_000
        await session.execute(
            update(AuditRecord)
            .where(AuditRecord.seq == 2)
            .values(record_json=json.dumps(doc, sort_keys=True, separators=(",", ":")))
        )
        await session.commit()
    result = await audit_log.verify()
    assert not result.valid and result.first_invalid_seq == 2


async def test_deletion_is_detected(audit_log, app):
    for i in range(4):
        await audit_log.append(event(i))
    async with app.state.sessionmaker() as session:
        await session.delete(await session.get(AuditRecord, 2))
        await session.commit()
    result = await audit_log.verify()
    assert not result.valid and result.first_invalid_seq == 3


async def test_api_is_restricted_to_auditors(client, audit_log, auditor_headers, keys):
    await audit_log.append(event(1))
    customer = {"Authorization": f"Bearer {keys.mint('user-1')}"}
    assert (await client.get("/v1/audit/events", headers=customer)).status_code == 403

    events = await client.get(
        "/v1/audit/events?event_type=transfer.completed", headers=auditor_headers
    )
    assert events.status_code == 200 and events.json()[0]["data"] == {"amount_minor": 1}
    verify = await client.get("/v1/audit/verify", headers=auditor_headers)
    assert verify.json()["valid"] is True
