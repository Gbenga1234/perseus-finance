import uuid

import pytest
from notifications_service.handler import DeliveryError
from notifications_service.templates import render
from perseus_common.events import EventEnvelope

ALICE, BOB = str(uuid.uuid4()), str(uuid.uuid4())


def event(type_: str, **data) -> EventEnvelope:
    return EventEnvelope(type=type_, producer="test", data=data)


async def register(handler, user_id, email, name):
    await handler(event("user.registered", user_id=user_id, email=email, full_name=name))


async def test_transfer_notifies_both_parties_once(handler, sender):
    await register(handler, ALICE, "alice@example.com", "Alice")
    await register(handler, BOB, "bob@example.com", "Bob")
    sender.sent.clear()

    completed = event(
        "transfer.completed",
        transaction_id=str(uuid.uuid4()),
        source_owner_id=ALICE,
        destination_owner_id=BOB,
        amount_minor=2550,
        currency="USD",
    )
    await handler(completed)
    await handler(completed)  # redelivery must not send duplicates

    assert [(to, subject) for to, subject, _ in sender.sent] == [
        ("alice@example.com", "You sent 25.50 USD"),
        ("bob@example.com", "You received 25.50 USD"),
    ]


async def test_failed_delivery_raises_for_retry_then_succeeds(handler, sender):
    await register(handler, ALICE, "alice@example.com", "Alice")
    sender.sent.clear()
    sender.fail = True
    locked = event("user.locked", user_id=ALICE)
    with pytest.raises(DeliveryError):
        await handler(locked)
    sender.fail = False
    await handler(locked)
    assert len(sender.sent) == 1


async def test_unknown_recipient_is_skipped(handler, sender):
    await handler(event("user.password_changed", user_id=str(uuid.uuid4())))
    assert sender.sent == []


def test_subject_cannot_inject_headers():
    subject, _ = render(
        "transfer_sent",
        name="x",
        amount="1\r\nBcc: evil@example.com",
        currency="USD",
        transaction_id="t",
    )
    assert "\r" not in subject and "\n" not in subject


async def test_users_only_see_their_notifications(handler, client, keys):
    await register(handler, ALICE, "alice@example.com", "Alice")
    mine = await client.get(
        "/v1/notifications", headers={"Authorization": f"Bearer {keys.mint(ALICE)}"}
    )
    theirs = await client.get(
        "/v1/notifications", headers={"Authorization": f"Bearer {keys.mint(BOB)}"}
    )
    assert len(mine.json()) == 1 and theirs.json() == []
