import time
import uuid

import jwt
import pytest
from perseus_common.config import ServiceSettings
from perseus_common.errors import UnauthorizedError
from perseus_common.events import EventEnvelope, EventSigner, InvalidEventError, decode_event
from perseus_common.logging import REDACTED, redact_sensitive
from perseus_common.money import MoneyError, format_minor_units, to_minor_units
from perseus_common.testing import TEST_ISSUER, TEST_SIGNING_KEY, TestKeys
from pydantic import ValidationError


@pytest.fixture(scope="module")
def keys() -> TestKeys:
    return TestKeys()


# --- money -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("amount", "currency", "minor"),
    [("10.50", "USD", 1050), ("1", "USD", 100), ("1500", "JPY", 1500), ("1.234", "KWD", 1234)],
)
def test_to_minor_units(amount, currency, minor):
    assert to_minor_units(amount, currency) == minor
    assert to_minor_units(format_minor_units(minor, currency), currency) == minor


@pytest.mark.parametrize(
    ("amount", "currency"),
    [
        ("0.001", "USD"),
        ("1.5", "JPY"),
        ("0", "USD"),
        ("-1", "USD"),
        ("1e5", "USD"),
        ("NaN", "USD"),
        ("10", "XXX"),
        ("9" * 16, "USD"),
    ],
)
def test_to_minor_units_rejects(amount, currency):
    with pytest.raises(MoneyError):
        to_minor_units(amount, currency)


# --- events ------------------------------------------------------------------------


def test_signed_event_roundtrip_and_tamper_detection():
    signer = EventSigner(TEST_SIGNING_KEY)
    envelope = EventEnvelope(type="transfer.completed", producer="ledger", data={"amount": 1})
    body = envelope.model_dump_json()
    fields = {"envelope": body, "sig": signer.sign(body)}
    assert decode_event(fields, signer) == envelope

    tampered = {"envelope": body.replace('"amount":1', '"amount":9'), "sig": fields["sig"]}
    with pytest.raises(InvalidEventError):
        decode_event(tampered, signer)
    with pytest.raises(InvalidEventError):
        decode_event({"envelope": body}, signer)
    with pytest.raises(InvalidEventError):
        decode_event(fields, EventSigner("another-signing-key-0123456789abcdef"))


def test_short_signing_keys_are_refused():
    with pytest.raises(ValueError):
        EventSigner("too-short")


# --- logging -----------------------------------------------------------------------


def test_redaction_is_recursive():
    event = {
        "event": "x",
        "password": "hunter2",
        "payload": {"refresh_token": "abc", "nested": [{"client_secret": "s"}], "ok": 1},
        "Authorization": "Bearer abc",
    }
    out = redact_sensitive(None, "info", event)
    assert out["password"] == REDACTED and out["Authorization"] == REDACTED
    assert out["payload"]["refresh_token"] == REDACTED
    assert out["payload"]["nested"][0]["client_secret"] == REDACTED
    assert out["payload"]["ok"] == 1


# --- configuration -------------------------------------------------------------------


def test_production_config_rejects_unsafe_values():
    with pytest.raises(ValidationError) as exc:
        ServiceSettings(
            service_name="x", environment="production", allowed_hosts=["*"], db_sslmode="disable"
        )
    message = str(exc.value)
    for fragment in ("event_signing_key", "db_password", "db_sslmode", "allowed_hosts"):
        assert fragment in message


def test_production_config_accepts_safe_values():
    settings = ServiceSettings(
        service_name="x",
        environment="production",
        db_password="pw",
        event_signing_key=TEST_SIGNING_KEY,
        db_sslmode="verify-full",
    )
    assert not settings.docs_enabled
    assert settings.database_url().password == "pw"


# --- token verification -------------------------------------------------------------


async def test_verifier_accepts_valid_tokens(keys):
    principal = await keys.verifier().verify(
        keys.mint("user-1", roles=["admin"]), audience="perseus-api", expected_type="access"
    )
    assert principal.subject == "user-1" and principal.is_admin


@pytest.mark.parametrize(
    "case", ["expired", "wrong_aud", "wrong_iss", "wrong_typ", "hs256", "unknown_kid", "garbage"]
)
async def test_verifier_rejects_bad_tokens(keys, case):
    if case == "expired":
        token = keys.mint("u", ttl=-120)
    elif case == "wrong_aud":
        token = keys.mint("u", audience="perseus-internal")
    elif case == "wrong_iss":
        token = keys.mint("u", issuer="https://evil.example.com")
    elif case == "wrong_typ":
        token = keys.mint("u", typ="service")
    elif case == "hs256":
        now = int(time.time())
        token = jwt.encode(
            {
                "sub": "u",
                "aud": "perseus-api",
                "iss": TEST_ISSUER,
                "iat": now,
                "nbf": now,
                "exp": now + 60,
                "jti": uuid.uuid4().hex,
                "typ": "access",
            },
            "secret-key-material-that-is-long-enough",
            algorithm="HS256",
            headers={"kid": keys.kid},
        )
    elif case == "unknown_kid":
        other = TestKeys(kid="other")
        token = other.mint("u")
    else:
        token = "not.a.jwt"
    with pytest.raises(UnauthorizedError):
        await keys.verifier().verify(token, audience="perseus-api", expected_type="access")


def test_normalize_pem_accepts_escaped_and_real_newlines():
    from perseus_common.config import normalize_pem

    pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
    assert normalize_pem(pem.replace("\n", "\\n")) == pem + "\n"
    assert normalize_pem(pem) == pem + "\n"
