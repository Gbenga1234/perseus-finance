import pyotp
from auth_service.models import OutboxEvent, User
from sqlalchemy import select

EMAIL = "ada@example.com"


async def test_register_login_and_profile(client, auth):
    await auth.register(EMAIL)
    tokens = await auth.login(EMAIL)
    assert tokens["token_type"] == "Bearer"

    me = await client.get(
        "/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert me.status_code == 200
    assert me.json()["email"] == EMAIL
    assert me.json()["roles"] == ["customer"]
    assert "password_hash" not in me.json()


async def test_duplicate_registration_is_indistinguishable(client, app, auth):
    first = await auth.register(EMAIL)
    second = await auth.register(EMAIL.upper())
    assert first == second
    async with app.state.sessionmaker() as session:
        types = (await session.scalars(select(OutboxEvent.event_type))).all()
    assert sorted(types) == ["user.registered", "user.registration_attempted"]


async def test_registration_rejects_unknown_fields_and_weak_passwords(client, auth):
    resp = await client.post(
        "/v1/auth/register",
        json={"email": EMAIL, "password": auth.password, "full_name": "Ada", "roles": ["admin"]},
    )
    assert resp.status_code == 422

    resp = await client.post(
        "/v1/auth/register", json={"email": EMAIL, "password": "short", "full_name": "Ada"}
    )
    assert resp.status_code == 422
    assert resp.json()["code"] == "weak_password"


async def test_validation_errors_do_not_echo_secrets(client):
    resp = await client.post("/v1/auth/login", json={"email": "nope", "password": "TopSecret!123"})
    assert resp.status_code == 422
    assert "TopSecret" not in resp.text


async def test_wrong_password_is_generic_and_triggers_lockout(client, settings, auth):
    await auth.register(EMAIL)
    unknown = await client.post(
        "/v1/auth/login", json={"email": "ghost@example.com", "password": auth.password}
    )
    for _ in range(settings.max_failed_logins):
        wrong = await client.post(
            "/v1/auth/login", json={"email": EMAIL, "password": "wrong-password-123"}
        )
        assert wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"]

    # Correct password is now refused because the account is locked.
    locked = await client.post("/v1/auth/login", json={"email": EMAIL, "password": auth.password})
    assert locked.status_code == 401


async def test_refresh_rotation_and_reuse_detection(client, auth):
    await auth.register(EMAIL)
    original = await auth.login(EMAIL)

    rotated = await client.post(
        "/v1/auth/refresh", json={"refresh_token": original["refresh_token"]}
    )
    assert rotated.status_code == 200
    new_refresh = rotated.json()["refresh_token"]
    assert new_refresh != original["refresh_token"]

    replay = await client.post(
        "/v1/auth/refresh", json={"refresh_token": original["refresh_token"]}
    )
    assert replay.status_code == 401

    # Reuse revoked the whole family, including the legitimately rotated token.
    after = await client.post("/v1/auth/refresh", json={"refresh_token": new_refresh})
    assert after.status_code == 401


async def test_logout_revokes_refresh_token(client, auth):
    await auth.register(EMAIL)
    tokens = await auth.login(EMAIL)
    resp = await client.post("/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 204
    resp = await client.post("/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 401


async def test_mfa_enrolment_and_login(client, app, auth):
    await auth.register(EMAIL)
    tokens = await auth.login(EMAIL)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    setup = await client.post("/v1/auth/mfa/setup", headers=headers)
    assert setup.status_code == 200
    totp = pyotp.TOTP(setup.json()["secret"])
    enable = await client.post("/v1/auth/mfa/enable", headers=headers, json={"code": totp.now()})
    assert enable.status_code == 204

    async with app.state.sessionmaker() as session:
        user = await session.scalar(select(User).where(User.email == EMAIL))
        assert user.mfa_secret_encrypted and setup.json()["secret"] not in user.mfa_secret_encrypted
        # Simulate the enrolment code being in an earlier time step.
        user.last_totp_timecode -= 1
        await session.commit()

    no_code = await client.post("/v1/auth/login", json={"email": EMAIL, "password": auth.password})
    assert no_code.status_code == 401
    assert no_code.json()["code"] == "mfa_required"

    code = totp.now()
    ok = await client.post(
        "/v1/auth/login", json={"email": EMAIL, "password": auth.password, "totp_code": code}
    )
    assert ok.status_code == 200

    replay = await client.post(
        "/v1/auth/login", json={"email": EMAIL, "password": auth.password, "totp_code": code}
    )
    assert replay.status_code == 401
    assert replay.json()["code"] == "mfa_invalid"


async def test_change_password_revokes_sessions(client, auth):
    await auth.register(EMAIL)
    tokens = await auth.login(EMAIL)
    new_password = "An0ther-very-g00d-passphrase"
    resp = await client.post(
        "/v1/auth/password",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        json={"current_password": auth.password, "new_password": new_password},
    )
    assert resp.status_code == 204
    resp = await client.post("/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 401
    await auth.login(EMAIL, new_password)
