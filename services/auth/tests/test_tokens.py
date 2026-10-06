import jwt
from perseus_common.errors import UnauthorizedError


async def test_jwks_exposes_public_key_only(client):
    resp = await client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    (key,) = resp.json()["keys"]
    assert key["kty"] == "RSA" and key["alg"] == "RS256"
    assert "d" not in key and "p" not in key


async def test_client_credentials_grant(client, app, auth):
    resp = await client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        auth=("ledger-service", auth.client_secret),
    )
    assert resp.status_code == 200, resp.text
    principal = await app.state.token_verifier.verify(
        resp.json()["access_token"], audience="perseus-internal", expected_type="service"
    )
    assert principal.subject == "ledger-service"
    assert principal.has_scopes("accounts:read", "fraud:assess")


async def test_client_credentials_rejections(client, auth):
    bad_secret = await client.post(
        "/oauth/token", data={"grant_type": "client_credentials"}, auth=("ledger-service", "x")
    )
    assert bad_secret.status_code == 401

    bad_scope = await client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "audit:write"},
        auth=("ledger-service", auth.client_secret),
    )
    assert bad_scope.status_code == 400

    bad_grant = await client.post(
        "/oauth/token", data={"grant_type": "password"}, auth=("ledger-service", auth.client_secret)
    )
    assert bad_grant.status_code == 400


async def test_user_token_is_not_a_service_token(client, app, auth):
    await auth.register("eve@example.com")
    tokens = await auth.login("eve@example.com")
    try:
        await app.state.token_verifier.verify(
            tokens["access_token"], audience="perseus-internal", expected_type="service"
        )
    except UnauthorizedError:
        pass
    else:
        raise AssertionError("user token accepted as service token")


async def test_alg_none_token_rejected(client):
    forged = jwt.encode({"sub": "x"}, key=None, algorithm="none")
    resp = await client.get("/v1/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


async def test_security_headers_present(client):
    resp = await client.get("/health/live")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in resp.headers["content-security-policy"]
    assert len(resp.headers["x-request-id"]) >= 8


async def test_untrusted_host_rejected(client):
    resp = await client.get("/health/live", headers={"Host": "evil.example.com"})
    assert resp.status_code == 400


async def test_oversized_body_rejected(client):
    resp = await client.post(
        "/v1/auth/login", content=b"x" * 70_000, headers={"content-type": "application/json"}
    )
    assert resp.status_code == 413
