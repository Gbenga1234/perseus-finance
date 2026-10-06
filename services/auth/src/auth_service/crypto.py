"""Signing keys, token issuance and field-level encryption."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from auth_service.config import Settings

MIN_RSA_BITS = 2048


class SigningKey:
    def __init__(self, private_pem: str) -> None:
        key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < MIN_RSA_BITS:
            raise ValueError("JWT signing key must be an RSA key of at least 2048 bits")
        self.private_key = key
        self.public_key = key.public_key()
        der = self.public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.kid = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode()[:16]

    def jwk(self) -> dict[str, Any]:
        jwk: dict[str, Any] = jwt.algorithms.RSAAlgorithm.to_jwk(self.public_key, as_dict=True)
        jwk.update(kid=self.kid, use="sig", alg="RS256")
        return jwk


class TokenIssuer:
    def __init__(self, key: SigningKey, settings: Settings) -> None:
        self._key = key
        self._settings = settings

    def _encode(self, claims: dict[str, Any], ttl: int) -> str:
        now = int(time.time())
        payload = {
            "iss": self._settings.jwt_issuer,
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
            "jti": uuid.uuid4().hex,
            **claims,
        }
        return jwt.encode(
            payload, self._key.private_key, algorithm="RS256", headers={"kid": self._key.kid}
        )

    def access_token(self, user_id: uuid.UUID, roles: Iterable[str], amr: list[str]) -> str:
        return self._encode(
            {
                "sub": str(user_id),
                "aud": self._settings.jwt_api_audience,
                "typ": "access",
                "roles": sorted(roles),
                "scope": "",
                "amr": amr,
            },
            self._settings.access_token_ttl_seconds,
        )

    def service_token(self, client_id: str, scopes: Iterable[str]) -> str:
        return self._encode(
            {
                "sub": client_id,
                "aud": self._settings.jwt_internal_audience,
                "typ": "service",
                "roles": [],
                "scope": " ".join(sorted(scopes)),
            },
            self._settings.service_token_ttl_seconds,
        )


def new_refresh_token() -> tuple[str, str]:
    """Return ``(token, sha256_hex)``. 384 bits of entropy, so a fast hash is sufficient."""
    token = secrets.token_urlsafe(48)
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class FieldCipher:
    def __init__(self, keys_csv: str) -> None:
        keys = [k.strip() for k in keys_csv.split(",") if k.strip()]
        self._fernet = MultiFernet([Fernet(k) for k in keys])

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken as exc:
            raise ValueError("Unable to decrypt field") from exc


@dataclass(frozen=True)
class ServiceClient:
    client_id: str
    secret_sha256: str
    scopes: frozenset[str]


class ServiceClientRegistry:
    _DUMMY = hashlib.sha256(b"no-such-client").hexdigest()

    def __init__(self, raw_json: str) -> None:
        data = json.loads(raw_json or "{}")
        self._clients = {
            client_id: ServiceClient(
                client_id=client_id,
                secret_sha256=str(cfg["secret_sha256"]).lower(),
                scopes=frozenset(cfg.get("scopes", [])),
            )
            for client_id, cfg in data.items()
        }

    def authenticate(self, client_id: str, secret: str) -> ServiceClient | None:
        client = self._clients.get(client_id)
        expected = client.secret_sha256 if client else self._DUMMY
        presented = hashlib.sha256(secret.encode()).hexdigest()
        if hmac.compare_digest(expected, presented) and client is not None:
            return client
        return None
