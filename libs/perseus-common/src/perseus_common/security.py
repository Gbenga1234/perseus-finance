"""JWT verification (RS256 via JWKS) and FastAPI authorization dependencies.

Every service verifies tokens itself (zero-trust): the edge proxy is not trusted to
have authenticated a request. User tokens and service tokens use distinct audiences
so a customer token can never reach an ``/internal`` endpoint.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Protocol

import httpx
import jwt
import structlog
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from perseus_common.errors import ForbiddenError, UnauthorizedError, UpstreamError
from perseus_common.logging import get_logger

log = get_logger(__name__)

ALLOWED_ALGORITHMS = ["RS256"]
TokenType = Literal["access", "service"]


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    kind: TokenType
    roles: frozenset[str]
    scopes: frozenset[str]
    token_id: str

    def has_any_role(self, *roles: str) -> bool:
        return bool(self.roles.intersection(roles))

    def has_scopes(self, *scopes: str) -> bool:
        return set(scopes).issubset(self.scopes)

    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles


class KeyProvider(Protocol):
    async def get_key(self, kid: str) -> Any: ...


class StaticKeyProvider:
    """Key provider backed by an in-memory mapping (the issuer itself, and tests)."""

    def __init__(self, keys: Mapping[str, Any]) -> None:
        self._keys = dict(keys)

    async def get_key(self, kid: str) -> Any:
        return self._keys.get(kid)


class JWKSKeyProvider:
    """Fetches and caches public keys from the auth service's JWKS endpoint.

    Unknown ``kid`` values trigger a refresh (supporting key rotation), rate-limited so
    attackers cannot use random kids to hammer the auth service.
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        jwks_url: str,
        *,
        ttl_seconds: float = 600,
        min_refresh_interval: float = 30,
    ) -> None:
        self._http = http
        self._url = jwks_url
        self._ttl = ttl_seconds
        self._min_refresh = min_refresh_interval
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str) -> Any:
        now = time.monotonic()
        stale = now - self._fetched_at > self._ttl
        if kid in self._keys and not stale:
            return self._keys[kid]
        async with self._lock:
            now = time.monotonic()
            if (kid not in self._keys or stale) and now - self._fetched_at > self._min_refresh:
                await self._refresh()
            return self._keys.get(kid)

    async def _refresh(self) -> None:
        try:
            response = await self._http.get(self._url, timeout=5.0)
            response.raise_for_status()
            jwks = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("jwks_fetch_failed", error=str(exc))
            if not self._keys:
                raise UpstreamError("Unable to verify credentials right now.") from exc
            return
        keys: dict[str, Any] = {}
        for jwk in jwks.get("keys", []):
            if jwk.get("kty") != "RSA" or jwk.get("use", "sig") != "sig" or "kid" not in jwk:
                continue
            keys[jwk["kid"]] = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
        self._keys = keys
        self._fetched_at = time.monotonic()


class TokenVerifier:
    def __init__(self, keys: KeyProvider, issuer: str, *, leeway_seconds: int = 30) -> None:
        self._keys = keys
        self._issuer = issuer
        self._leeway = leeway_seconds

    async def verify(self, token: str, *, audience: str, expected_type: TokenType) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise UnauthorizedError("Invalid token") from exc
        # Pin the algorithm explicitly: rejects "none" and HS256 key-confusion attacks.
        if header.get("alg") not in ALLOWED_ALGORITHMS or not header.get("kid"):
            raise UnauthorizedError("Invalid token")
        key = await self._keys.get_key(str(header["kid"]))
        if key is None:
            raise UnauthorizedError("Invalid token")
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=ALLOWED_ALGORITHMS,
                audience=audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise UnauthorizedError("Token expired", code="token_expired") from exc
        except jwt.PyJWTError as exc:
            raise UnauthorizedError("Invalid token") from exc
        if claims.get("typ") != expected_type:
            raise UnauthorizedError("Invalid token")
        roles = claims.get("roles", [])
        scope = claims.get("scope", "")
        if not isinstance(roles, list) or not isinstance(scope, str):
            raise UnauthorizedError("Invalid token")
        return Principal(
            subject=str(claims["sub"]),
            kind=expected_type,
            roles=frozenset(str(r) for r in roles),
            scopes=frozenset(scope.split()),
            token_id=str(claims["jti"]),
        )


_bearer = HTTPBearer(auto_error=False)


def _verifier(request: Request) -> TokenVerifier:
    verifier: TokenVerifier = request.app.state.token_verifier
    return verifier


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise UnauthorizedError()
    settings = request.app.state.settings
    principal = await _verifier(request).verify(
        credentials.credentials, audience=settings.jwt_api_audience, expected_type="access"
    )
    structlog.contextvars.bind_contextvars(principal=principal.subject)
    return principal


async def get_current_service(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise UnauthorizedError()
    settings = request.app.state.settings
    principal = await _verifier(request).verify(
        credentials.credentials, audience=settings.jwt_internal_audience, expected_type="service"
    )
    structlog.contextvars.bind_contextvars(principal=principal.subject)
    return principal


CurrentUser = Annotated[Principal, Depends(get_current_user)]
CurrentService = Annotated[Principal, Depends(get_current_service)]


def require_roles(*roles: str) -> Callable[..., Awaitable[Principal]]:
    async def dependency(principal: CurrentUser) -> Principal:
        if not principal.has_any_role(*roles):
            raise ForbiddenError("Insufficient permissions")
        return principal

    return dependency


def require_service_scopes(*scopes: str) -> Callable[..., Awaitable[Principal]]:
    async def dependency(principal: CurrentService) -> Principal:
        if not principal.has_scopes(*scopes):
            log.warning("service_scope_denied", client=principal.subject, required=scopes)
            raise ForbiddenError("Insufficient scope")
        return principal

    return dependency
