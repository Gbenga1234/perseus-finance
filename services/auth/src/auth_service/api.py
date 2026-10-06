from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from perseus_common.db import DbSession
from perseus_common.errors import AppError, UnauthorizedError
from perseus_common.logging import get_logger
from perseus_common.security import CurrentUser

from auth_service.crypto import ServiceClientRegistry, SigningKey, TokenIssuer
from auth_service.schemas import (
    AcceptedResponse,
    ChangePasswordRequest,
    LoginRequest,
    MfaEnableRequest,
    MfaSetupResponse,
    RefreshRequest,
    RegisterRequest,
    ServiceTokenResponse,
    TokenResponse,
    UserOut,
)
from auth_service.service import AuthService, RequestMeta, TokenPair

log = get_logger(__name__)

router = APIRouter(prefix="/v1/auth", tags=["auth"])
oauth_router = APIRouter(tags=["oauth"])
jwks_router = APIRouter(tags=["keys"])

_basic = HTTPBasic(auto_error=False)


def get_auth_service(request: Request, session: DbSession) -> AuthService:
    state = request.app.state
    return AuthService(session, state.settings, state.token_issuer, state.field_cipher)


Service = Annotated[AuthService, Depends(get_auth_service)]


def request_meta(request: Request) -> RequestMeta:
    return RequestMeta(
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:200] or None,
    )


def _token_response(pair: TokenPair) -> TokenResponse:
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        expires_in=pair.expires_in,
        refresh_expires_in=pair.refresh_expires_in,
    )


@router.post("/register", status_code=status.HTTP_202_ACCEPTED, response_model=AcceptedResponse)
async def register(body: RegisterRequest, service: Service) -> AcceptedResponse:
    await service.register(body.email, body.password.get_secret_value(), body.full_name)
    return AcceptedResponse(detail="If the email address is eligible, an account has been created.")


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, service: Service) -> TokenResponse:
    pair = await service.login(
        body.email, body.password.get_secret_value(), body.totp_code, request_meta(request)
    )
    return _token_response(pair)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, request: Request, service: Service) -> TokenResponse:
    pair = await service.refresh(body.refresh_token.get_secret_value(), request_meta(request))
    return _token_response(pair)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(body: RefreshRequest, service: Service) -> Response:
    await service.logout(body.refresh_token.get_secret_value())
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(user: CurrentUser, service: Service) -> Response:
    await service.logout_all(uuid.UUID(user.subject))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser, service: Service) -> UserOut:
    return UserOut.model_validate(await service.get_profile(uuid.UUID(user.subject)))


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: ChangePasswordRequest, user: CurrentUser, service: Service
) -> Response:
    await service.change_password(
        uuid.UUID(user.subject),
        body.current_password.get_secret_value(),
        body.new_password.get_secret_value(),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def mfa_setup(user: CurrentUser, service: Service) -> MfaSetupResponse:
    secret, uri = await service.mfa_setup(uuid.UUID(user.subject))
    return MfaSetupResponse(secret=secret, provisioning_uri=uri)


@router.post("/mfa/enable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_enable(body: MfaEnableRequest, user: CurrentUser, service: Service) -> Response:
    await service.mfa_enable(uuid.UUID(user.subject), body.code)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@oauth_router.post("/oauth/token", response_model=ServiceTokenResponse)
async def service_token(
    request: Request,
    grant_type: Annotated[str, Form(max_length=50)],
    scope: Annotated[str | None, Form(max_length=500)] = None,
    credentials: HTTPBasicCredentials | None = Depends(_basic),
) -> ServiceTokenResponse:
    """OAuth2 client-credentials grant for service-to-service calls (internal only)."""
    if grant_type != "client_credentials":
        raise AppError("Unsupported grant type.", code="unsupported_grant_type")
    basic_challenge = {"WWW-Authenticate": 'Basic realm="perseus"'}
    if credentials is None:
        raise UnauthorizedError(
            "Client authentication required.", code="invalid_client", headers=basic_challenge
        )
    registry: ServiceClientRegistry = request.app.state.service_clients
    client = registry.authenticate(credentials.username, credentials.password)
    if client is None:
        log.warning("service_client_auth_failed", client_id=credentials.username[:64])
        raise UnauthorizedError(
            "Invalid client credentials.", code="invalid_client", headers=basic_challenge
        )
    scopes = client.scopes
    if scope:
        requested = frozenset(scope.split())
        if not requested.issubset(client.scopes):
            raise AppError("Requested scope is not allowed.", code="invalid_scope")
        scopes = requested
    issuer: TokenIssuer = request.app.state.token_issuer
    return ServiceTokenResponse(
        access_token=issuer.service_token(client.client_id, scopes),
        expires_in=request.app.state.settings.service_token_ttl_seconds,
        scope=" ".join(sorted(scopes)),
    )


@jwks_router.get("/.well-known/jwks.json")
async def jwks(request: Request) -> JSONResponse:
    key: SigningKey = request.app.state.signing_key
    return JSONResponse({"keys": [key.jwk()]}, headers={"Cache-Control": "public, max-age=300"})
