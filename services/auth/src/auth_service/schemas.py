from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr

# Printable characters only; blocks control characters and angle brackets (HTML in emails).
SAFE_NAME = r"^[^\x00-\x1f\x7f<>]+$"


class StrictModel(BaseModel):
    # Reject unknown fields (prevents mass-assignment style attacks, e.g. "roles").
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RegisterRequest(StrictModel):
    email: EmailStr = Field(max_length=320)
    password: SecretStr
    full_name: str = Field(min_length=1, max_length=100, pattern=SAFE_NAME)


class LoginRequest(StrictModel):
    email: EmailStr = Field(max_length=320)
    password: SecretStr
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class RefreshRequest(StrictModel):
    refresh_token: SecretStr


class ChangePasswordRequest(StrictModel):
    current_password: SecretStr
    new_password: SecretStr


class MfaEnableRequest(StrictModel):
    code: str = Field(pattern=r"^\d{6}$")


class AcceptedResponse(BaseModel):
    status: Literal["accepted"] = "accepted"
    detail: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105
    expires_in: int
    refresh_expires_in: int


class ServiceTokenResponse(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105
    expires_in: int
    scope: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str
    roles: list[str]
    mfa_enabled: bool
    created_at: datetime


class MfaSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
