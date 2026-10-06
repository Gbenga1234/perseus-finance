from functools import lru_cache
from typing import Self

from perseus_common.config import ServiceSettings
from pydantic import SecretStr, model_validator


class Settings(ServiceSettings):
    service_name: str = "auth-service"

    jwt_private_key: SecretStr = SecretStr("")
    access_token_ttl_seconds: int = 600
    refresh_token_ttl_seconds: int = 7 * 24 * 3600
    service_token_ttl_seconds: int = 900

    # Comma-separated Fernet keys; the first encrypts, all decrypt (supports rotation).
    mfa_encryption_key: SecretStr = SecretStr("")
    mfa_issuer_name: str = "Perseus Finance"

    # JSON: {"<client_id>": {"secret_sha256": "<hex>", "scopes": ["..."]}}
    service_clients: SecretStr = SecretStr("{}")

    max_failed_logins: int = 5
    lockout_minutes: int = 15

    @model_validator(mode="after")
    def _require_key_material(self) -> Self:
        if not self.jwt_private_key.get_secret_value():
            raise ValueError("jwt_private_key is required")
        if not self.mfa_encryption_key.get_secret_value():
            raise ValueError("mfa_encryption_key is required")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
