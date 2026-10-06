"""Base settings shared by every service.

All values, including secrets, come from environment variables. Locally they are
supplied by Docker Compose from the git-ignored ``.env`` file; in production inject them
from a secret manager.
"""

from __future__ import annotations

from typing import Literal, Self

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url

Environment = Literal["development", "test", "staging", "production"]
SslMode = Literal["disable", "prefer", "require", "verify-ca", "verify-full"]

MIN_SIGNING_KEY_LENGTH = 32


def normalize_pem(value: str) -> str:
    """PEM values in ``.env`` files are usually stored on one line with ``\\n`` escapes."""
    return value.replace("\\n", "\n").strip() + "\n"


class DatabaseSettings(BaseSettings):
    """Database connection settings. Used on their own by migration jobs, which therefore
    need nothing but database credentials."""

    model_config = SettingsConfigDict(extra="ignore")

    # Secure by default: anything not explicitly marked as dev/test gets production checks.
    environment: Environment = "production"

    database_url_override: str | None = None  # used by tests (sqlite) only
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = ""
    db_user: str = ""
    db_password: SecretStr = SecretStr("")
    db_sslmode: SslMode = "prefer"
    db_pool_size: int = 10
    db_max_overflow: int = 5
    db_statement_timeout_ms: int = 15_000

    @property
    def is_production_like(self) -> bool:
        return self.environment in ("production", "staging")

    def database_url(self) -> URL:
        if self.database_url_override:
            return make_url(self.database_url_override)
        return URL.create(
            "postgresql+asyncpg",
            username=self.db_user,
            password=self.db_password.get_secret_value(),
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
        )

    def unsafe_production_settings(self) -> list[str]:
        problems: list[str] = []
        if self.database_url_override:
            problems.append("database_url_override is not allowed in production")
        if not self.db_password.get_secret_value():
            problems.append("db_password is required")
        if self.db_sslmode == "disable":
            problems.append("db_sslmode=disable is not allowed in production")
        return problems

    @model_validator(mode="after")
    def _enforce_production_safety(self) -> Self:
        if self.is_production_like and (problems := self.unsafe_production_settings()):
            raise ValueError("Unsafe production configuration: " + "; ".join(problems))
        return self


class ServiceSettings(DatabaseSettings):
    service_name: str
    log_level: str = "INFO"
    json_logs: bool = True

    allowed_hosts: list[str] = ["localhost", "127.0.0.1"]
    cors_allowed_origins: list[str] = []
    max_request_body_bytes: int = 64 * 1024

    # --- Redis / events ---------------------------------------------------------
    redis_url: str = "redis://localhost:6379/0"
    redis_password: SecretStr | None = None
    event_stream: str = "perseus:events"
    event_signing_key: SecretStr = SecretStr("")
    run_background_workers: bool = True

    # --- Token verification -----------------------------------------------------
    jwt_issuer: str = "https://auth.perseus.local"
    jwks_url: str = "http://auth:8000/.well-known/jwks.json"
    jwt_api_audience: str = "perseus-api"
    jwt_internal_audience: str = "perseus-internal"

    # --- Service-to-service credentials (OAuth2 client credentials) --------------
    auth_token_url: str = "http://auth:8000/oauth/token"  # noqa: S105 - URL, not a secret
    service_client_id: str | None = None
    service_client_secret: SecretStr | None = None
    upstream_timeout_seconds: float = 5.0

    @property
    def docs_enabled(self) -> bool:
        return not self.is_production_like

    def unsafe_production_settings(self) -> list[str]:
        problems = super().unsafe_production_settings()
        if len(self.event_signing_key.get_secret_value()) < MIN_SIGNING_KEY_LENGTH:
            problems.append("event_signing_key must be at least 32 characters")
        if "*" in self.allowed_hosts:
            problems.append("allowed_hosts must not contain '*'")
        if "*" in self.cors_allowed_origins:
            problems.append("cors_allowed_origins must not contain '*'")
        return problems
