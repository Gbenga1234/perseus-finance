from functools import lru_cache
from typing import Self

from perseus_common.config import ServiceSettings
from pydantic import SecretStr, model_validator


class Settings(ServiceSettings):
    service_name: str = "notifications-service"
    consumer_group: str = "notifications-service"

    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_starttls: bool = True
    smtp_use_tls: bool = False
    smtp_ca_file: str | None = None  # CA bundle file for a private mail relay
    smtp_ca_pem: str | None = None  # or the CA certificate itself (PEM)
    smtp_timeout_seconds: float = 10.0
    mail_from: str = "Perseus Finance <no-reply@perseus.local>"
    # Explicit EHLO name: avoids a slow reverse-DNS lookup of the container hostname.
    smtp_helo_hostname: str = "perseus.local"

    @model_validator(mode="after")
    def _require_encrypted_smtp(self) -> Self:
        if self.is_production_like and not (self.smtp_starttls or self.smtp_use_tls):
            raise ValueError("SMTP must use STARTTLS or implicit TLS in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
