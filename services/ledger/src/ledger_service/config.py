from functools import lru_cache

from perseus_common.config import ServiceSettings


class Settings(ServiceSettings):
    service_name: str = "ledger-service"
    accounts_base_url: str = "http://accounts:8000"
    fraud_base_url: str = "http://fraud:8000"
    # An in-progress idempotency key older than this is considered abandoned.
    idempotency_stale_seconds: int = 300


@lru_cache
def get_settings() -> Settings:
    return Settings()
