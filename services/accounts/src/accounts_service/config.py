from functools import lru_cache

from perseus_common.config import ServiceSettings


class Settings(ServiceSettings):
    service_name: str = "accounts-service"
    ledger_base_url: str = "http://ledger:8000"
    max_accounts_per_user: int = 10


@lru_cache
def get_settings() -> Settings:
    return Settings()
