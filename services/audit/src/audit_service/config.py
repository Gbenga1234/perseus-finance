from functools import lru_cache

from perseus_common.config import ServiceSettings


class Settings(ServiceSettings):
    service_name: str = "audit-service"
    consumer_group: str = "audit-service"


@lru_cache
def get_settings() -> Settings:
    return Settings()
