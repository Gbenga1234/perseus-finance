from functools import lru_cache

from perseus_common.config import ServiceSettings


class Settings(ServiceSettings):
    service_name: str = "fraud-service"

    # Thresholds are in minor units. A multi-currency deployment would normalise
    # amounts through an FX rate source before scoring.
    hard_limit_minor: int = 100_000_000  # 1,000,000.00
    review_amount_minor: int = 1_000_000  # 10,000.00
    daily_limit_minor: int = 2_500_000  # 25,000.00
    velocity_window_seconds: int = 600
    velocity_max_transfers: int = 5

    deny_score: int = 80
    review_score: int = 50


@lru_cache
def get_settings() -> Settings:
    return Settings()
