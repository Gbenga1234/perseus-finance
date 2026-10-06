from fraud_service.models import Base
from perseus_common.migrations import run_migrations

run_migrations(Base.metadata)
