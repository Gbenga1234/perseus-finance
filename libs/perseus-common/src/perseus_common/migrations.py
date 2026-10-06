"""Shared Alembic ``env.py`` logic. Each service's env.py just calls ``run_migrations``."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import MetaData, pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from perseus_common.config import DatabaseSettings


def _configure(target_metadata: MetaData, **kwargs: Any) -> None:
    context.configure(target_metadata=target_metadata, compare_type=True, **kwargs)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations(target_metadata: MetaData) -> None:
    config = context.config
    if config.config_file_name is not None:
        fileConfig(config.config_file_name, disable_existing_loggers=False)
    settings = DatabaseSettings()
    url = settings.database_url()

    if context.is_offline_mode():
        _configure(
            target_metadata, url=url.render_as_string(hide_password=True), literal_binds=True
        )
        return

    connect_args: dict[str, Any] = {}
    if url.get_backend_name() == "postgresql":
        connect_args = {
            "ssl": settings.db_sslmode,
            # Fail fast instead of queueing behind long-running locks in production.
            "server_settings": {"lock_timeout": "10000", "application_name": "migrations"},
        }

    def _run(connection: Connection) -> None:
        _configure(
            target_metadata,
            connection=connection,
            render_as_batch=connection.dialect.name == "sqlite",
        )

    async def _online() -> None:
        engine = create_async_engine(url, poolclass=pool.NullPool, connect_args=connect_args)
        async with engine.connect() as connection:
            await connection.run_sync(_run)
        await engine.dispose()

    asyncio.run(_online())
