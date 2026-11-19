"""Alembic environment: online mode only, URL supplied programmatically by `upgrade_to_head`."""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from tenantlab.db.models import Base

config = context.config


def run_migrations_online() -> None:
    url = config.attributes.get("database_url")
    if not isinstance(url, str) or not url:
        raise RuntimeError("no database_url supplied: call tenantlab.db.migrate.upgrade_to_head()")
    engine = create_engine(url, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=Base.metadata,
                render_as_batch=connection.dialect.name == "sqlite",
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("offline (--sql) migrations are not supported")
run_migrations_online()
