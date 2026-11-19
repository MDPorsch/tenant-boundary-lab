"""Engine construction and the UTC datetime column type.

SQLite is the lab/unit-test database. It does not enforce foreign keys unless asked, so every
connection switches `PRAGMA foreign_keys=ON` (docs/architecture.md s4). SQLite uses `NullPool`: no
connection outlives a request, nothing leaks between tests, and a file database is never touched
from two threads at once. In-memory SQLite is refused because every new connection would silently
see a different, empty database.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool
from sqlalchemy.types import TypeDecorator

from tenantlab.auth.tokens import ConfigurationError


def make_engine(database_url: str) -> Engine:
    try:
        url = make_url(database_url)
    except Exception:  # the message of a URL parse error can contain the password
        raise ConfigurationError("database_url is not a valid SQLAlchemy URL") from None
    if url.get_backend_name() == "sqlite":
        if url.database in (None, "", ":memory:"):
            raise ConfigurationError("SQLite in-memory databases are not supported; use a file")
        engine = create_engine(url, poolclass=NullPool)
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
        return engine
    return create_engine(url, pool_pre_ping=True)


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _record: object) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


class UtcDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetimes only. A naive value is a bug, not a guess."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime refused: timestamps must be timezone-aware")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
