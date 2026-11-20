"""Helpers for the M5 PostgreSQL concurrency tests.

The tests make races DETERMINISTIC instead of hoping a thread scheduler produces them: a separate
transaction (the `Holder`) takes a row lock the request under test will need, the request is started
and observed to be BLOCKED on it, a competing change is then started, and only afterwards is the lock
released. Whether the competing change could complete while the request was in flight is exactly the
behaviour under test. Judging is by raw SQL and by what the lock manager reports, never by app code.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Final

import psycopg
from sqlalchemy.engine import Engine

from tests.harness import Lab

POLL_SECONDS: Final = 0.05


def conninfo(engine: Engine) -> str:
    """A libpq URL for the lab's database (SQLAlchemy's `+psycopg` driver suffix removed)."""
    return engine.url.render_as_string(hide_password=False).replace("+psycopg", "", 1)


class Holder:
    """A raw transaction that holds row locks until `release()`. Use as a context manager."""

    def __init__(self, lab: Lab) -> None:
        self._conn = psycopg.connect(conninfo(lab.engine), autocommit=False)

    def lock(self, sql: str, *params: Any) -> None:
        with self._conn.cursor() as cursor:
            cursor.execute(sql, params)
            cursor.fetchall()

    def release(self) -> None:
        if not self._conn.closed:
            self._conn.commit()
            self._conn.close()

    def __enter__(self) -> Holder:
        return self

    def __exit__(self, *_exc: object) -> None:
        if not self._conn.closed:
            self._conn.rollback()
            self._conn.close()


def blocked_backends(lab: Lab) -> int:
    """How many OTHER sessions of this database are waiting for a lock right now."""
    with psycopg.connect(conninfo(lab.engine), autocommit=True) as conn:
        row = conn.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
            "AND pid <> pg_backend_pid() AND wait_event_type = 'Lock'"
        ).fetchone()
    assert row is not None
    return int(row[0])


async def wait_until_blocked(lab: Lab, count: int, *, seconds: float = 15.0) -> None:
    """Wait until `count` sessions are blocked on locks; fail (not hang) if they never are."""
    deadline = time.monotonic() + seconds
    seen = 0
    while time.monotonic() < deadline:
        seen = blocked_backends(lab)
        if seen >= count:
            return
        await asyncio.sleep(POLL_SECONDS)
    raise AssertionError(f"expected {count} blocked session(s), saw {seen}")


def run_sql(lab: Lab, statement: str, *params: Any) -> None:
    """One committed statement on its OWN connection (it blocks if a lock is in the way)."""
    with psycopg.connect(conninfo(lab.engine), autocommit=True) as conn:
        conn.execute("SET statement_timeout = '60s'")
        conn.execute(statement, params)


class Competing:
    """A change started in a worker thread while the request under test is already in flight."""

    def __init__(self, lab: Lab, statement: str, *params: Any) -> None:
        self._lab = lab
        self._task = asyncio.ensure_future(asyncio.to_thread(run_sql, lab, statement, *params))

    async def got_through(self, *, blocked: int, seconds: float = 8.0) -> bool:
        """True if it COMPLETED before it was seen waiting for a lock: nothing stood in its way
        although the request was in flight. False if the lock manager made it wait (`blocked`
        sessions are waiting, counting the request under test)."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self._task.done():
                await self._task
                return True
            if blocked_backends(self._lab) >= blocked:
                return False
            await asyncio.sleep(POLL_SECONDS)
        raise AssertionError("the competing change neither finished nor blocked")

    async def finish(self) -> None:
        await self._task
