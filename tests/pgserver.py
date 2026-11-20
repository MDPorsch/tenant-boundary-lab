"""A throwaway PostgreSQL server for the M5 tests (the spec: SQLite is not an adequate substitute
for PostgreSQL row-locking behaviour, so concurrency tests must run on PostgreSQL).

One container per test session, started on first use from an image pinned BY DIGEST, listening on a
random loopback port only, with a random password that never leaves this process. Every test gets
its own database. Nothing here touches a real server: the container is removed when the session
ends.

Like the Docker tests (decision D-46), a missing Docker daemon FAILS the calling test with the exact
deselect command. It is never reported as a pass, and never skipped.
"""

from __future__ import annotations

import atexit
import secrets
import subprocess
import time
import uuid
from typing import Final

import pytest

# postgres:17-alpine, PostgreSQL 17.12, resolved 2026-11-20. A digest, not a tag: a tag can move.
IMAGE: Final = "postgres@sha256:526f86d93c6ea08fd3f1fe5605650cacc781b2c6013169a0ad8f42c7d3d84f32"
DESELECT: Final = 'deselect them with: pytest -m "not docker"'
STARTUP_SECONDS: Final = 90


def _docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - a fixed argv, no shell
        ["docker", *args],  # noqa: S607 - the Docker CLI, found on PATH like the Docker tests do
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


class PgServer:
    def __init__(self) -> None:
        self.name = f"tl-pg-{uuid.uuid4().hex[:10]}"
        self._password = secrets.token_hex(16)
        self.port = 0

    def start(self) -> None:
        try:
            probe = _docker("version", "--format", "{{.Server.Version}}", timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            probe = None
        if probe is None or probe.returncode != 0:
            pytest.fail(
                f"no Docker daemon is available, which the PostgreSQL tests need; {DESELECT}",
                pytrace=False,
            )
        run = _docker(
            "run", "-d", "--rm", "--name", self.name,
            "-e", f"POSTGRES_PASSWORD={self._password}",
            "-p", "127.0.0.1::5432",
            IMAGE,
            # speed, not safety: this server holds synthetic data that is thrown away
            "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off",
            "-c", "max_connections=200",
        )  # fmt: skip
        if run.returncode != 0:
            pytest.fail(
                f"could not start the PostgreSQL container: {run.stderr[-400:]}", pytrace=False
            )
        atexit.register(self.stop)
        deadline = time.monotonic() + STARTUP_SECONDS
        while time.monotonic() < deadline:
            # -h 127.0.0.1: the image first runs a temporary server that listens on a Unix socket
            # only; the final server alone listens on TCP, so a TCP probe is not fooled by init
            if (
                _docker(
                    "exec", self.name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"
                ).returncode
                == 0
            ):
                break
            time.sleep(0.5)
        else:
            pytest.fail("the PostgreSQL container did not become ready", pytrace=False)
        mapping = _docker("port", self.name, "5432/tcp").stdout.strip().splitlines()
        self.port = int(mapping[0].rsplit(":", 1)[1])

    def stop(self) -> None:
        _docker("rm", "-f", self.name, timeout=60)

    def _url(self, database: str) -> str:
        return f"postgresql+psycopg://postgres:{self._password}@127.0.0.1:{self.port}/{database}"

    def new_database_url(self) -> str:
        """A fresh, empty database on this server (the caller migrates and seeds it)."""
        import psycopg  # noqa: PLC0415

        name = f"tl_{uuid.uuid4().hex}"
        with psycopg.connect(
            self._url("postgres").replace("+psycopg", ""), autocommit=True
        ) as conn:
            conn.execute(f'CREATE DATABASE "{name}"')
        return self._url(name)


_SERVER: PgServer | None = None


def server() -> PgServer:
    global _SERVER  # noqa: PLW0603 - one server per session, started on first use
    if _SERVER is None:
        candidate = PgServer()
        candidate.start()
        _SERVER = candidate
    return _SERVER
