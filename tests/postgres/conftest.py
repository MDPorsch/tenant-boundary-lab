"""Fixtures for the PostgreSQL tests (milestone M5)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import pytest

from tests.harness import KeyPair, Lab, build_lab


@pytest.fixture
async def open_pg_lab(
    tmp_path: Path, trusted_keys: KeyPair, attacker_keys: KeyPair
) -> AsyncIterator[Callable[[], Awaitable[Lab]]]:
    """Factory: `lab = await open_pg_lab()` is a migrated, seeded lab on its own PostgreSQL database."""
    opened: list[Lab] = []

    async def _open() -> Lab:
        lab = await build_lab(
            tmp_path / "unused.sqlite", trusted_keys, attacker_keys, postgres=True
        )
        opened.append(lab)
        return lab

    yield _open
    for lab in opened:
        await lab.aclose()
