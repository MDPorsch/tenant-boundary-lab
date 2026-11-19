"""Shared fixtures. Keys are generated in memory for each test session and never persisted."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import pytest

from tests.harness import KeyPair, Lab, build_lab, generate_keypair


@pytest.fixture(scope="session")
def trusted_keys() -> KeyPair:
    return generate_keypair()


@pytest.fixture(scope="session")
def attacker_keys() -> KeyPair:
    return generate_keypair()


@pytest.fixture
async def open_lab(
    tmp_path: Path, trusted_keys: KeyPair, attacker_keys: KeyPair
) -> AsyncIterator[Callable[[], Awaitable[Lab]]]:
    """Factory, not a ready lab: while the app does not exist, the failure happens inside the
    test body (FAILED with an explicit message) rather than as a setup ERROR."""
    opened: list[Lab] = []

    async def _open() -> Lab:
        lab = await build_lab(tmp_path / f"lab{len(opened)}.sqlite", trusted_keys, attacker_keys)
        opened.append(lab)
        return lab

    yield _open
    for lab in opened:
        await lab.aclose()
