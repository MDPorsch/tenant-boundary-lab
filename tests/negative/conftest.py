"""Fixtures for the M3 tests (the vulnerable lab); tests/conftest.py itself stays frozen."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Iterator, Mapping
from pathlib import Path

import pytest

from tests.harness import KeyPair, Lab
from tests.support_m3 import IsolatedLab, build_vulnerable_lab


@pytest.fixture
async def open_vuln(
    tmp_path: Path, trusted_keys: KeyPair, attacker_keys: KeyPair
) -> AsyncIterator[Callable[..., Awaitable[Lab]]]:
    """Factory: `await open_vuln(flaws, environ=..., bind_host=...)`. As with `open_lab`, a missing
    implementation fails INSIDE the test body with an explicit message, not as a setup error."""
    opened: list[Lab] = []

    async def _open(
        flaws: Iterable[str] = (),
        environ: Mapping[str, str] | None = None,
        bind_host: str | None = None,
    ) -> Lab:
        lab = await build_vulnerable_lab(
            tmp_path / f"vuln{len(opened)}.sqlite", trusted_keys, attacker_keys, flaws,
            environ=environ, bind_host=bind_host,
        )  # fmt: skip
        opened.append(lab)
        return lab

    yield _open
    for lab in opened:
        await lab.aclose()


@pytest.fixture
def isolated_lab(tmp_path: Path, trusted_keys: KeyPair) -> Iterator[Callable[..., IsolatedLab]]:
    """Factory for the lab as a separate process on a Unix socket; every one is stopped."""
    started: list[IsolatedLab] = []

    def _start(flaws: Iterable[str]) -> IsolatedLab:
        sub = tmp_path / f"proc{len(started)}"
        sub.mkdir()
        process = IsolatedLab(sub, trusted_keys, flaws)
        started.append(process)
        process.start()
        return process

    yield _start
    for process in started:
        process.stop()
