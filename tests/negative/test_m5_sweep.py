"""M5: negative tests across ALL resources. Every route, every kind of caller (seven principals, no
token, five kinds of forged token) and every kind of target (own tenant, another tenant, a suspended
tenant, a hidden-market object, something that does not exist, a project paired with another
project's invoice) is sent once, and each response is judged by one independent checker
(tests/support_properties.py): no server error, a well-formed problem, no foreign or private data, the
authorization matrix's answer for a caller with no right to know, and an unchanged database unless an
authorised write succeeded."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from tests.harness import KeyPair, Lab
from tests.support_properties import (
    CREDENTIALS,
    ROUTES,
    build_probe,
    build_template,
    lab_from_template,
    send_and_check,
    targets_for,
)

pytestmark = pytest.mark.milestone("M5")


@pytest.fixture(scope="module")
def template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("m5-template") / "template.sqlite"
    build_template(path)
    return path


@pytest.mark.parametrize("route", [r[0] for r in ROUTES])
async def test_every_caller_and_every_target_of_a_route_is_judged(
    route: str, template: Path, tmp_path: Path, trusted_keys: KeyPair, attacker_keys: KeyPair
) -> None:
    lab = await lab_from_template(template, tmp_path / "lab.sqlite", trusted_keys, attacker_keys)
    try:
        sent = 0
        for credential in CREDENTIALS:
            for target in targets_for(route):
                await send_and_check(lab, credential, build_probe(lab, route, target))
                sent += 1
        assert sent == len(CREDENTIALS) * len(targets_for(route))  # nothing was skipped
        assert sent >= 52
    finally:
        await lab.aclose()


def test_the_sweep_covers_every_route_of_the_contract() -> None:
    """Anti-vacuity: the table the sweep walks has all ten routes of docs/api-contract.md s2."""
    assert len(ROUTES) == 10
    assert {(r[1], r[2]) for r in ROUTES} == {
        ("GET", "/v1/tenants/{tenant}/me"), ("GET", "/v1/tenants/{tenant}/projects"),
        ("POST", "/v1/tenants/{tenant}/projects"), ("GET", "/v1/tenants/{tenant}/audit"),
        ("PUT", "/v1/tenants/{tenant}/members/{member}"), ("GET", "/v1/projects/{project}"),
        ("PATCH", "/v1/projects/{project}"), ("GET", "/v1/projects/{project}/contacts"),
        ("GET", "/v1/invoices/{invoice}"), ("GET", "/v1/projects/{project}/invoices/{invoice}"),
    }  # fmt: skip


# ---------------------------------------------------------------- the checker has teeth ----
IMPLEMENTED_BY_THE_VULNERABLE_LAB = ("me", "list", "project", "patch", "contacts", "invoice")
FLAWS = (
    "TENANT_PREDICATE_OMITTED", "ROLE_CHECK_MISSING", "PRIVATE_PROPERTY_SERIALIZED",
    "MARKET_BOUNDARY_OMITTED", "WRITE_BEFORE_AUTHORIZATION",
)  # fmt: skip


async def _first_failure(lab: Lab) -> str | None:
    for route in IMPLEMENTED_BY_THE_VULNERABLE_LAB:
        for credential in CREDENTIALS:
            for target in targets_for(route):
                try:
                    await send_and_check(lab, credential, build_probe(lab, route, target))
                except AssertionError as exc:
                    return str(exc)
    return None


async def test_the_checker_finds_nothing_in_a_vulnerable_lab_with_every_flaw_off(
    open_vuln: Callable[..., Awaitable[Lab]],
) -> None:
    lab = await open_vuln([])
    assert await _first_failure(lab) is None


@pytest.mark.parametrize("flaw", FLAWS)
async def test_the_checker_fails_on_each_controlled_flaw(
    open_vuln: Callable[..., Awaitable[Lab]], flaw: str
) -> None:
    """Anti-vacuity: a sweep that cannot fail proves nothing. Each of the five flaws must trip it,
    including the one that returns exactly the right status code (the state rule catches that)."""
    lab = await open_vuln([flaw])
    assert await _first_failure(lab) is not None, f"the sweep missed {flaw}"
