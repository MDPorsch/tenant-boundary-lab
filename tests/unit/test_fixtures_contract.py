"""Fixture integrity and trap-presence (spec s4 'Fixtures')."""

from __future__ import annotations

import re
import uuid

import pytest

from tenantlab.lab.fixtures.loader import Fixtures, load_fixtures


@pytest.fixture(scope="module")
def fx() -> Fixtures:
    return load_fixtures()


def test_spec_named_principals_tenants_and_markets_exist(fx: Fixtures) -> None:
    assert {p.key for p in fx.principals} >= {"alice", "bob", "carla", "dave", "erin", "frank"}
    assert {t.key for t in fx.tenants} == {"A", "B", "C"}
    assert {m.code for m in fx.markets} == {"UK", "US"}


def test_roles_match_the_spec_fixture_list(fx: Fixtures) -> None:
    def role(principal: str, tenant: str) -> tuple[str, str]:
        m = fx.membership_for(principal, tenant)
        return m.role, m.status

    assert role("alice", "A") == ("owner", "active")
    assert role("bob", "A") == ("viewer", "active")
    assert role("carla", "B") == ("admin", "active")
    assert role("dave", "A")[0] != role("dave", "B")[0]  # "different roles"
    assert fx.principal("erin").status == "disabled"
    assert role("frank", "A")[1] == "revoked"


def test_dave_is_a_multi_member_with_roles_that_must_not_leak_across_tenants(fx: Fixtures) -> None:
    assert {m.tenant for m in fx.memberships if m.principal == "dave"} == {"A", "B"}


def test_ids_are_canonical_uuid4_and_never_seeded_ids_are_absent(fx: Fixtures) -> None:
    seeded = {
        x.id
        for x in (
            *fx.principals,
            *fx.tenants,
            *fx.markets,
            *fx.memberships,
            *fx.projects,
            *fx.invoices,
            *fx.contacts,
        )
    }
    for value in seeded | set(fx.never_seeded.values()):
        parsed = uuid.UUID(value)
        assert parsed.version == 4
        assert str(parsed) == value
    assert not seeded & set(fx.never_seeded.values())
    assert set(fx.never_seeded) == {"principal", "tenant", "project", "invoice"}


def test_cross_tenant_objects_exist_for_idor_probing(fx: Fixtures) -> None:
    assert {"A", "B"} <= {p.tenant for p in fx.projects}
    assert {"A", "B"} <= {i.tenant for i in fx.invoices}


def test_market_permissions_are_disjoint_between_tenants_a_and_b(fx: Fixtures) -> None:
    access: dict[str, set[str]] = {}
    for tenant, market in fx.tenant_market_access:
        access.setdefault(tenant, set()).add(market)
    assert access["A"] == {"UK"}
    assert access["B"] == {"US"}
    assert not access["A"] & access["B"]


def test_cross_market_trap_exists_a_project_in_a_market_its_tenant_lacks(fx: Fixtures) -> None:
    access = set(fx.tenant_market_access)
    traps = [p.key for p in fx.projects if (p.tenant, p.market) not in access]
    assert traps == ["PA2"]


def test_object_ownership_trap_owner_principal_is_a_revoked_member(fx: Fixtures) -> None:
    """Ownership must not grant rights (D-04): PA1's owner has a REVOKED membership."""
    pa1 = fx.project("PA1")
    assert fx.membership_for(pa1.owner, pa1.tenant).status == "revoked"


def test_suspended_tenant_has_an_active_owner_for_tl14(fx: Fixtures) -> None:
    assert fx.tenant("C").state == "suspended"
    assert fx.membership_for("gina", "C").status == "active"


def test_exactly_one_active_owner_in_tenant_a_for_the_last_owner_case(fx: Fixtures) -> None:
    owners = [
        m for m in fx.memberships if m.tenant == "A" and m.role == "owner" and m.status == "active"
    ]
    assert [m.principal for m in owners] == ["alice"]


def test_baseline_invoices_are_tenant_coherent(fx: Fixtures) -> None:
    for inv in fx.invoices:
        assert fx.project(inv.project).tenant == inv.tenant


def test_emails_use_the_reserved_invalid_tld_and_no_real_domains(fx: Fixtures) -> None:
    emails = [p.email for p in fx.principals] + [c.email_private for c in fx.contacts]
    assert all(e.endswith("@tenantlab.invalid") for e in emails)


def test_private_sentinel_appears_only_in_private_contact_fields(fx: Fixtures) -> None:
    s = fx.private_sentinel
    for c in fx.contacts:
        assert s in c.email_private
        assert s in c.phone_private
        assert s not in c.public_name
    haystack = [
        *(p.email for p in fx.principals),
        *(p.title for p in fx.projects),
        *(c.public_name for c in fx.contacts),
        *(t.slug for t in fx.tenants),
    ]
    assert not any(s in h for h in haystack)


def test_each_tenant_has_a_unique_tenant_sentinel_in_its_project_titles(fx: Fixtures) -> None:
    for p in fx.projects:
        assert p.title.startswith(f"{fx.tenant_sentinel_prefix}{p.tenant} ")
    assert re.fullmatch(r"SENTINEL-TENANT-", fx.tenant_sentinel_prefix)


def test_no_fixture_value_looks_like_a_credential(fx: Fixtures) -> None:
    blob = repr(fx).lower()
    for needle in ("password", "secret", "bearer ", "-----begin", "api_key", "token"):
        assert needle not in blob, needle
