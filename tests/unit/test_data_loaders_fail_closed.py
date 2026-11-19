"""Fixtures and catalog must raise on malformed data, never return partial or permissive data.

Each case mutates the REAL packaged text, and `_mutate` asserts the mutation changed something so a
stale search string cannot turn a case into a vacuous pass.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from importlib import resources

import pytest

from tenantlab.lab.fixtures.loader import FixtureError, load_fixtures, parse_fixtures
from tenantlab.oracle.catalog import load_catalog, parse_catalog
from tenantlab.oracle.matrix import OracleDataError

FIXTURES = (
    resources.files("tenantlab.lab.fixtures").joinpath("fixtures.toml").read_text(encoding="utf-8")
)
CATALOG = (
    resources.files("tenantlab.oracle")
    .joinpath("data", "case_catalog.toml")
    .read_text(encoding="utf-8")
)


def _mutate(text: str, old: str, new: str) -> str:
    assert old in text, f"mutation target not found: {old!r}"
    mutated = text.replace(old, new, 1)
    assert mutated != text
    return mutated


def _mutate_all(text: str, old: str, new: str) -> str:
    assert text.count(old) >= 1, f"mutation target not found: {old!r}"
    return text.replace(old, new)


def test_packaged_data_parses_and_equals_the_loaders() -> None:
    assert parse_fixtures(FIXTURES) == load_fixtures()
    assert parse_catalog(CATALOG) == load_catalog()


BOB = "10000000-0000-4000-8000-000000000002"
ALICE = "10000000-0000-4000-8000-000000000001"
TENANT_A = "20000000-0000-4000-8000-000000000001"

FIXTURE_MUTATIONS: dict[str, Callable[[str], str]] = {
    "duplicate_id": lambda t: _mutate(t, BOB, ALICE),
    "uuid_not_version_4": lambda t: _mutate(t, BOB, BOB.replace("-4000-", "-1000-")),
    "uuid_not_canonical_lowercase": lambda t: _mutate(
        t, "10000000-0000-4000-8000-0000000000ff", "10000000-0000-4000-8000-0000000000FF"
    ),
    "id_not_a_uuid": lambda t: _mutate(t, BOB, "not-a-uuid"),
    "membership_dangling_principal": lambda t: _mutate(
        t, 'principal = "bob"', 'principal = "nobody"'
    ),
    "membership_dangling_tenant": lambda t: _mutate(
        t, 'tenant = "A"\nrole = "viewer"', 'tenant = "Z"\nrole = "viewer"'
    ),
    "membership_bad_role": lambda t: _mutate(t, 'role = "viewer"', 'role = "superuser"'),
    "membership_bad_status": lambda t: _mutate(t, 'status = "revoked"', 'status = "maybe"'),
    "duplicate_principal_tenant_pair": lambda t: _mutate(
        t, 'principal = "bob"', 'principal = "alice"'
    ),
    "project_dangling_owner": lambda t: _mutate(t, 'owner = "frank"', 'owner = "ghost"'),
    "project_dangling_market": lambda t: _mutate(
        t, 'market = "UK"\nowner = "frank"', 'market = "XX"\nowner = "frank"'
    ),
    "invoice_tenant_differs_from_project_tenant": lambda t: _mutate(
        t, 'tenant = "A"\nproject = "PA1"', 'tenant = "B"\nproject = "PA1"'
    ),
    "invoice_dangling_project": lambda t: _mutate(
        t, 'project = "PA1"\namount_minor', 'project = "P??"\namount_minor'
    ),
    "invoice_negative_amount": lambda t: _mutate(t, "amount_minor = 125000", "amount_minor = -1"),
    "contact_dangling_project": lambda t: _mutate(
        t, 'project = "PA1"\npublic_name', 'project = "P??"\npublic_name'
    ),
    "market_access_dangling_market": lambda t: _mutate(
        t, 'tenant = "A"\nmarket = "UK"', 'tenant = "A"\nmarket = "XX"'
    ),
    "market_access_duplicate_pair": lambda t: _mutate(
        t, 'tenant = "B"\nmarket = "US"', 'tenant = "A"\nmarket = "UK"'
    ),
    "never_seeded_collides_with_a_real_id": lambda t: _mutate(
        t, 'tenant = "20000000-0000-4000-8000-0000000000ff"', f'tenant = "{TENANT_A}"'
    ),
    "duplicate_key": lambda t: _mutate(t, 'key = "B"\nid = "20000000', 'key = "A"\nid = "20000000'),
    "required_table_missing": lambda t: _mutate_all(t, "[[markets]]", "[[marketz]]"),
    "required_field_missing": lambda t: _mutate(t, 'slug = "tenant-a"\n', ""),
    "invalid_toml": lambda t: t + "\n[[broken\n",
}


FIXTURE_EXPECTED_ERROR = {
    "duplicate_id": "duplicate id across fixture tables",
    "uuid_not_version_4": "canonical lowercase UUIDv4",
    "uuid_not_canonical_lowercase": "canonical lowercase UUIDv4",
    "id_not_a_uuid": "is not a UUID",
    "membership_dangling_principal": "dangling reference",
    "membership_dangling_tenant": "dangling reference",
    "membership_bad_role": "bad role/status",
    "membership_bad_status": "bad role/status",
    "duplicate_principal_tenant_pair": "UNIQUE(principal, tenant)",
    "project_dangling_owner": "dangling reference",
    "project_dangling_market": "dangling reference",
    "invoice_tenant_differs_from_project_tenant": "tenant differs from its project's tenant",
    "invoice_dangling_project": "dangling reference",
    "invoice_negative_amount": "negative amount",
    "contact_dangling_project": "dangling project",
    "market_access_dangling_market": "tenant_market_access: dangling",
    "market_access_duplicate_pair": "duplicate tenant_market_access pair",
    "never_seeded_collides_with_a_real_id": "never_seeded id is also seeded",
    "duplicate_key": "duplicate key in tenants",
    "required_table_missing": "missing or empty [[markets]]",
    "required_field_missing": "fixtures.toml is malformed",
    "invalid_toml": "fixtures.toml is malformed",
}


def test_every_fixture_mutation_declares_the_error_it_must_trigger() -> None:
    assert set(FIXTURE_MUTATIONS) == set(FIXTURE_EXPECTED_ERROR)


@pytest.mark.parametrize("name", sorted(FIXTURE_MUTATIONS))
def test_malformed_fixtures_raise_fixture_error_for_the_intended_reason(name: str) -> None:
    with pytest.raises(FixtureError, match=re.escape(FIXTURE_EXPECTED_ERROR[name])):
        parse_fixtures(FIXTURE_MUTATIONS[name](FIXTURES))


CATALOG_MUTATIONS: dict[str, Callable[[str], str]] = {
    "unknown_owasp_id": lambda t: _mutate(t, 'owasp = ["API2:2023"]', 'owasp = ["API99:2023"]'),
    "owasp_not_a_list": lambda t: _mutate(t, 'owasp = ["API2:2023"]', 'owasp = "API2:2023"'),
    "id_wrong_format": lambda t: _mutate(t, 'id = "TL-01"', 'id = "TL-1"'),
    "id_out_of_range": lambda t: _mutate(t, 'id = "TL-01"', 'id = "TL-21"'),
    "duplicate_id": lambda t: _mutate(t, 'id = "TL-02"', 'id = "TL-01"'),
    "unknown_milestone": lambda t: _mutate(t, 'milestones = ["M1"]', 'milestones = ["M9"]'),
    "empty_milestones": lambda t: _mutate(t, 'milestones = ["M1"]', "milestones = []"),
    "bad_state": lambda t: _mutate(
        t, 'state = "red"\nmutation_allowed', 'state = "green"\nmutation_allowed'
    ),
    "expected_too_vague": lambda t: _mutate(
        t, t.split('expected = "', 1)[1].split('"\n', 1)[0], "it works"
    ),
    "missing_title": lambda t: _mutate(t, 'title = "No, malformed or forged bearer"\n', ""),
    "mutation_flag_not_a_bool": lambda t: _mutate(
        t, "mutation_allowed = false", 'mutation_allowed = "false"'
    ),
    "test_modules_not_strings": lambda t: _mutate(
        t, 'test_modules = ["tests/negative/test_m1_authentication.py"]', "test_modules = [1]"
    ),
    "no_cases_at_all": lambda _t: "[meta]\nversion = 1\n",
    "invalid_toml": lambda t: t + "\n[[broken\n",
}


CATALOG_EXPECTED_ERROR = {
    "unknown_owasp_id": "unknown OWASP id",
    "owasp_not_a_list": "must be a list of strings",
    "id_wrong_format": "bad or duplicate id",
    "id_out_of_range": "bad or duplicate id",
    "duplicate_id": "bad or duplicate id",
    "unknown_milestone": "unknown milestone",
    "empty_milestones": "unknown milestone",
    "bad_state": "bad state",
    "expected_too_vague": "concrete statement",
    "missing_title": "missing title",
    "mutation_flag_not_a_bool": "must be a bool",
    "test_modules_not_strings": "must be a list of strings",
    "no_cases_at_all": "no [[cases]]",
    "invalid_toml": "invalid TOML",
}


def test_every_catalog_mutation_declares_the_error_it_must_trigger() -> None:
    assert set(CATALOG_MUTATIONS) == set(CATALOG_EXPECTED_ERROR)


@pytest.mark.parametrize("name", sorted(CATALOG_MUTATIONS))
def test_malformed_catalog_raises_oracle_data_error_for_the_intended_reason(name: str) -> None:
    with pytest.raises(OracleDataError, match=re.escape(CATALOG_EXPECTED_ERROR[name])):
        parse_catalog(CATALOG_MUTATIONS[name](CATALOG))
