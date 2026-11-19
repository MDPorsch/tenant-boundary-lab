"""The application's own capability table must equal the independent oracle, cell by cell.

The two are written separately on purpose (see tenantlab/auth/policy.py). This is the ONE place
where they meet, so a divergence is caught here rather than mirrored silently.
"""

from __future__ import annotations

import pytest

from tenantlab.auth.policy import CAPABILITIES, Role, parse_role, role_holds
from tenantlab.oracle.matrix import Role as OracleRole
from tenantlab.oracle.matrix import load_capabilities

MATRIX = load_capabilities()
OPERATIONS = [rule.operation for rule in MATRIX.rules]


def test_the_roles_are_the_same_four() -> None:
    assert {r.value for r in Role} == {r.value for r in OracleRole}


def test_the_operations_are_the_same_set() -> None:
    assert set(CAPABILITIES) == set(OPERATIONS)


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("role", [r.value for r in Role])
def test_every_operation_and_role_cell_agrees_with_the_oracle(operation: str, role: str) -> None:
    assert role_holds(operation, Role(role)) is MATRIX.allows(operation, role), (operation, role)


@pytest.mark.parametrize("role", [*Role, None])
def test_an_unknown_operation_is_denied_to_every_role(role: Role | None) -> None:
    """Default deny. Kills any 'unknown means allowed' fallback."""
    for operation in ("", "project.delete", "PROJECT.READ", "project.read ", "tenant.*"):
        assert role_holds(operation, role) is False, operation


@pytest.mark.parametrize("bad", ["", "Owner", "OWNER", " owner", "owner ", "root", "owner\n", "ow"])
def test_only_the_four_exact_role_strings_are_roles(bad: str) -> None:
    assert parse_role(bad) is None
    assert role_holds("tenant.context.read", parse_role(bad)) is False


@pytest.mark.parametrize("bad", [None, 1, 1.5, b"owner", ["owner"], {"owner"}])
def test_a_non_string_is_never_a_role(bad: object) -> None:
    assert parse_role(bad) is None


@pytest.mark.parametrize("good", [r.value for r in Role])
def test_the_exact_role_strings_parse(good: str) -> None:
    assert parse_role(good) is Role(good)


def test_the_capability_table_is_read_only() -> None:
    with pytest.raises(TypeError):
        CAPABILITIES["project.read"] = frozenset()  # type: ignore[index]
