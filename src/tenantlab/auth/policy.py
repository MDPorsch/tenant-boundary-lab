"""The application's OWN role/capability table (gate 6).

This is deliberately a second, hand-written copy of the policy and NOT a loader for the oracle
CSV. The oracle (tenantlab.oracle) judges this code; if both read the same file, a bug in the
loader would be mirrored into the judge (spec s5: "avoid coupling test expected result to the same
helper that enforces it"). tests/unit/test_app_policy_matches_oracle.py compares the two cell by
cell, and tests/unit/test_app_independence.py forbids this package from importing the oracle.

Default deny: an unknown operation, an unknown role or a role string that is not exactly one of the
four roles holds nothing.
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Final


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"


_EVERYONE: Final = frozenset(Role)
_EDITORS_UP: Final = frozenset({Role.OWNER, Role.ADMIN, Role.EDITOR})
_ADMINS_UP: Final = frozenset({Role.OWNER, Role.ADMIN})
_OWNER_ONLY: Final = frozenset({Role.OWNER})

CAPABILITIES: Final = MappingProxyType(
    {
        "tenant.context.read": _EVERYONE,
        "project.list": _EVERYONE,
        "project.read": _EVERYONE,
        "project.create": _EDITORS_UP,
        "project.write": _EDITORS_UP,
        "invoice.read": _EVERYONE,
        "contact.private.read": _ADMINS_UP,
        "member.role.write": _OWNER_ONLY,
        "audit.read": _ADMINS_UP,
    }
)


def parse_role(value: object) -> Role | None:
    """Exact match only. Case variants and padded strings are not roles."""
    if not isinstance(value, str):
        return None
    try:
        return Role(value)
    except ValueError:
        return None


def role_holds(operation: str, role: Role | None) -> bool:
    """True only if `operation` is known and `role` is one of the roles that holds it."""
    if role is None:
        return False
    return role in CAPABILITIES.get(operation, frozenset())
