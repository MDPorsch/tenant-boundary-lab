"""Strict loader for the declarative authorization oracle (CSV).

Fail closed: an unknown role, boolean, error code, header or malformed row raises
:class:`OracleDataError`; an operation/role pair that is not listed is DENIED.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from enum import StrEnum
from importlib import resources
from typing import Final, Literal

from tenantlab.schemas.errors import ErrorCode


class OracleDataError(ValueError):
    """The oracle data is malformed. Never swallowed: a broken oracle must not look clean."""


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"


# Total order used by field_policy.read_min_role. owner >= admin >= editor >= viewer.
ROLE_RANK: Final[dict[Role, int]] = {
    Role.VIEWER: 1,
    Role.EDITOR: 2,
    Role.ADMIN: 3,
    Role.OWNER: 4,
}

_CAPABILITIES_HEADER: Final = (
    "operation",
    "capability",
    "owner",
    "admin",
    "editor",
    "viewer",
    "spec_ref",
)
_GATES_HEADER: Final = (
    "order",
    "gate",
    "applies_to",
    "deny_condition",
    "http_status",
    "problem_code",
    "audit",
    "standard_ref",
)
_FIELDS_HEADER: Final = (
    "resource",
    "field",
    "read_min_role",
    "surfaces",
    "on_create",
    "on_update",
    "notes",
)

# none: structured log only, NO database write (pre-authentication, TL-01/TL-02 "no DB change").
# tenant_null: audit row with the actor but tenant_id NULL (never pollutes a tenant audit log).
# tenant: audit row scoped to the resolved tenant (the actor is an active member).
AuditPolicy = Literal["none", "tenant_null", "tenant"]
_AUDIT_POLICIES: Final[tuple[AuditPolicy, ...]] = ("none", "tenant_null", "tenant")
WriteMode = Literal["server", "client", "precondition", "n/a"]
_WRITE_MODES: Final[tuple[WriteMode, ...]] = ("server", "client", "precondition", "n/a")


@dataclass(frozen=True, slots=True)
class CapabilityRule:
    operation: str
    capability: str
    allowed_roles: frozenset[Role]
    spec_ref: str


@dataclass(frozen=True, slots=True)
class Gate:
    order: int
    gate: str
    applies_to: str
    deny_condition: str
    http_status: int
    problem_code: ErrorCode
    audit: AuditPolicy
    standard_ref: str


@dataclass(frozen=True, slots=True)
class FieldRule:
    resource: str
    field: str
    read_min_role: Role | None  # None == "never": no surface may ever expose it
    surfaces: frozenset[str]
    on_create: WriteMode
    on_update: WriteMode
    notes: str


@dataclass(frozen=True, slots=True)
class CapabilityMatrix:
    rules: tuple[CapabilityRule, ...]

    def allows(self, operation: str, role: str | Role) -> bool:
        """Default-deny: unknown operation or unknown role is False."""
        try:
            role_enum = Role(role)
        except ValueError:
            return False
        for rule in self.rules:
            if rule.operation == operation:
                return role_enum in rule.allowed_roles
        return False


def _read_text(name: str) -> str:
    return resources.files("tenantlab.oracle").joinpath("data", name).read_text(encoding="utf-8")


def _rows(name: str, header: tuple[str, ...]) -> list[dict[str, str]]:
    reader = csv.reader(io.StringIO(_read_text(name)), strict=True)
    try:
        first = next(reader)
    except StopIteration as exc:
        raise OracleDataError(f"{name}: empty file") from exc
    if tuple(first) != header:
        raise OracleDataError(f"{name}: unexpected header {first!r}")
    out: list[dict[str, str]] = []
    for line_no, row in enumerate(reader, start=2):
        if len(row) != len(header):
            raise OracleDataError(f"{name}:{line_no}: expected {len(header)} cells, got {len(row)}")
        out.append(dict(zip(header, row, strict=True)))
    if not out:
        raise OracleDataError(f"{name}: no data rows")
    return out


def _yn(name: str, value: str) -> bool:
    if value == "Y":
        return True
    if value == "N":
        return False
    raise OracleDataError(f"{name}: expected 'Y' or 'N', got {value!r}")  # blank is an error


def load_capabilities() -> CapabilityMatrix:
    rules: list[CapabilityRule] = []
    seen: set[str] = set()
    for row in _rows("capabilities.csv", _CAPABILITIES_HEADER):
        operation = row["operation"]
        if not operation or operation in seen:
            raise OracleDataError(f"capabilities.csv: empty or duplicate operation {operation!r}")
        seen.add(operation)
        allowed = frozenset(
            role for role in Role if _yn(f"{operation}.{role.value}", row[role.value])
        )
        rules.append(CapabilityRule(operation, row["capability"], allowed, row["spec_ref"]))
    return CapabilityMatrix(tuple(rules))


def load_gates() -> tuple[Gate, ...]:
    gates: list[Gate] = []
    for row in _rows("gates.csv", _GATES_HEADER):
        try:
            code = ErrorCode(row["problem_code"])
            order = int(row["order"])
            status = int(row["http_status"])
        except ValueError as exc:
            raise OracleDataError(f"gates.csv: bad value in gate {row['gate']!r}: {exc}") from exc
        audit = _audit_policy(row["audit"], row["gate"])
        gates.append(
            Gate(
                order,
                row["gate"],
                row["applies_to"],
                row["deny_condition"],
                status,
                code,
                audit,
                row["standard_ref"],
            )
        )
    return tuple(gates)


def load_field_policy() -> tuple[FieldRule, ...]:
    rules: list[FieldRule] = []
    seen: set[tuple[str, str]] = set()
    for row in _rows("field_policy.csv", _FIELDS_HEADER):
        key = (row["resource"], row["field"])
        if key in seen:
            raise OracleDataError(f"field_policy.csv: duplicate {key!r}")
        seen.add(key)
        raw_role = row["read_min_role"]
        role: Role | None
        if raw_role == "never":
            role = None
        else:
            try:
                role = Role(raw_role)
            except ValueError as exc:
                raise OracleDataError(f"field_policy.csv: bad read_min_role {raw_role!r}") from exc
        surfaces = frozenset(s for s in row["surfaces"].split("|") if s)
        if role is None and surfaces:
            raise OracleDataError(f"field_policy.csv: 'never' field {key!r} lists surfaces")
        if role is not None and not surfaces:
            raise OracleDataError(f"field_policy.csv: readable field {key!r} lists no surface")
        rules.append(
            FieldRule(
                row["resource"],
                row["field"],
                role,
                surfaces,
                _mode(row["on_create"]),
                _mode(row["on_update"]),
                row["notes"],
            )
        )
    return tuple(rules)


def _mode(value: str) -> WriteMode:
    for mode in _WRITE_MODES:
        if value == mode:
            return mode
    raise OracleDataError(f"field_policy.csv: bad write mode {value!r}")


def _audit_policy(value: str, gate: str) -> AuditPolicy:
    for policy in _AUDIT_POLICIES:
        if value == policy:
            return policy
    raise OracleDataError(f"gates.csv: bad audit policy {value!r} for gate {gate!r}")
