"""Strict loader for the synthetic lab fixtures (fixtures.toml).

Every id must be a canonical lowercase UUIDv4; every reference must resolve; every key must be
unique. A malformed fixture raises :class:`FixtureError`: it never degrades to partial data.
"""

from __future__ import annotations

import tomllib
import uuid
from dataclasses import dataclass
from importlib import resources
from typing import Any, Final

_ROLES: Final = ("owner", "admin", "editor", "viewer")


class FixtureError(ValueError):
    """The fixture file is malformed or internally inconsistent."""


@dataclass(frozen=True, slots=True)
class PrincipalFx:
    key: str
    id: str
    email: str
    status: str
    auth_version: int


@dataclass(frozen=True, slots=True)
class TenantFx:
    key: str
    id: str
    slug: str
    state: str


@dataclass(frozen=True, slots=True)
class MarketFx:
    key: str
    id: str
    code: str


@dataclass(frozen=True, slots=True)
class MembershipFx:
    key: str
    id: str
    principal: str  # key
    tenant: str  # key
    role: str
    status: str
    version: int


@dataclass(frozen=True, slots=True)
class ProjectFx:
    key: str
    id: str
    tenant: str  # key
    market: str  # key
    owner: str  # principal key
    title: str
    status: str
    row_version: int


@dataclass(frozen=True, slots=True)
class InvoiceFx:
    key: str
    id: str
    tenant: str  # key
    project: str  # key
    amount_minor: int
    currency: str
    status: str


@dataclass(frozen=True, slots=True)
class ContactFx:
    key: str
    id: str
    project: str  # key
    public_name: str
    email_private: str
    phone_private: str


@dataclass(frozen=True, slots=True)
class Fixtures:
    private_sentinel: str
    tenant_sentinel_prefix: str
    never_seeded: dict[str, str]
    principals: tuple[PrincipalFx, ...]
    tenants: tuple[TenantFx, ...]
    markets: tuple[MarketFx, ...]
    tenant_market_access: tuple[tuple[str, str], ...]  # (tenant key, market key)
    memberships: tuple[MembershipFx, ...]
    projects: tuple[ProjectFx, ...]
    invoices: tuple[InvoiceFx, ...]
    contacts: tuple[ContactFx, ...]

    def principal(self, key: str) -> PrincipalFx:
        return _one(self.principals, key)

    def tenant(self, key: str) -> TenantFx:
        return _one(self.tenants, key)

    def project(self, key: str) -> ProjectFx:
        return _one(self.projects, key)

    def invoice(self, key: str) -> InvoiceFx:
        return _one(self.invoices, key)

    def membership_for(self, principal: str, tenant: str) -> MembershipFx:
        for m in self.memberships:
            if m.principal == principal and m.tenant == tenant:
                return m
        raise KeyError((principal, tenant))


def _one[T](items: tuple[T, ...], key: str) -> T:
    for item in items:
        if getattr(item, "key") == key:  # noqa: B009 - all fixture dataclasses define `key`
            return item
    raise KeyError(key)


def _check_uuid4(label: str, value: object) -> str:
    if not isinstance(value, str):
        raise FixtureError(f"{label}: id must be a string")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise FixtureError(f"{label}: {value!r} is not a UUID") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise FixtureError(f"{label}: {value!r} must be a canonical lowercase UUIDv4")
    return value


def _table(raw: dict[str, Any], name: str) -> list[dict[str, Any]]:
    value = raw.get(name)
    if not isinstance(value, list) or not value:
        raise FixtureError(f"fixtures.toml: missing or empty [[{name}]]")
    return value


def load_fixtures() -> Fixtures:
    """Load and validate the packaged fixtures."""
    text = (
        resources.files("tenantlab.lab.fixtures")
        .joinpath("fixtures.toml")
        .read_text(encoding="utf-8")
    )
    return parse_fixtures(text)


def parse_fixtures(text: str) -> Fixtures:
    """Parse fixture TOML. Any structural problem is a FixtureError, never a partial result."""
    try:
        return _parse(text)
    except (KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise FixtureError(f"fixtures.toml is malformed: {type(exc).__name__}: {exc}") from exc


def _parse(text: str) -> Fixtures:
    raw = tomllib.loads(text)
    meta = raw.get("meta", {})
    never = {
        k: _check_uuid4(f"never_seeded.{k}", v) for k, v in meta.get("never_seeded", {}).items()
    }

    principals = tuple(
        PrincipalFx(
            r["key"], _check_uuid4(r["key"], r["id"]), r["email"], r["status"], r["auth_version"]
        )
        for r in _table(raw, "principals")
    )
    tenants = tuple(
        TenantFx(r["key"], _check_uuid4(r["key"], r["id"]), r["slug"], r["state"])
        for r in _table(raw, "tenants")
    )
    markets = tuple(
        MarketFx(r["key"], _check_uuid4(r["key"], r["id"]), r["code"])
        for r in _table(raw, "markets")
    )
    access = tuple((r["tenant"], r["market"]) for r in _table(raw, "tenant_market_access"))
    memberships = tuple(
        MembershipFx(
            r["key"],
            _check_uuid4(r["key"], r["id"]),
            r["principal"],
            r["tenant"],
            r["role"],
            r["status"],
            r["version"],
        )
        for r in _table(raw, "memberships")
    )
    projects = tuple(
        ProjectFx(
            r["key"],
            _check_uuid4(r["key"], r["id"]),
            r["tenant"],
            r["market"],
            r["owner"],
            r["title"],
            r["status"],
            r["row_version"],
        )
        for r in _table(raw, "projects")
    )
    invoices = tuple(
        InvoiceFx(
            r["key"],
            _check_uuid4(r["key"], r["id"]),
            r["tenant"],
            r["project"],
            r["amount_minor"],
            r["currency"],
            r["status"],
        )
        for r in _table(raw, "invoices")
    )
    contacts = tuple(
        ContactFx(
            r["key"],
            _check_uuid4(r["key"], r["id"]),
            r["project"],
            r["public_name"],
            r["email_private"],
            r["phone_private"],
        )
        for r in _table(raw, "project_contacts")
    )
    fx = Fixtures(
        private_sentinel=meta["private_sentinel"],
        tenant_sentinel_prefix=meta["tenant_sentinel_prefix"],
        never_seeded=never,
        principals=principals,
        tenants=tenants,
        markets=markets,
        tenant_market_access=access,
        memberships=memberships,
        projects=projects,
        invoices=invoices,
        contacts=contacts,
    )
    _validate(fx)
    return fx


def _validate(fx: Fixtures) -> None:
    """Referential and uniqueness integrity. The database enforces the same in M1."""
    _validate_uniqueness(fx)
    _validate_memberships(fx)
    _validate_resources(fx)


def _validate_uniqueness(fx: Fixtures) -> None:
    tables: dict[str, list[Any]] = {
        "principals": list(fx.principals),
        "tenants": list(fx.tenants),
        "markets": list(fx.markets),
        "memberships": list(fx.memberships),
        "projects": list(fx.projects),
        "invoices": list(fx.invoices),
        "contacts": list(fx.contacts),
    }
    all_ids = [row.id for rows in tables.values() for row in rows]
    if len(all_ids) != len(set(all_ids)):
        raise FixtureError("duplicate id across fixture tables")
    collided = set(all_ids) & set(fx.never_seeded.values())
    if collided:
        raise FixtureError(f"a never_seeded id is also seeded: {sorted(collided)}")
    for label, rows in tables.items():
        keys = [row.key for row in rows]
        if len(keys) != len(set(keys)):
            raise FixtureError(f"duplicate key in {label}")


def _validate_memberships(fx: Fixtures) -> None:
    principals = {p.key for p in fx.principals}
    tenants = {t.key for t in fx.tenants}
    markets = {m.key for m in fx.markets}
    if len(set(fx.tenant_market_access)) != len(fx.tenant_market_access):
        raise FixtureError("duplicate tenant_market_access pair")
    for tenant, market in fx.tenant_market_access:
        if tenant not in tenants or market not in markets:
            raise FixtureError(f"tenant_market_access: dangling ({tenant}, {market})")
    pairs = [(m.principal, m.tenant) for m in fx.memberships]
    if len(pairs) != len(set(pairs)):
        raise FixtureError("UNIQUE(principal, tenant) violated by memberships")
    for m in fx.memberships:
        if m.principal not in principals or m.tenant not in tenants:
            raise FixtureError(f"membership {m.key}: dangling reference")
        if m.role not in _ROLES or m.status not in ("active", "revoked"):
            raise FixtureError(f"membership {m.key}: bad role/status")


def _validate_resources(fx: Fixtures) -> None:
    principals = {p.key for p in fx.principals}
    tenants = {t.key for t in fx.tenants}
    markets = {m.key for m in fx.markets}
    projects = {p.key: p for p in fx.projects}
    for p in fx.projects:
        if p.tenant not in tenants or p.market not in markets or p.owner not in principals:
            raise FixtureError(f"project {p.key}: dangling reference")
    for inv in fx.invoices:
        if inv.project not in projects or inv.tenant not in tenants:
            raise FixtureError(f"invoice {inv.key}: dangling reference")
        if projects[inv.project].tenant != inv.tenant:
            raise FixtureError(f"invoice {inv.key}: tenant differs from its project's tenant")
        if inv.amount_minor < 0:
            raise FixtureError(f"invoice {inv.key}: negative amount")
    for c in fx.contacts:
        if c.project not in projects:
            raise FixtureError(f"contact {c.key}: dangling project")
