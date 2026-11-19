"""Helpers shared by the M2 tests.

Independence rule (as in tests/harness.py): expected field sets come from the ORACLE data
(`field_policy.csv`), never from application code. Rows are injected with raw SQL.

UUID storage: M1 stores a UUID as 32 lowercase hex characters on SQLite (`sa.Uuid`). That single
assumption lives in `hexid()`; the PostgreSQL variant of the harness (M5) changes it in one place.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Final

from sqlalchemy import Engine, event, text

from tenantlab.oracle.matrix import ROLE_RANK, Role, load_field_policy
from tests.harness import Lab

MAX_PROJECTS_PER_TENANT: Final = 1000
SIXTY_FIVE_KIB: Final = 65_536


def hexid(value: uuid.UUID) -> str:
    return value.hex


def insert_projects(
    lab: Lab, *, tenant: str, market: str, count: int, owner: str = "alice", status: str = "active"
) -> list[str]:
    """Insert `count` projects; returns their canonical ids in ascending order."""
    ids = sorted(uuid.uuid4() for _ in range(count))
    rows = [
        {"id": hexid(i), "title": f"SENTINEL-TENANT-{tenant} bulk {n}"} for n, i in enumerate(ids)
    ]
    with lab.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO projects (id, tenant_id, market_id, owner_principal_id, title, "
                "status, row_version) SELECT :id, t.id, m.id, p.id, :title, :status, 1 "
                "FROM tenants t, markets m, principals p "
                "WHERE t.slug = :slug AND m.code = :market AND p.email = :email"
            ),
            [
                {
                    **row,
                    "status": status,
                    "slug": lab.fx.tenant(tenant).slug,
                    "market": market,
                    "email": lab.fx.principal(owner).email,
                }
                for row in rows
            ],
        )
    return [str(i) for i in ids]


def insert_contacts(lab: Lab, *, project: str, count: int) -> list[str]:
    ids = sorted(uuid.uuid4() for _ in range(count))
    with lab.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO project_contacts (id, project_id, email_private, phone_private, "
                "public_name) SELECT :id, p.id, :email, :phone, :name FROM projects p "
                "WHERE p.title = :title"
            ),
            [
                {
                    "id": hexid(i),
                    "email": f"SENTINEL-PRIV-EMAIL-X{n}@tenantlab.invalid",
                    "phone": f"SENTINEL-PRIV-PHONE-X{n}",
                    "name": f"Extra Contact {n}",
                    "title": lab.fx.project(project).title,
                }
                for n, i in enumerate(ids)
            ],
        )
    return [str(i) for i in ids]


def insert_audit_rows(lab: Lab, *, tenant: str | None, count: int) -> None:
    with lab.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_events (actor_id, tenant_id, action, resource_type, "
                "resource_id, decision, reason_code, timestamp, correlation_id) "
                "SELECT p.id, (SELECT id FROM tenants WHERE slug = :slug), 'project.write', "
                "'project', NULL, 'deny', 'authz.forbidden', '2026-01-01 00:00:00', :cid "
                "FROM principals p WHERE p.email = :email"
            ),
            [
                {
                    "slug": lab.fx.tenant(tenant).slug if tenant else "no-such-tenant",
                    "email": lab.fx.principal("bob").email,
                    "cid": hexid(uuid.uuid4()),
                }
                for _ in range(count)
            ],
        )


@contextmanager
def count_statements() -> Iterator[list[str]]:
    """Every SQL statement any engine executes inside the block (all threads)."""
    seen: list[str] = []

    def before(conn: Any, cursor: Any, statement: str, *rest: Any) -> None:
        seen.append(statement)

    event.listen(Engine, "before_cursor_execute", before)
    try:
        yield seen
    finally:
        event.remove(Engine, "before_cursor_execute", before)


def oracle_fields(surface: str, role: str) -> set[str]:
    """Field names the oracle allows on `surface` for `role` (floor: read_min_role)."""
    rank = ROLE_RANK[Role(role)]
    return {
        rule.field
        for rule in load_field_policy()
        if surface in rule.surfaces
        and rule.read_min_role is not None
        and rank >= ROLE_RANK[rule.read_min_role]
    }


def oracle_resource_fields(resource: str, surface: str, role: str) -> set[str]:
    rank = ROLE_RANK[Role(role)]
    return {
        rule.field
        for rule in load_field_policy()
        if rule.resource == resource
        and surface in rule.surfaces
        and rule.read_min_role is not None
        and rank >= ROLE_RANK[rule.read_min_role]
    }


def body_routes(lab: Lab) -> dict[str, tuple[str, str, str, str, dict[str, object]]]:
    """name -> (method, path, audit action, audit resource_type, a VALID body)."""
    tenant_a, pa1, bob = lab.fx.tenant("A").id, lab.fx.project("PA1").id, lab.fx.principal("bob").id
    return {
        "create": (
            "POST", f"/v1/tenants/{tenant_a}/projects", "project.create", "tenant",
            {"title": "A new project", "market": "UK"},
        ),
        "patch": (
            "PATCH", f"/v1/projects/{pa1}", "project.write", "project",
            {"title": "Renamed", "row_version": 1},
        ),
        "put": (
            "PUT", f"/v1/tenants/{tenant_a}/members/{bob}", "member.role.write", "membership",
            {"role": "editor", "status": "active", "version": 1},
        ),
    }  # fmt: skip
