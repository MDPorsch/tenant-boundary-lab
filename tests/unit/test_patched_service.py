"""The write statements re-check authority BY THEMSELVES (decision D-35, closing L-16).

The handlers also pre-check, so the HTTP tests cannot tell "the statement refused" from "the
pre-check refused first". Here the service functions are called directly, with the state changed
underneath them exactly as a race would: each defect must make the statement change NO row, and a
valid control must change exactly one.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from tenantlab.auth.policy import CAPABILITIES
from tenantlab.db.engine import make_engine
from tenantlab.db.migrate import upgrade_to_head
from tenantlab.db.seed import seed_fixtures
from tenantlab.lab.fixtures.loader import load_fixtures
from tenantlab.lab.patched import service
from tests.support_m2 import hexid

FX = load_fixtures()
EDITORS = sorted(r.value for r in CAPABILITIES["project.write"])
OWNER_ONLY = sorted(r.value for r in CAPABILITIES["member.role.write"])


def _id(key: str) -> uuid.UUID:
    return uuid.UUID(key)


def _market(code: str) -> uuid.UUID:
    return _id(next(m.id for m in FX.markets if m.code == code))


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Session]:
    url = f"sqlite+pysqlite:///{tmp_path / 'svc.sqlite'}"
    upgrade_to_head(url)
    seed_fixtures(url)
    engine = make_engine(url)
    with Session(engine) as session:
        yield session
    engine.dispose()


def _sql(db: Session, statement: str, **params: Any) -> None:
    db.execute(text(statement), params)


def _count(db: Session, table: str) -> int:
    return int(db.scalar(text(f"SELECT count(*) FROM {table}")))  # noqa: S608 - constant names


# ------------------------------------------------------------------------ create_project ----
def _create(
    db: Session, *, actor: str = "dave", tenant: str = "A", market: str = "UK",
    roles: list[str] | None = None,
) -> uuid.UUID | None:  # fmt: skip
    return service.create_project(
        db,
        tenant_id=_id(FX.tenant(tenant).id),
        actor_id=_id(FX.principal(actor).id),
        market_id=_market(market),
        title="Created by the unit test",
        roles=roles or sorted(r.value for r in CAPABILITIES["project.create"]),
    )


def test_create_control_inserts_exactly_one_row(db: Session) -> None:
    before = _count(db, "projects")
    new_id = _create(db)
    assert new_id is not None
    assert _count(db, "projects") == before + 1


CREATE_DEFECTS: dict[str, Callable[[Session], None]] = {
    "membership_revoked": lambda db: _sql(
        db, "UPDATE memberships SET status = 'revoked' WHERE principal_id = :p",
        p=hexid(_id(FX.principal("dave").id)),
    ),
    "role_downgraded_to_viewer": lambda db: _sql(
        db, "UPDATE memberships SET role = 'viewer' WHERE principal_id = :p AND tenant_id = :t",
        p=hexid(_id(FX.principal("dave").id)), t=hexid(_id(FX.tenant("A").id)),
    ),
    "principal_disabled": lambda db: _sql(
        db, "UPDATE principals SET status = 'disabled' WHERE id = :p",
        p=hexid(_id(FX.principal("dave").id)),
    ),
    "tenant_suspended": lambda db: _sql(
        db, "UPDATE tenants SET state = 'suspended' WHERE id = :t", t=hexid(_id(FX.tenant("A").id))
    ),
    "market_access_removed": lambda db: _sql(
        db, "DELETE FROM tenant_market_access WHERE tenant_id = :t AND market_id = :m",
        t=hexid(_id(FX.tenant("A").id)), m=hexid(_market("UK")),
    ),
}  # fmt: skip


@pytest.mark.parametrize("defect", sorted(CREATE_DEFECTS))
def test_create_writes_nothing_when_authority_changed_underneath_it(
    db: Session, defect: str
) -> None:
    CREATE_DEFECTS[defect](db)
    before = _count(db, "projects")
    assert _create(db) is None
    assert _count(db, "projects") == before


def test_create_writes_nothing_for_an_actor_who_was_never_a_member(db: Session) -> None:
    before = _count(db, "projects")
    assert _create(db, actor="carla") is None  # carla belongs to B only
    assert _count(db, "projects") == before


def test_create_writes_nothing_in_a_market_the_tenant_lacks(db: Session) -> None:
    assert _create(db, market="US") is None


def test_create_stops_at_the_quota_atomically(db: Session) -> None:
    rows = [
        {"id": hexid(uuid.uuid4())}
        for _ in range(
            service.MAX_PROJECTS_PER_TENANT - service.count_projects(db, _id(FX.tenant("A").id))
        )
    ]
    db.execute(
        text(
            "INSERT INTO projects (id, tenant_id, market_id, owner_principal_id, title, status, "
            "row_version) SELECT :id, t.id, m.id, p.id, 'fill', 'active', 1 FROM tenants t, "
            "markets m, principals p WHERE t.slug = 'tenant-a' AND m.code = 'UK' AND "
            "p.email = 'alice@tenantlab.invalid'"
        ),
        rows,
    )
    assert service.count_projects(db, _id(FX.tenant("A").id)) == service.MAX_PROJECTS_PER_TENANT
    assert _create(db) is None
    assert service.count_projects(db, _id(FX.tenant("A").id)) == service.MAX_PROJECTS_PER_TENANT


# ------------------------------------------------------------------------ update_project ----
def _update(
    db: Session, *, actor: str = "dave", version: int = 1, tenant: str = "A",
    project: str = "PA1", title: str | None = "Updated by the unit test", status: str | None = None,
) -> bool:  # fmt: skip
    return service.update_project(
        db, project_id=_id(FX.project(project).id), tenant_id=_id(FX.tenant(tenant).id),
        actor_id=_id(FX.principal(actor).id), row_version=version, title=title, status=status,
        roles=EDITORS,
    )  # fmt: skip


def _title(db: Session) -> tuple[str, int]:
    row = db.execute(
        text("SELECT title, row_version FROM projects WHERE id = :i"),
        {"i": hexid(_id(FX.project("PA1").id))},
    ).one()
    return row.title, row.row_version


def test_update_control_changes_exactly_the_requested_fields(db: Session) -> None:
    assert _update(db, status="archived") is True
    assert _title(db) == ("Updated by the unit test", 2)


UPDATE_DEFECTS: dict[str, Callable[[Session], None]] = {
    **CREATE_DEFECTS,
    "market_access_removed_for_the_projects_market": CREATE_DEFECTS["market_access_removed"],
    "row_version_moved_on": lambda db: _sql(
        db, "UPDATE projects SET row_version = 2 WHERE id = :i", i=hexid(_id(FX.project("PA1").id))
    ),
}


@pytest.mark.parametrize("defect", sorted(UPDATE_DEFECTS))
def test_update_changes_nothing_when_authority_or_version_changed_underneath_it(
    db: Session, defect: str
) -> None:
    UPDATE_DEFECTS[defect](db)
    stored_before = _title(db)
    assert _update(db) is False
    assert _title(db) == stored_before


@pytest.mark.parametrize(
    ("actor", "tenant", "project"),
    [
        ("bob", "A", "PA1"),
        ("carla", "A", "PA1"),
        ("dave", "B", "PA1"),
        ("alice", "B", "PB1"),
        ("alice", "A", "PB1"),  # an owner of A, naming tenant A, aiming at tenant B's project
        ("carla", "B", "PA1"),  # an admin of B, naming tenant B, aiming at tenant A's project
    ],
    ids=[
        "viewer",
        "other_tenant_member",
        "wrong_tenant_in_the_call",
        "member_of_another_tenant",
        "owner_of_A_aiming_at_a_B_project",
        "admin_of_B_aiming_at_an_A_project",
    ],
)
def test_update_changes_nothing_for_the_wrong_actor_or_tenant(
    db: Session, actor: str, tenant: str, project: str
) -> None:
    before = _title(db)
    assert _update(db, actor=actor, tenant=tenant, project=project) is False
    assert _title(db) == before


def test_update_cannot_move_a_project_between_tenants_or_change_its_owner(db: Session) -> None:
    """The statement's SET list is fixed: only title, status and the version counter."""
    assert _update(db, title="x", status="draft") is True
    row = db.execute(
        text("SELECT tenant_id, market_id, owner_principal_id FROM projects WHERE id = :i"),
        {"i": hexid(_id(FX.project("PA1").id))},
    ).one()
    assert row.tenant_id == hexid(_id(FX.tenant("A").id))
    assert row.owner_principal_id == hexid(_id(FX.principal("frank").id))


# ---------------------------------------------------------------------- update_membership ----
def _put(
    db: Session, *, actor: str = "alice", target: str = "bob", version: int = 1,
    role: str = "editor", status: str = "active", tenant: str = "A",
) -> bool:  # fmt: skip
    return service.update_membership(
        db, tenant_id=_id(FX.tenant(tenant).id), target_id=_id(FX.principal(target).id),
        actor_id=_id(FX.principal(actor).id), version=version, role=role, status=status,
        roles=OWNER_ONLY,
    )  # fmt: skip


def _member(db: Session, principal: str, tenant: str = "A") -> tuple[str, str, int]:
    row = db.execute(
        text(
            "SELECT role, status, version FROM memberships "
            "WHERE principal_id = :p AND tenant_id = :t"
        ),
        {"p": hexid(_id(FX.principal(principal).id)), "t": hexid(_id(FX.tenant(tenant).id))},
    ).one()
    return row.role, row.status, row.version


def test_membership_control_changes_one_row_and_bumps_the_version(db: Session) -> None:
    assert _put(db) is True
    assert _member(db, "bob") == ("editor", "active", 2)
    assert _member(db, "dave") == ("editor", "active", 1)  # nobody else was touched


@pytest.mark.parametrize(
    "defect",
    ["actor_membership_revoked", "actor_demoted", "actor_disabled", "tenant_suspended", "stale"],
)
def test_membership_change_is_refused_when_authority_changed_underneath_it(
    db: Session, defect: str
) -> None:
    alice, tenant = hexid(_id(FX.principal("alice").id)), hexid(_id(FX.tenant("A").id))
    {
        "actor_membership_revoked": lambda: _sql(
            db, "UPDATE memberships SET status = 'revoked' WHERE principal_id = :p", p=alice
        ),
        "actor_demoted": lambda: _sql(
            db, "UPDATE memberships SET role = 'admin' WHERE principal_id = :p", p=alice
        ),
        "actor_disabled": lambda: _sql(
            db, "UPDATE principals SET status = 'disabled' WHERE id = :p", p=alice
        ),
        "tenant_suspended": lambda: _sql(
            db, "UPDATE tenants SET state = 'suspended' WHERE id = :t", t=tenant
        ),
        "stale": lambda: _sql(
            db,
            "UPDATE memberships SET version = 5 WHERE principal_id = :p",
            p=hexid(_id(FX.principal("bob").id)),
        ),
    }[defect]()
    before = _member(db, "bob")
    assert _put(db) is False
    assert _member(db, "bob") == before


@pytest.mark.parametrize("actor", ["bob", "dave", "carla"])
def test_only_an_owner_of_the_tenant_may_change_a_membership(db: Session, actor: str) -> None:
    before = _member(db, "bob")
    assert _put(db, actor=actor) is False
    assert _member(db, "bob") == before


def test_the_last_active_owner_cannot_be_removed_by_the_statement_itself(db: Session) -> None:
    for role, status in (("admin", "active"), ("viewer", "active"), ("owner", "revoked")):
        assert _put(db, target="alice", role=role, status=status) is False
        assert _member(db, "alice") == ("owner", "active", 1)


def test_an_owner_may_step_down_when_another_active_owner_exists(db: Session) -> None:
    _sql(
        db, "UPDATE memberships SET role = 'owner' WHERE principal_id = :p AND tenant_id = :t",
        p=hexid(_id(FX.principal("dave").id)), t=hexid(_id(FX.tenant("A").id)),
    )  # fmt: skip
    assert _put(db, target="alice", role="admin") is True
    assert _put(db, actor="dave", target="dave", role="viewer") is False  # now dave is the last


def test_a_revoked_owner_does_not_count_as_the_other_owner(db: Session) -> None:
    _sql(
        db, "UPDATE memberships SET role = 'owner', status = 'revoked' "
        "WHERE principal_id = :p AND tenant_id = :t",
        p=hexid(_id(FX.principal("dave").id)), t=hexid(_id(FX.tenant("A").id)),
    )  # fmt: skip
    assert _put(db, target="alice", role="admin") is False


def test_a_no_op_change_by_the_sole_owner_is_allowed(db: Session) -> None:
    assert _put(db, target="alice", role="owner", status="active") is True
    assert _member(db, "alice") == ("owner", "active", 2)


def test_demoting_a_non_owner_never_trips_the_owner_rule(db: Session) -> None:
    assert _put(db, target="dave", role="viewer") is True


def test_a_membership_in_another_tenant_cannot_be_reached_through_this_tenant(db: Session) -> None:
    before = _member(db, "carla", "B")
    assert _put(db, target="carla") is False  # carla has no membership in A
    assert _member(db, "carla", "B") == before


# -------------------------------------------------------------------------------- reads ----
def test_looking_up_an_id_that_does_not_exist_returns_none(db: Session) -> None:
    ghost = _id(FX.never_seeded["project"])
    assert service.get_project(db, ghost) is None
    assert service.get_invoice(db, _id(FX.never_seeded["invoice"])) is None
    assert service.project_version(db, ghost) is None
    assert (
        service.get_membership(
            db, tenant_id=_id(FX.tenant("A").id), principal_id=_id(FX.never_seeded["principal"])
        )
        is None
    )


def test_a_hidden_market_project_is_not_listed_nor_counted(db: Session) -> None:
    items, more, total = service.list_projects(
        db, tenant_id=_id(FX.tenant("A").id), limit=25, after=None
    )
    assert [i.id for i in items] == [_id(FX.project("PA1").id)]
    assert (more, total) == (False, 1)


def test_audit_is_filtered_by_tenant_and_newest_first(db: Session) -> None:
    db.execute(
        text(
            "INSERT INTO audit_events (tenant_id, action, resource_type, decision, reason_code, "
            "timestamp, correlation_id) VALUES (:t, 'a', 'tenant', 'deny', 'r', "
            "'2026-01-01 00:00:00', :c)"
        ),
        [
            {"t": t, "c": hexid(uuid.uuid4())}
            for t in (hexid(_id(FX.tenant("A").id)),) * 3 + (None, hexid(_id(FX.tenant("B").id)))
        ],  # type: ignore[misc]
    )
    items, more, total = service.list_audit(
        db, tenant_id=_id(FX.tenant("A").id), limit=2, before=None
    )
    assert [i.id for i in items] == sorted((i.id for i in items), reverse=True)
    assert (len(items), more, total) == (2, True, 3)
    assert all(i.tenant_id == _id(FX.tenant("A").id) for i in items)
