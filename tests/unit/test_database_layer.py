"""Migrations, constraints, seed and engine behaviour, exercised against a real (SQLite) database.

Foreign keys and CHECK constraints must be ENFORCED, not merely declared (spec s4): every one is
provoked here with exactly one defect, next to a valid control so a broken fixture cannot make a
constraint look enforced.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from tenantlab.auth.tokens import ConfigurationError
from tenantlab.db import models, seed
from tenantlab.db.engine import make_engine
from tenantlab.db.migrate import _downgrade_to_base, upgrade_to_head
from tenantlab.db.models import Base
from tenantlab.lab.fixtures.loader import load_fixtures, parse_fixtures

FX = load_fixtures()
APP_TABLES = {
    "principals",
    "tenants",
    "markets",
    "memberships",
    "tenant_market_access",
    "projects",
    "invoices",
    "project_contacts",
    "audit_events",
}


@pytest.fixture
def url(tmp_path: Path) -> str:
    return f"sqlite+pysqlite:///{tmp_path / 'db.sqlite'}"


@pytest.fixture
def migrated(url: str) -> str:
    upgrade_to_head(url)
    return url


@pytest.fixture
def seeded(migrated: str) -> str:
    seed.seed_fixtures(migrated)
    return migrated


def _uid(key: str) -> uuid.UUID:
    return uuid.UUID(key)


def _dump(connection: Any, table: str) -> list[Any]:
    return list(connection.execute(text(f"SELECT * FROM {table} ORDER BY 1")))  # noqa: S608


def _count(connection: Any, table: str) -> int:
    return int(connection.execute(text(f"SELECT count(*) FROM {table}")).scalar())  # noqa: S608


# ------------------------------------------------------------------------- migrations ----


def test_the_migration_creates_every_table(migrated: str) -> None:
    engine = make_engine(migrated)
    assert set(inspect(engine).get_table_names()) == APP_TABLES | {"alembic_version"}
    engine.dispose()


def test_the_hand_written_migration_and_the_models_agree(migrated: str) -> None:
    """No drift in columns, types, nullability, indexes, uniques or foreign keys. (CHECK
    constraints are not compared by this tool: the tests below provoke each one instead.)"""
    engine = make_engine(migrated)
    with engine.connect() as connection:
        diff = compare_metadata(MigrationContext.configure(connection), Base.metadata)
    engine.dispose()
    assert diff == []


def test_upgrading_twice_is_a_no_op(migrated: str) -> None:
    upgrade_to_head(migrated)  # must not raise or duplicate anything
    engine = make_engine(migrated)
    assert set(inspect(engine).get_table_names()) == APP_TABLES | {"alembic_version"}
    engine.dispose()


def test_downgrade_removes_the_schema_and_upgrade_restores_it(migrated: str) -> None:
    _downgrade_to_base(migrated)
    engine = make_engine(migrated)
    assert set(inspect(engine).get_table_names()) == {"alembic_version"}
    engine.dispose()
    upgrade_to_head(migrated)
    engine = make_engine(migrated)
    assert set(inspect(engine).get_table_names()) >= APP_TABLES
    engine.dispose()


def test_the_declared_indexes_exist(migrated: str) -> None:
    engine = make_engine(migrated)
    names = {
        index["name"]
        for table in ("projects", "invoices", "audit_events", "project_contacts")
        for index in inspect(engine).get_indexes(table)
    }
    engine.dispose()
    assert {
        "ix_projects_tenant_id_id",
        "ix_projects_market_id_status",
        "ix_invoices_tenant_id_id",
        "ix_audit_events_tenant_id_id",
        "ix_project_contacts_project_id",
    } <= names


def test_audit_events_id_is_the_sqlite_rowid_alias(migrated: str) -> None:
    """The harness orders audit rows by rowid; that only means 'insertion order' for an
    INTEGER PRIMARY KEY."""
    engine = make_engine(migrated)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO audit_events (action, resource_type, decision, reason_code, "
                "timestamp, correlation_id) VALUES ('a', 'tenant', 'deny', 'r', "
                "'2026-01-01 00:00:00', :c)"
            ),
            {"c": uuid.uuid4().hex},
        )
        id_value, rowid_value = connection.execute(text("SELECT id, rowid FROM audit_events")).one()
    engine.dispose()
    assert id_value == rowid_value  # compared by position: SQLite names both columns "id"


# --------------------------------------------------------------------- constraints ----

NOW = datetime(2026, 1, 1, tzinfo=UTC)
ALICE, GINA = _uid(FX.principal("alice").id), _uid(FX.principal("gina").id)
TENANT_A, TENANT_B = _uid(FX.tenant("A").id), _uid(FX.tenant("B").id)
MARKET_UK = _uid(next(m.id for m in FX.markets if m.code == "UK"))
PA1 = _uid(FX.project("PA1").id)
GHOST = uuid.uuid4()


def _principal(**o: Any) -> models.Principal:
    base: dict[str, Any] = {
        "id": uuid.uuid4(), "email": f"{uuid.uuid4().hex}@tenantlab.invalid",
        "status": "active", "auth_version": 1, "created_at": NOW,
    }  # fmt: skip
    return models.Principal(**{**base, **o})


def _tenant(**o: Any) -> models.Tenant:
    base: dict[str, Any] = {"id": uuid.uuid4(), "slug": uuid.uuid4().hex[:12], "state": "active"}
    return models.Tenant(**{**base, **o})


def _membership(**o: Any) -> models.Membership:
    base: dict[str, Any] = {
        "id": uuid.uuid4(), "principal_id": GINA, "tenant_id": TENANT_A,
        "role": "viewer", "status": "active", "version": 1,
    }  # fmt: skip
    return models.Membership(**{**base, **o})


def _project(**o: Any) -> models.Project:
    base: dict[str, Any] = {
        "id": uuid.uuid4(), "tenant_id": TENANT_A, "market_id": MARKET_UK,
        "owner_principal_id": ALICE, "title": "t", "status": "draft", "row_version": 1,
    }  # fmt: skip
    return models.Project(**{**base, **o})


def _invoice(**o: Any) -> models.Invoice:
    base: dict[str, Any] = {
        "id": uuid.uuid4(), "tenant_id": TENANT_A, "project_id": PA1,
        "amount_minor": 0, "currency": "GBP", "status": "draft",
    }  # fmt: skip
    return models.Invoice(**{**base, **o})


def _contact(**o: Any) -> models.ProjectContact:
    base: dict[str, Any] = {
        "id": uuid.uuid4(), "project_id": PA1, "email_private": "e", "phone_private": "p",
        "public_name": "n",
    }  # fmt: skip
    return models.ProjectContact(**{**base, **o})


def _audit(**o: Any) -> models.AuditEvent:
    base: dict[str, Any] = {
        "actor_id": ALICE, "tenant_id": TENANT_A, "action": "a", "resource_type": "tenant",
        "resource_id": None, "decision": "deny", "reason_code": "r", "timestamp": NOW,
        "correlation_id": uuid.uuid4(),
    }  # fmt: skip
    return models.AuditEvent(**{**base, **o})


Builder = Callable[[], Any]

VALID: dict[str, Builder] = {
    "principals": _principal,
    "tenants": _tenant,
    "memberships": _membership,
    "projects": _project,
    "invoices": _invoice,
    "project_contacts": _contact,
    "audit_events": _audit,
}

VIOLATIONS: dict[str, Builder] = {
    "principal.status": lambda: _principal(status="banned"),
    "principal.auth_version": lambda: _principal(auth_version=0),
    "principal.email_unique": lambda: _principal(email=FX.principal("alice").email),
    "tenant.state": lambda: _tenant(state="deleted"),
    "tenant.slug_unique": lambda: _tenant(slug=FX.tenant("A").slug),
    "membership.role": lambda: _membership(role="root"),
    "membership.role_case": lambda: _membership(role="Owner"),
    "membership.status": lambda: _membership(status="pending"),
    "membership.version": lambda: _membership(version=0),
    "membership.unique_principal_tenant": lambda: _membership(principal_id=ALICE),
    "membership.fk_principal": lambda: _membership(principal_id=GHOST),
    "membership.fk_tenant": lambda: _membership(tenant_id=GHOST),
    "project.title_empty": lambda: _project(title=""),
    "project.title_121": lambda: _project(title="x" * 121),
    "project.status": lambda: _project(status="deleted"),
    "project.row_version": lambda: _project(row_version=0),
    "project.fk_tenant": lambda: _project(tenant_id=GHOST),
    "project.fk_market": lambda: _project(market_id=GHOST),
    "project.fk_owner": lambda: _project(owner_principal_id=GHOST),
    "invoice.amount_negative": lambda: _invoice(amount_minor=-1),
    "invoice.currency_short": lambda: _invoice(currency="GB"),
    "invoice.currency_long": lambda: _invoice(currency="GBPP"),
    "invoice.status_empty": lambda: _invoice(status=""),
    "invoice.status_long": lambda: _invoice(status="x" * 17),
    "invoice.fk_project": lambda: _invoice(project_id=GHOST),
    "invoice.fk_tenant": lambda: _invoice(tenant_id=GHOST),
    "contact.fk_project": lambda: _contact(project_id=GHOST),
    "audit.resource_type": lambda: _audit(resource_type="secrets"),
    "audit.decision": lambda: _audit(decision="maybe"),
    "audit.fk_actor": lambda: _audit(actor_id=GHOST),
    "audit.fk_tenant": lambda: _audit(tenant_id=GHOST),
}


@pytest.mark.parametrize("table", sorted(VALID))
def test_a_valid_row_is_accepted_so_the_violations_below_are_meaningful(
    seeded: str, table: str
) -> None:
    engine = make_engine(seeded)
    with Session(engine) as session, session.begin():
        session.add(VALID[table]())  # control: must not raise
    engine.dispose()


@pytest.mark.parametrize("name", sorted(VIOLATIONS))
def test_every_check_unique_and_foreign_key_constraint_is_enforced(seeded: str, name: str) -> None:
    engine = make_engine(seeded)
    with pytest.raises(IntegrityError), Session(engine) as session, session.begin():
        session.add(VIOLATIONS[name]())
    engine.dispose()


def test_a_nullable_audit_actor_and_tenant_are_allowed(seeded: str) -> None:
    engine = make_engine(seeded)
    with Session(engine) as session, session.begin():
        session.add(_audit(actor_id=None, tenant_id=None))
    engine.dispose()


# -------------------------------------------------------------------------------- seed ----


def test_the_seed_reproduces_the_fixtures_exactly(seeded: str) -> None:
    engine = make_engine(seeded)
    with Session(engine) as s:
        assert {
            (str(p.id), p.email, p.status, p.auth_version)
            for p in s.scalars(select(models.Principal))
        } == {(p.id, p.email, p.status, p.auth_version) for p in FX.principals}
        assert {(str(t.id), t.slug, t.state) for t in s.scalars(select(models.Tenant))} == {
            (t.id, t.slug, t.state) for t in FX.tenants
        }
        assert {(str(m.id), m.code) for m in s.scalars(select(models.Market))} == {
            (m.id, m.code) for m in FX.markets
        }
        assert {
            (str(m.id), str(m.principal_id), str(m.tenant_id), m.role, m.status, m.version)
            for m in s.scalars(select(models.Membership))
        } == {
            (
                m.id,
                FX.principal(m.principal).id,
                FX.tenant(m.tenant).id,
                m.role,
                m.status,
                m.version,
            )
            for m in FX.memberships
        }
        market_id = {m.key: m.id for m in FX.markets}
        assert {
            (str(a.tenant_id), str(a.market_id))
            for a in s.scalars(select(models.TenantMarketAccess))
        } == {(FX.tenant(t).id, market_id[m]) for t, m in FX.tenant_market_access}
        assert {
            (str(p.id), str(p.tenant_id), str(p.market_id), str(p.owner_principal_id), p.title,
             p.status, p.row_version)
            for p in s.scalars(select(models.Project))
        } == {
            (p.id, FX.tenant(p.tenant).id, market_id[p.market], FX.principal(p.owner).id, p.title,
             p.status, p.row_version)
            for p in FX.projects
        }  # fmt: skip
        assert {
            (str(i.id), str(i.tenant_id), str(i.project_id), i.amount_minor, i.currency, i.status)
            for i in s.scalars(select(models.Invoice))
        } == {
            (i.id, FX.tenant(i.tenant).id, FX.project(i.project).id, i.amount_minor, i.currency,
             i.status)
            for i in FX.invoices
        }  # fmt: skip
        assert {
            (str(c.id), str(c.project_id), c.email_private, c.phone_private, c.public_name)
            for c in s.scalars(select(models.ProjectContact))
        } == {
            (c.id, FX.project(c.project).id, c.email_private, c.phone_private, c.public_name)
            for c in FX.contacts
        }
        assert s.scalar(select(func.count()).select_from(models.AuditEvent)) == 0
        created = {p.created_at for p in s.scalars(select(models.Principal))}
    engine.dispose()
    assert created == {seed.SEED_TIMESTAMP}


def test_the_seed_is_deterministic(tmp_path: Path) -> None:
    dumps = []
    for name in ("one", "two"):
        db_url = f"sqlite+pysqlite:///{tmp_path / f'{name}.sqlite'}"
        upgrade_to_head(db_url)
        seed.seed_fixtures(db_url)
        engine = make_engine(db_url)
        with engine.connect() as c:
            dumps.append({t: _dump(c, t) for t in sorted(APP_TABLES)})
        engine.dispose()
    assert dumps[0] == dumps[1]


def test_the_seed_refuses_a_database_that_already_has_data(seeded: str) -> None:
    engine = make_engine(seeded)
    with engine.connect() as c:
        before = {t: _count(c, t) for t in APP_TABLES}
    with pytest.raises(seed.SeedError, match="not empty"):
        seed.seed_fixtures(seeded)
    with engine.connect() as c:
        after = {t: _count(c, t) for t in APP_TABLES}
    engine.dispose()
    assert before == after


def test_the_seed_refuses_a_database_whose_only_content_is_an_audit_row(migrated: str) -> None:
    engine = make_engine(migrated)
    with Session(engine) as session, session.begin():
        session.add(_audit(actor_id=None, tenant_id=None))
    engine.dispose()
    with pytest.raises(seed.SeedError, match="audit_events"):
        seed.seed_fixtures(migrated)


def test_a_failed_seed_leaves_nothing_behind(
    migrated: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All-or-nothing: a constraint violation in the LAST tier rolls the earlier tiers back."""
    from importlib import resources  # noqa: PLC0415

    text_ = (
        resources.files("tenantlab.lab.fixtures").joinpath("fixtures.toml").read_text("utf-8")
    ).replace('currency = "GBP"', 'currency = "GBPP"')
    monkeypatch.setattr(seed, "load_fixtures", lambda: parse_fixtures(text_))
    with pytest.raises(IntegrityError):
        seed.seed_fixtures(migrated)
    engine = make_engine(migrated)
    with engine.connect() as c:
        assert all(_count(c, t) == 0 for t in APP_TABLES)
    engine.dispose()


# ------------------------------------------------------------------------------ engine ----


def test_foreign_keys_are_switched_on_for_every_sqlite_connection(url: str) -> None:
    engine = make_engine(url)
    for _ in range(3):  # NullPool: a fresh connection each time
        with engine.connect() as c:
            assert c.execute(text("PRAGMA foreign_keys")).scalar() == 1
    engine.dispose()


@pytest.mark.parametrize(
    "bad", ["sqlite://", "sqlite+pysqlite://", "sqlite+pysqlite:///:memory:", "sqlite:///:memory:"]
)
def test_in_memory_sqlite_is_refused(bad: str) -> None:
    with pytest.raises(ConfigurationError, match="in-memory"):
        make_engine(bad)


def test_an_unparsable_url_is_refused_without_echoing_it() -> None:
    secret = "definitely-not-a-url-with-password-hunter2"
    with pytest.raises(ConfigurationError) as caught:
        make_engine(secret)
    assert "hunter2" not in str(caught.value)


def test_naive_datetimes_are_refused_and_aware_ones_round_trip_as_utc(migrated: str) -> None:
    engine = make_engine(migrated)
    with pytest.raises(StatementError, match="naive"), Session(engine) as s, s.begin():
        s.add(_audit(actor_id=None, tenant_id=None, timestamp=datetime(2026, 1, 1)))
    plus_five = timezone(timedelta(hours=5))
    when = datetime(2026, 3, 4, 10, 0, tzinfo=plus_five)
    with Session(engine) as s, s.begin():
        s.add(_audit(actor_id=None, tenant_id=None, timestamp=when))
    with Session(engine) as s:
        stored = s.scalars(select(models.AuditEvent.timestamp)).one()
    engine.dispose()
    assert stored == when
    assert stored.utcoffset() == timedelta(0)
    assert stored.tzinfo is not None


def test_a_server_database_gets_a_pooled_engine_with_liveness_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-SQLite URLs keep SQLAlchemy's default pool and add pre-ping (no driver needed here)."""
    from tenantlab.db import engine as engine_module  # noqa: PLC0415

    seen: dict[str, Any] = {}

    def fake_create_engine(url: Any, **kwargs: Any) -> str:
        seen.update(kwargs, backend=url.get_backend_name())
        return "engine"

    monkeypatch.setattr(engine_module, "create_engine", fake_create_engine)
    assert make_engine("postgresql+psycopg://user:pw@db.invalid/app") == "engine"
    assert seen == {"pool_pre_ping": True, "backend": "postgresql"}


def test_the_utc_column_type_handles_null_and_aware_values() -> None:
    from tenantlab.db.engine import UtcDateTime  # noqa: PLC0415

    column = UtcDateTime()
    assert column.process_bind_param(None, None) is None
    assert column.process_result_value(None, None) is None
    plus_five = datetime(2026, 1, 1, 5, 0, tzinfo=timezone(timedelta(hours=5)))
    assert column.process_result_value(plus_five, None) == datetime(2026, 1, 1, tzinfo=UTC)
    assert column.process_result_value(datetime(2026, 1, 1), None).tzinfo is UTC  # type: ignore[union-attr]
