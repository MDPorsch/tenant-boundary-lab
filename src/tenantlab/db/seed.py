"""Load the synthetic fixtures (lab/fixtures/fixtures.toml) into an EMPTY database.

* Refuses a non-empty database: a seed must never overwrite or mix with existing data.
* All-or-nothing: one transaction.
* Deterministic: fixed UUIDs (from the fixture file) and a fixed `created_at`.
* The fixtures hold no credential. Tokens are minted by whoever holds the signing key.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tenantlab.db import models
from tenantlab.db.engine import make_engine
from tenantlab.lab.fixtures.loader import Fixtures, load_fixtures

SEED_TIMESTAMP: Final = datetime(2026, 1, 1, tzinfo=UTC)

_SEEDED_TABLES: Final = (
    models.Principal,
    models.Tenant,
    models.Market,
    models.Membership,
    models.TenantMarketAccess,
    models.Project,
    models.Invoice,
    models.ProjectContact,
    models.AuditEvent,
)


class SeedError(RuntimeError):
    """The database is not in a state where seeding is safe."""


def seed_fixtures(database_url: str) -> None:
    """Insert the fixtures. Raises SeedError if any table already contains rows."""
    fx = load_fixtures()
    engine = make_engine(database_url)
    try:
        with Session(engine) as session, session.begin():
            _require_empty(session)
            _insert(session, fx)
    finally:
        engine.dispose()


def _require_empty(session: Session) -> None:
    for model in _SEEDED_TABLES:
        if session.scalar(select(func.count()).select_from(model)):
            raise SeedError(f"refusing to seed: table {model.__tablename__!r} is not empty")


def _insert(session: Session, fx: Fixtures) -> None:
    ids = {
        "principal": {p.key: uuid.UUID(p.id) for p in fx.principals},
        "tenant": {t.key: uuid.UUID(t.id) for t in fx.tenants},
        "market": {m.key: uuid.UUID(m.id) for m in fx.markets},
        "project": {p.key: uuid.UUID(p.id) for p in fx.projects},
    }
    # Flush per dependency tier so foreign keys are satisfied regardless of mapper ordering.
    session.add_all(
        models.Principal(
            id=ids["principal"][p.key],
            email=p.email,
            status=p.status,
            auth_version=p.auth_version,
            created_at=SEED_TIMESTAMP,
        )
        for p in fx.principals
    )
    session.add_all(
        models.Tenant(id=ids["tenant"][t.key], slug=t.slug, state=t.state) for t in fx.tenants
    )
    session.add_all(models.Market(id=ids["market"][m.key], code=m.code) for m in fx.markets)
    session.flush()
    session.add_all(
        models.TenantMarketAccess(tenant_id=ids["tenant"][t], market_id=ids["market"][m])
        for t, m in fx.tenant_market_access
    )
    session.add_all(
        models.Membership(
            id=uuid.UUID(m.id),
            principal_id=ids["principal"][m.principal],
            tenant_id=ids["tenant"][m.tenant],
            role=m.role,
            status=m.status,
            version=m.version,
        )
        for m in fx.memberships
    )
    session.add_all(
        models.Project(
            id=ids["project"][p.key],
            tenant_id=ids["tenant"][p.tenant],
            market_id=ids["market"][p.market],
            owner_principal_id=ids["principal"][p.owner],
            title=p.title,
            status=p.status,
            row_version=p.row_version,
        )
        for p in fx.projects
    )
    session.flush()
    session.add_all(
        models.Invoice(
            id=uuid.UUID(i.id),
            tenant_id=ids["tenant"][i.tenant],
            project_id=ids["project"][i.project],
            amount_minor=i.amount_minor,
            currency=i.currency,
            status=i.status,
        )
        for i in fx.invoices
    )
    session.add_all(
        models.ProjectContact(
            id=uuid.UUID(c.id),
            project_id=ids["project"][c.project],
            email_private=c.email_private,
            phone_private=c.phone_private,
            public_name=c.public_name,
        )
        for c in fx.contacts
    )
    session.flush()
