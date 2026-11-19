"""Relational model (spec s4, docs/architecture.md s4).

Constraint names follow a naming convention so migrations are deterministic. The initial migration
(migrations/versions/0001_initial_schema.py) is written out by hand; a test compares it with this
metadata so the two cannot drift. CHECK constraints are NOT compared by that tool, so a separate
test exercises each one against a migrated database.

Project/invoice tenant coherence is deliberately NOT a composite foreign key: TL-07 (M2) must be
able to inject an incoherent row to prove the service layer still refuses it.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from tenantlab.db.engine import UtcDateTime

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Principal(Base):
    __tablename__ = "principals"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'disabled')", name="status"),
        CheckConstraint("auth_version >= 1", name="auth_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)  # not an authorization key
    status: Mapped[str] = mapped_column(String(16))
    auth_version: Mapped[int] = mapped_column(Integer, server_default="1")  # reserved (L-10)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (CheckConstraint("state IN ('active', 'suspended')", name="state"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(63), unique=True)
    state: Mapped[str] = mapped_column(String(16))


class Market(Base):
    __tablename__ = "markets"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(16), unique=True)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("principal_id", "tenant_id"),
        CheckConstraint("role IN ('owner', 'admin', 'editor', 'viewer')", name="role"),
        CheckConstraint("status IN ('active', 'revoked')", name="status"),
        CheckConstraint("version >= 1", name="version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    principal_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("principals.id"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    role: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    version: Mapped[int] = mapped_column(Integer)


class TenantMarketAccess(Base):
    __tablename__ = "tenant_market_access"

    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    market_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("markets.id"), primary_key=True)


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint("length(title) BETWEEN 1 AND 120", name="title_length"),
        CheckConstraint("status IN ('draft', 'active', 'archived')", name="status"),
        CheckConstraint("row_version >= 1", name="row_version"),
        Index("ix_projects_tenant_id_id", "tenant_id", "id"),
        Index("ix_projects_market_id_status", "market_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    market_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("markets.id"))
    # Informational only (D-04): ownership of a row never grants a right.
    owner_principal_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("principals.id"))
    title: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16))
    row_version: Mapped[int] = mapped_column(Integer)


class Invoice(Base):
    __tablename__ = "invoices"
    __table_args__ = (
        CheckConstraint("amount_minor >= 0", name="amount_minor"),
        CheckConstraint("length(currency) = 3", name="currency_length"),
        CheckConstraint("length(status) BETWEEN 1 AND 16", name="status_length"),
        Index("ix_invoices_tenant_id_id", "tenant_id", "id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    amount_minor: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3))
    status: Mapped[str] = mapped_column(String(16))  # value set is defined by M2


class ProjectContact(Base):
    __tablename__ = "project_contacts"
    __table_args__ = (Index("ix_project_contacts_project_id", "project_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    email_private: Mapped[str] = mapped_column(String(254))
    phone_private: Mapped[str] = mapped_column(String(64))
    public_name: Mapped[str] = mapped_column(String(120))


class AuditEvent(Base):
    """Append-only by convention: no code path updates or deletes a row (see LIMITATIONS)."""

    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "resource_type IN ('tenant', 'project', 'invoice', 'contact', 'membership', 'audit')",
            name="resource_type",
        ),
        CheckConstraint("decision IN ('allow', 'deny')", name="decision"),
        Index("ix_audit_events_tenant_id_id", "tenant_id", "id"),
    )

    # BigInteger on PostgreSQL; plain INTEGER PRIMARY KEY on SQLite so it is the rowid alias.
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("principals.id"))
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id"))
    action: Mapped[str] = mapped_column(String(64))  # an oracle operation id, never user input
    resource_type: Mapped[str] = mapped_column(String(16))
    resource_id: Mapped[uuid.UUID | None] = mapped_column()  # no FK: may name nothing that exists
    decision: Mapped[str] = mapped_column(String(8))
    reason_code: Mapped[str] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(UtcDateTime)
    correlation_id: Mapped[uuid.UUID] = mapped_column()
