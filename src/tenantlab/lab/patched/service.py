"""The patched domain operations: database access for the data-bearing routes.

Two rules shape this module:

* **Reads are bounded and N+1-free.** One statement per page, one for the total, one for embedded
  contacts: the statement count does not grow with the data (TL-10 measures it).
* **Writes re-check authority inside the write statement** (D-35). The UPDATE/INSERT itself carries
  the principal, membership, role, tenant-state, market, quota and version predicates, so a
  revocation that lands between the gates and the write cannot be overridden. A write that changes
  no row returns False; the caller re-runs the gates to name the true reason.

This module knows nothing about HTTP, tokens or audit rows.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import (
    ColumnElement,
    CursorResult,
    Integer,
    String,
    Uuid,
    and_,
    exists,
    false,
    func,
    insert,
    literal,
    not_,
    or_,
    select,
    true,
    update,
)
from sqlalchemy.engine import Result
from sqlalchemy.orm import Session, aliased

from tenantlab.db.models import (
    AuditEvent,
    Invoice,
    Market,
    Membership,
    Principal,
    Project,
    ProjectContact,
    Tenant,
    TenantMarketAccess,
)
from tenantlab.lab.patched.schemas import (
    AuditItem,
    ContactPrivate,
    ContactPublic,
    InvoiceDetail,
    ProjectListItem,
)

MAX_PROJECTS_PER_TENANT: Final = 1000
MAX_EMBEDDED_CONTACTS: Final = 100


@dataclass(frozen=True, slots=True)
class ProjectRecord:
    item: ProjectListItem
    owner_principal_id: uuid.UUID
    contacts: list[ContactPublic]


@dataclass(frozen=True, slots=True)
class MembershipRecord:
    role: str
    status: str
    version: int


def _rowcount(result: Result[Any]) -> int:
    """Rows a statement changed. A driver that does not know (-1) is an error, never "zero rows":
    on PostgreSQL an INSERT ... SELECT reports -1 through psycopg 3 and SQLAlchemy 2.1 (found by
    running the suite on PostgreSQL, M5), and reading that as "nothing was written" made every
    project creation fail closed. Statements whose outcome matters use RETURNING instead."""
    assert isinstance(result, CursorResult)  # noqa: S101 - narrowing for the type checker
    count = int(result.rowcount)
    if count < 0:
        raise RuntimeError("the database driver did not report how many rows the statement changed")
    return count


def _readable_projects(tenant_id: uuid.UUID) -> ColumnElement[bool]:
    """A project is readable if its market is one its tenant may use (gate 5)."""
    return and_(
        Project.tenant_id == tenant_id,
        exists().where(
            TenantMarketAccess.tenant_id == Project.tenant_id,
            TenantMarketAccess.market_id == Project.market_id,
        ),
    )


def _actor_may(
    actor_id: uuid.UUID, tenant_id: uuid.UUID, roles: Sequence[str]
) -> ColumnElement[bool]:
    """The actor is active, the tenant is active, and the actor holds an active membership whose
    role is one of `roles`: evaluated by the database inside the write."""
    return and_(
        exists().where(Principal.id == actor_id, Principal.status == "active"),
        exists().where(Tenant.id == tenant_id, Tenant.state == "active"),
        exists().where(
            Membership.principal_id == actor_id,
            Membership.tenant_id == tenant_id,
            Membership.status == "active",
            Membership.role.in_(list(roles)),
        ),
    )


def _lock_authority(
    db: Session,
    *,
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID,
    exclusive: bool,
    market_id: uuid.UUID | None = None,
) -> bool:
    """Lock the rows a write's authority rests on, in ONE fixed order, until the transaction ends.

    The in-statement predicates (`_actor_may`) decide against the statement's snapshot, so two
    transactions can each pass them and then both commit (write skew), and a revocation can commit
    while a write that relies on the old authority is still in flight (D-56). Locks order those:

    * the tenant row: `FOR UPDATE` when the write must be serialised per tenant (a role change and
      its last-owner rule, a create and its quota), `FOR SHARE` otherwise (it also blocks a
      suspension until the write has committed);
    * the actor's principal row and her membership row `FOR SHARE` (a disable, a revocation or a
      downgrade has to wait for the write);
    * the market-access row `FOR SHARE` when the write depends on a market.

    The order (tenant, principal, membership, market access) never changes, so two writers cannot
    deadlock. SQLite ignores `FOR UPDATE`/`FOR SHARE` (it already serialises writers); the same
    predicates inside the write statement still apply. Returns False when a row is missing: the
    caller refuses and re-runs the gates to name the reason.
    """
    tenant = db.execute(
        select(Tenant.id).where(Tenant.id == tenant_id).with_for_update(read=not exclusive)
    ).first()
    principal = db.execute(
        select(Principal.id).where(Principal.id == actor_id).with_for_update(read=True)
    ).first()
    membership = db.execute(
        select(Membership.principal_id)
        .where(Membership.principal_id == actor_id, Membership.tenant_id == tenant_id)
        .with_for_update(read=True)
    ).first()
    if tenant is None or principal is None or membership is None:
        return False
    if market_id is None:
        return True
    access = db.execute(
        select(TenantMarketAccess.tenant_id)
        .where(TenantMarketAccess.tenant_id == tenant_id, TenantMarketAccess.market_id == market_id)
        .with_for_update(read=True)
    ).first()
    return access is not None


# ------------------------------------------------------------------------------- reads ----
def list_projects(
    db: Session, *, tenant_id: uuid.UUID, limit: int, after: uuid.UUID | None
) -> tuple[list[ProjectListItem], bool, int]:
    query = (
        select(
            Project.id, Project.tenant_id, Market.code, Project.title, Project.status,
            Project.row_version,
        )
        .join(Market, Market.id == Project.market_id)
        .where(_readable_projects(tenant_id))
    )  # fmt: skip
    if after is not None:
        query = query.where(Project.id > after)
    rows = db.execute(query.order_by(Project.id).limit(limit + 1)).all()
    total = db.scalar(
        select(func.count()).select_from(Project).where(_readable_projects(tenant_id))
    )
    items = [
        ProjectListItem(
            id=r.id, tenant_id=r.tenant_id, market=r.code, title=r.title, status=r.status,
            row_version=r.row_version,
        )
        for r in rows[:limit]
    ]  # fmt: skip
    return items, len(rows) > limit, int(total or 0)


def get_project(db: Session, project_id: uuid.UUID) -> ProjectRecord | None:
    row = db.execute(
        select(
            Project.id, Project.tenant_id, Market.code, Project.title, Project.status,
            Project.row_version, Project.owner_principal_id,
        )
        .join(Market, Market.id == Project.market_id)
        .where(Project.id == project_id)
    ).one_or_none()  # fmt: skip
    if row is None:
        return None
    contacts = db.execute(
        select(ProjectContact.id, ProjectContact.public_name)
        .where(ProjectContact.project_id == project_id)
        .order_by(ProjectContact.id)
        .limit(MAX_EMBEDDED_CONTACTS)
    ).all()
    return ProjectRecord(
        item=ProjectListItem(
            id=row.id, tenant_id=row.tenant_id, market=row.code, title=row.title,
            status=row.status, row_version=row.row_version,
        ),
        owner_principal_id=row.owner_principal_id,
        contacts=[ContactPublic(id=c.id, public_name=c.public_name) for c in contacts],
    )  # fmt: skip


def list_private_contacts(
    db: Session, *, project_id: uuid.UUID, limit: int, after: uuid.UUID | None
) -> tuple[list[ContactPrivate], bool, int]:
    query = select(
        ProjectContact.id, ProjectContact.public_name, ProjectContact.email_private,
        ProjectContact.phone_private,
    ).where(ProjectContact.project_id == project_id)  # fmt: skip
    if after is not None:
        query = query.where(ProjectContact.id > after)
    rows = db.execute(query.order_by(ProjectContact.id).limit(limit + 1)).all()
    total = db.scalar(
        select(func.count())
        .select_from(ProjectContact)
        .where(ProjectContact.project_id == project_id)
    )
    items = [
        ContactPrivate(
            id=r.id, public_name=r.public_name, email_private=r.email_private,
            phone_private=r.phone_private,
        )
        for r in rows[:limit]
    ]  # fmt: skip
    return items, len(rows) > limit, int(total or 0)


def get_invoice(db: Session, invoice_id: uuid.UUID) -> InvoiceDetail | None:
    row = db.execute(
        select(
            Invoice.id, Invoice.tenant_id, Invoice.project_id, Invoice.amount_minor,
            Invoice.currency, Invoice.status,
        ).where(Invoice.id == invoice_id)
    ).one_or_none()  # fmt: skip
    if row is None:
        return None
    return InvoiceDetail(
        id=row.id, tenant_id=row.tenant_id, project_id=row.project_id,
        amount_minor=row.amount_minor, currency=row.currency, status=row.status,
    )  # fmt: skip


def list_audit(
    db: Session, *, tenant_id: uuid.UUID, limit: int, before: int | None
) -> tuple[list[AuditItem], bool, int]:
    """Newest first. Only rows whose tenant_id equals the path tenant: rows with a NULL tenant
    (denials for non-members) and other tenants' rows are never returned."""
    query = select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
    if before is not None:
        query = query.where(AuditEvent.id < before)
    rows = db.scalars(query.order_by(AuditEvent.id.desc()).limit(limit + 1)).all()
    total = db.scalar(
        select(func.count()).select_from(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
    )
    items = [
        AuditItem(
            id=r.id, actor_id=r.actor_id, tenant_id=r.tenant_id, action=r.action,
            resource_type=r.resource_type, resource_id=r.resource_id, decision=r.decision,
            reason_code=r.reason_code, timestamp=r.timestamp, correlation_id=r.correlation_id,
        )
        for r in rows[:limit]
    ]  # fmt: skip
    return items, len(rows) > limit, int(total or 0)


def permitted_market(db: Session, *, tenant_id: uuid.UUID, code: str) -> uuid.UUID | None:
    """The market id for `code` IF the tenant may use it; None for both 'not permitted' and
    'does not exist' so the answer cannot map the market catalogue (D-31)."""
    return db.scalar(
        select(Market.id)
        .join(TenantMarketAccess, TenantMarketAccess.market_id == Market.id)
        .where(TenantMarketAccess.tenant_id == tenant_id, Market.code == code)
    )


def count_projects(db: Session, tenant_id: uuid.UUID) -> int:
    """Every project of the tenant, hidden-market ones included (D-32)."""
    return int(
        db.scalar(select(func.count()).select_from(Project).where(Project.tenant_id == tenant_id))
        or 0
    )


def project_version(db: Session, project_id: uuid.UUID) -> int | None:
    return db.scalar(select(Project.row_version).where(Project.id == project_id))


def get_membership(
    db: Session, *, tenant_id: uuid.UUID, principal_id: uuid.UUID
) -> MembershipRecord | None:
    row = db.execute(
        select(Membership.role, Membership.status, Membership.version).where(
            Membership.tenant_id == tenant_id, Membership.principal_id == principal_id
        )
    ).one_or_none()
    return None if row is None else MembershipRecord(row.role, row.status, row.version)


def other_active_owner_exists(db: Session, *, tenant_id: uuid.UUID, excluding: uuid.UUID) -> bool:
    return bool(
        db.scalar(
            select(
                exists().where(
                    Membership.tenant_id == tenant_id,
                    Membership.role == "owner",
                    Membership.status == "active",
                    Membership.principal_id != excluding,
                )
            )
        )
    )


# ------------------------------------------------------------------------------ writes ----
def create_project(  # noqa: PLR0913 - every argument is a distinct fact the statement re-checks
    db: Session,
    *,
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID,
    market_id: uuid.UUID,
    title: str,
    roles: Sequence[str],
) -> uuid.UUID | None:
    """INSERT ... SELECT ... WHERE <authority, market, quota>. Returns the new id, or None when
    the database found any predicate false (nothing is written)."""
    if not _lock_authority(
        db, tenant_id=tenant_id, actor_id=actor_id, exclusive=True, market_id=market_id
    ):
        return None
    new_id = uuid.uuid4()
    under_quota = (
        select(func.count()).select_from(Project).where(Project.tenant_id == tenant_id)
    ).scalar_subquery() < MAX_PROJECTS_PER_TENANT
    market_permitted = exists().where(
        TenantMarketAccess.tenant_id == tenant_id, TenantMarketAccess.market_id == market_id
    )
    source = select(
        literal(new_id, Uuid()), literal(tenant_id, Uuid()), literal(market_id, Uuid()),
        literal(actor_id, Uuid()), literal(title, String()), literal("draft", String()),
        literal(1, Integer()),
    ).where(_actor_may(actor_id, tenant_id, roles), market_permitted, under_quota)  # fmt: skip
    result = db.execute(
        insert(Project)
        .from_select(
            [
                Project.id,
                Project.tenant_id,
                Project.market_id,
                Project.owner_principal_id,
                Project.title,
                Project.status,
                Project.row_version,
            ],
            source,
        )
        .returning(Project.id)  # not rowcount: see _rowcount
    )
    return new_id if result.scalar_one_or_none() is not None else None


def update_project(  # noqa: PLR0913
    db: Session,
    *,
    project_id: uuid.UUID,
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID,
    row_version: int,
    title: str | None,
    status: str | None,
    roles: Sequence[str],
) -> bool:
    project_market = db.scalar(select(Project.market_id).where(Project.id == project_id))
    if project_market is None or not _lock_authority(
        db, tenant_id=tenant_id, actor_id=actor_id, exclusive=False, market_id=project_market
    ):
        return False
    values: dict[str, Any] = {"row_version": Project.row_version + 1}
    if title is not None:
        values["title"] = title
    if status is not None:
        values["status"] = status
    statement = (
        update(Project)
        .where(
            Project.id == project_id,
            Project.tenant_id == tenant_id,
            Project.row_version == row_version,
            _actor_may(actor_id, tenant_id, roles),
            exists().where(
                TenantMarketAccess.tenant_id == Project.tenant_id,
                TenantMarketAccess.market_id == Project.market_id,
            ),
        )
        .values(**values)
    )
    result = db.execute(statement, execution_options={"synchronize_session": False})
    return _rowcount(result) == 1


def update_membership(  # noqa: PLR0913
    db: Session,
    *,
    tenant_id: uuid.UUID,
    target_id: uuid.UUID,
    actor_id: uuid.UUID,
    version: int,
    role: str,
    status: str,
    roles: Sequence[str],
) -> bool:
    """Compare-and-set on `version`, with the last-owner invariant evaluated by the database: the
    change is refused unless the target is not currently an active owner, or stays one, or another
    active owner exists."""
    if not _lock_authority(db, tenant_id=tenant_id, actor_id=actor_id, exclusive=True):
        return False
    other = aliased(Membership)
    stays_active_owner = role == "owner" and status == "active"
    keeps_an_owner = or_(
        true() if stays_active_owner else false(),
        not_(and_(Membership.role == "owner", Membership.status == "active")),
        exists().where(
            other.tenant_id == tenant_id,
            other.role == "owner",
            other.status == "active",
            other.principal_id != target_id,
        ),
    )
    statement = (
        update(Membership)
        .where(
            Membership.tenant_id == tenant_id,
            Membership.principal_id == target_id,
            Membership.version == version,
            _actor_may(actor_id, tenant_id, roles),
            keeps_an_owner,
        )
        .values(role=role, status=status, version=Membership.version + 1)
    )
    result = db.execute(statement, execution_options={"synchronize_session": False})
    return _rowcount(result) == 1
