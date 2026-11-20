"""The vulnerable lab's request handling: the patched pipeline with controls REMOVED one at a time.

Each flaw is a single `if Flaw.X in flaws` on one control, so the difference from the patched
behaviour is visible in the line that carries it. With no flaw enabled this must answer like the
patched app (a differential test proves it, decision D-42). It deliberately reuses nothing from the
patched gates, handlers or service, and it writes no audit rows.

Implemented: `me`, project list, project read, project patch, private contacts, invoice read.
Request-validation error DETAIL is simplified (an empty `errors` list).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import and_, exists, func, select, update
from sqlalchemy.orm import Session
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from tenantlab.api.problems import ApiProblem
from tenantlab.auth.policy import Role, parse_role, role_holds
from tenantlab.auth.tokens import TokenError, TokenVerifier
from tenantlab.db.models import (
    Invoice,
    Market,
    Membership,
    Principal,
    Project,
    ProjectContact,
    Tenant,
    TenantMarketAccess,
)
from tenantlab.ids import parse_uuid4
from tenantlab.lab.vulnerable.flaws import Flaw
from tenantlab.schemas.errors import ErrorCode

_RANK: Final = {"viewer": 1, "editor": 2, "admin": 3, "owner": 4}
_OWNER_VISIBLE: Final = frozenset({Role.OWNER, Role.ADMIN, Role.EDITOR})
_PAGE: Final = 25
_STATUSES: Final = ("draft", "active", "archived")


@dataclass(frozen=True, slots=True)
class Ctx:
    db: Session
    flaws: frozenset[Flaw]
    principal: uuid.UUID


@dataclass(frozen=True, slots=True)
class Target:
    tenant_id: uuid.UUID
    market_id: uuid.UUID | None


def _problem(code: ErrorCode) -> ApiProblem:
    return ApiProblem(code)


def authenticate(request: Request, verifier: TokenVerifier, db: Session) -> tuple[uuid.UUID, str]:
    """Strict authentication is NOT one of the flaws: same rules as the patched app."""
    unauthorized = ApiProblem(ErrorCode.AUTH_TOKEN_INVALID, headers={"WWW-Authenticate": "Bearer"})
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        raise unauthorized
    scheme, separator, token = values[0].partition(" ")
    if scheme.lower() != "bearer" or not separator or not token or token != token.strip():
        raise unauthorized
    try:
        verified = verifier.verify(token)
    except TokenError:
        raise unauthorized from None
    status = db.scalar(select(Principal.status).where(Principal.id == verified.subject))
    if status is None:
        raise unauthorized
    return verified.subject, str(status)


# ------------------------------------------------------------------------ authorization ----
def _membership(ctx: Ctx, tenant_id: uuid.UUID, *, scoped: bool) -> tuple[str, str] | None:
    query = (
        select(Membership.role, Tenant.state, Membership.tenant_id)
        .join(Tenant, Tenant.id == Membership.tenant_id)
        .where(Membership.principal_id == ctx.principal, Membership.status == "active")
    )
    # FLAW TENANT_PREDICATE_OMITTED: the lookup is not filtered by the object's tenant.
    if scoped or Flaw.TENANT_PREDICATE_OMITTED not in ctx.flaws:
        query = query.where(Membership.tenant_id == tenant_id)
    rows = ctx.db.execute(query).all()
    if not rows:
        return None
    best = max(rows, key=lambda r: (_RANK.get(r.role, 0), str(r.tenant_id)))
    return str(best.role), str(best.state)


def authorize(
    ctx: Ctx, operation: str, target: Target | None, *, scoped: bool = False
) -> tuple[Role, uuid.UUID]:
    if target is None:
        raise _problem(ErrorCode.RESOURCE_NOT_FOUND)
    found = _membership(ctx, target.tenant_id, scoped=scoped)
    if found is None:
        raise _problem(ErrorCode.RESOURCE_NOT_FOUND)
    role_text, tenant_state = found
    if tenant_state != "active":
        raise _problem(ErrorCode.TENANT_SUSPENDED)
    # FLAW MARKET_BOUNDARY_OMITTED: the market-access gate is skipped.
    if (
        Flaw.MARKET_BOUNDARY_OMITTED not in ctx.flaws
        and target.market_id is not None
        and not ctx.db.scalar(
            select(
                exists().where(
                    TenantMarketAccess.tenant_id == target.tenant_id,
                    TenantMarketAccess.market_id == target.market_id,
                )
            )
        )
    ):
        raise _problem(ErrorCode.RESOURCE_NOT_FOUND)
    role = parse_role(role_text)
    # FLAW ROLE_CHECK_MISSING: the capability gate is skipped.
    if Flaw.ROLE_CHECK_MISSING not in ctx.flaws and (
        role is None or not role_holds(operation, role)
    ):
        raise _problem(ErrorCode.AUTHZ_FORBIDDEN)
    return role or Role.VIEWER, target.tenant_id


def _project_target(db: Session, project_id: uuid.UUID) -> Target | None:
    row = db.execute(
        select(Project.tenant_id, Project.market_id).where(Project.id == project_id)
    ).one_or_none()
    return None if row is None else Target(row.tenant_id, row.market_id)


def _invoice_target(db: Session, invoice_id: uuid.UUID) -> Target | None:
    invoice = db.execute(
        select(Invoice.tenant_id, Invoice.project_id).where(Invoice.id == invoice_id)
    ).one_or_none()
    if invoice is None:
        return None
    project = _project_target(db, invoice.project_id)
    if project is None or project.tenant_id != invoice.tenant_id:
        return None
    return project


# ---------------------------------------------------------------------------- responses ----
def _json(content: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(content, status_code=status)


def _item(row: Any) -> dict[str, Any]:
    return {
        "id": str(row.id), "tenant_id": str(row.tenant_id), "market": row.code, "title": row.title,
        "status": row.status, "row_version": row.row_version,
    }  # fmt: skip


def _project_detail(ctx: Ctx, project_id: uuid.UUID, role: Role) -> dict[str, Any]:
    row = ctx.db.execute(
        select(
            Project.id, Project.tenant_id, Market.code, Project.title, Project.status,
            Project.row_version, Project.owner_principal_id,
        )
        .join(Market, Market.id == Project.market_id)
        .where(Project.id == project_id)
    ).one()  # fmt: skip
    contacts = ctx.db.execute(
        select(ProjectContact)
        .where(ProjectContact.project_id == project_id)
        .order_by(ProjectContact.id)
        .limit(100)
    ).scalars()
    rows: list[dict[str, Any]] = []
    for contact in contacts:
        entry: dict[str, Any] = {"id": str(contact.id), "public_name": contact.public_name}
        # FLAW PRIVATE_PROPERTY_SERIALIZED: private fields ride along in the general JSON.
        if Flaw.PRIVATE_PROPERTY_SERIALIZED in ctx.flaws:
            entry["email_private"] = contact.email_private
            entry["phone_private"] = contact.phone_private
        rows.append(entry)
    body = _item(row) | {"contacts": rows}
    if role in _OWNER_VISIBLE:
        body["owner_principal_id"] = str(row.owner_principal_id)
    return body


# ----------------------------------------------------------------------------- handlers ----
Ids = Mapping[str, uuid.UUID]


def me(ctx: Ctx, request: Request, ids: Ids, body: bytes) -> Response:
    target = Target(ids["tenant_id"], None)
    role, tenant_id = authorize(ctx, "tenant.context.read", target, scoped=True)
    return _json(
        {"principal_id": str(ctx.principal), "tenant_id": str(tenant_id), "role": role.value}
    )


def list_projects(ctx: Ctx, request: Request, ids: Ids, body: bytes) -> Response:
    _, tenant_id = authorize(ctx, "project.list", Target(ids["tenant_id"], None))
    visible = Project.tenant_id == tenant_id
    if Flaw.MARKET_BOUNDARY_OMITTED not in ctx.flaws:
        visible = and_(
            visible,
            exists().where(
                TenantMarketAccess.tenant_id == Project.tenant_id,
                TenantMarketAccess.market_id == Project.market_id,
            ),
        )
    rows = ctx.db.execute(
        select(
            Project.id, Project.tenant_id, Market.code, Project.title, Project.status,
            Project.row_version,
        )
        .join(Market, Market.id == Project.market_id)
        .where(visible)
        .order_by(Project.id)
        .limit(_PAGE)
    ).all()  # fmt: skip
    total = ctx.db.scalar(select(func.count()).select_from(Project).where(visible))
    return _json({"items": [_item(r) for r in rows], "next_cursor": None, "total": int(total or 0)})


def read_project(ctx: Ctx, request: Request, ids: Ids, body: bytes) -> Response:
    role, _ = authorize(ctx, "project.read", _project_target(ctx.db, ids["project_id"]))
    return _json(_project_detail(ctx, ids["project_id"], role))


def read_contacts(ctx: Ctx, request: Request, ids: Ids, body: bytes) -> Response:
    authorize(ctx, "contact.private.read", _project_target(ctx.db, ids["project_id"]))
    contacts = ctx.db.execute(
        select(ProjectContact)
        .where(ProjectContact.project_id == ids["project_id"])
        .order_by(ProjectContact.id)
        .limit(_PAGE)
    ).scalars().all()  # fmt: skip
    items = [
        {
            "id": str(c.id), "public_name": c.public_name, "email_private": c.email_private,
            "phone_private": c.phone_private,
        }
        for c in contacts
    ]  # fmt: skip
    return _json({"items": items, "next_cursor": None, "total": len(items)})


def read_invoice(ctx: Ctx, request: Request, ids: Ids, body: bytes) -> Response:
    authorize(ctx, "invoice.read", _invoice_target(ctx.db, ids["invoice_id"]))
    row = ctx.db.execute(
        select(
            Invoice.id, Invoice.tenant_id, Invoice.project_id, Invoice.amount_minor,
            Invoice.currency, Invoice.status,
        ).where(Invoice.id == ids["invoice_id"])
    ).one()  # fmt: skip
    return _json(
        {
            "id": str(row.id), "tenant_id": str(row.tenant_id), "project_id": str(row.project_id),
            "amount_minor": row.amount_minor, "currency": row.currency, "status": row.status,
        }
    )  # fmt: skip


def _parse_patch(raw: bytes) -> tuple[str | None, str | None, int]:
    invalid = _problem(ErrorCode.REQUEST_INVALID)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        raise invalid from None
    if not isinstance(data, dict) or set(data) - {"title", "status", "row_version"}:
        raise invalid
    title, status, version = data.get("title"), data.get("status"), data.get("row_version")
    if title is not None and (not isinstance(title, str) or not 1 <= len(title) <= 120):
        raise invalid
    if status is not None and status not in _STATUSES:
        raise invalid
    if type(version) is not int or not 1 <= version <= 2_147_483_647:
        raise invalid
    if title is None and status is None:
        raise invalid
    return title, status, version


def _apply_patch(ctx: Ctx, project_id: uuid.UUID, body: bytes) -> None:
    """Validate, check the version, UPDATE and COMMIT. Nothing here looks at who is asking."""
    title, status, version = _parse_patch(body)
    stored = ctx.db.scalar(select(Project.row_version).where(Project.id == project_id))
    if stored != version:
        raise _problem(ErrorCode.CONFLICT_STALE_REVISION)
    values: dict[str, Any] = {"row_version": Project.row_version + 1}
    if title is not None:
        values["title"] = title
    if status is not None:
        values["status"] = status
    changed = ctx.db.execute(
        update(Project)
        .where(Project.id == project_id, Project.row_version == version)
        .values(**values),
        execution_options={"synchronize_session": False},
    )
    if changed.rowcount != 1:  # type: ignore[attr-defined]
        raise _problem(ErrorCode.CONFLICT_STALE_REVISION)
    ctx.db.commit()


def patch_project(ctx: Ctx, request: Request, ids: Ids, body: bytes) -> Response:
    project_id = ids["project_id"]
    target = _project_target(ctx.db, project_id)
    # FLAW WRITE_BEFORE_AUTHORIZATION: the change is committed BEFORE the gates run. A project
    # that does not exist is never written (there is no row), and validation still comes first.
    write_first = Flaw.WRITE_BEFORE_AUTHORIZATION in ctx.flaws and target is not None
    if write_first:
        _apply_patch(ctx, project_id, body)
    role, _ = authorize(ctx, "project.write", target)
    if not write_first:
        _apply_patch(ctx, project_id, body)
    return _json(_project_detail(ctx, project_id, role))


def parse_ids(names: tuple[str, ...], request: Request) -> dict[str, uuid.UUID]:
    parsed: dict[str, uuid.UUID] = {}
    for name in names:
        value = parse_uuid4(request.path_params.get(name))
        if value is None:
            raise _problem(ErrorCode.REQUEST_INVALID)
        parsed[name] = value
    return parsed
