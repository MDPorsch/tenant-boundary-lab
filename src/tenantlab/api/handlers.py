"""Route handlers. They receive a `Context` produced AFTER gates 1-6 and the query-name check, and
never see an unauthenticated or unauthorized request.

Order inside a handler (docs/api-contract.md s10.3): media type and JSON syntax, gate 7 (create
only), gate 8 body validation, gate 9 quota, then the write. Pre-checks run in that order so errors
are reported as the contract says; the WRITE is one statement that re-checks authority (D-35). If
that statement changes no row, the gates are re-run and the checks repeated: a revocation, a
suspension or a stale version that raced in is reported as what it is, and a plain retry covers a
race that flipped back. After MAX_ATTEMPTS the request fails closed with 503.

Every denial goes through `gates.deny` (one tenant-scoped audit row); every success adds its
`allow` row to the SAME transaction as the change (D-37).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final, NoReturn
from uuid import UUID

from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy.orm import Session
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from tenantlab.api.gates import Allowed, Deps, deny, reauthorize, record_allow
from tenantlab.api.problems import (
    NOT_IMPLEMENTED_DETAIL,
    NOT_IMPLEMENTED_STATUS,
    ApiProblem,
)
from tenantlab.auth.policy import CAPABILITIES, Role
from tenantlab.lab.patched import service
from tenantlab.lab.patched.paging import (
    QueryError,
    encode_cursor,
    int_cursor,
    parse_limit,
    uuid_cursor,
)
from tenantlab.lab.patched.schemas import (
    OWNER_FIELD_ROLES,
    BodyError,
    CreateProject,
    PatchProject,
    ProjectDetail,
    ProjectDetailWithOwner,
    PutMembership,
    field_errors,
    page,
    parse_json_object,
)
from tenantlab.schemas.errors import ErrorCode, FieldError

MAX_ATTEMPTS: Final = 3


@dataclass(frozen=True, slots=True)
class Context:
    allowed: Allowed
    deps: Deps
    request: Request
    body: bytes  # read AFTER the gates; empty for routes without a body


Handler = Callable[[Context], Response]


class TenantContext(BaseModel):
    """Exactly what `GET /v1/tenants/{tenant_id}/me` returns (D-08). Nothing else may be added."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal_id: UUID
    tenant_id: UUID
    role: Role


def _roles(operation: str) -> list[str]:
    return sorted(role.value for role in CAPABILITIES[operation])


def _json(content: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(content, status_code=status)


# ------------------------------------------------------------------------------- helpers ----
def _page_params(ctx: Context, db: Session, parse_cursor: Callable[[str], Any]) -> tuple[int, Any]:
    """Gate 8 for the query VALUES (names were checked with the gates)."""
    params: Mapping[str, str] = ctx.request.query_params
    errors: list[FieldError] = []
    limit, after = 0, None
    try:
        limit = parse_limit(params)
    except QueryError as exc:
        errors.append(exc.error)
    if "cursor" in params:
        try:
            after = parse_cursor(params["cursor"])
        except QueryError as exc:
            errors.append(exc.error)
    if errors:
        deny(ctx.deps, db, ctx.allowed, ErrorCode.REQUEST_INVALID, errors=errors)
    return limit, after


def _json_object(ctx: Context, db: Session) -> dict[str, Any]:
    try:
        return parse_json_object(ctx.body, ctx.request.headers.get("content-type"))
    except BodyError as exc:
        deny(ctx.deps, db, ctx.allowed, ErrorCode.REQUEST_INVALID, errors=exc.errors)


def _validated[M: BaseModel](ctx: Context, db: Session, model: type[M], raw: dict[str, Any]) -> M:
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        deny(ctx.deps, db, ctx.allowed, ErrorCode.REQUEST_INVALID, errors=field_errors(exc))


def _vanished(ctx: Context, db: Session) -> NoReturn:
    """The target disappeared between the gates and the handler. Re-run the gates for the true
    reason; if they still pass, it is a plain 404."""
    reauthorize(ctx.deps, db, ctx.allowed)
    deny(ctx.deps, db, ctx.allowed, ErrorCode.RESOURCE_NOT_FOUND)


def _project_body(record: service.ProjectRecord, role: Role) -> dict[str, Any]:
    fields = record.item.model_dump()
    if role in OWNER_FIELD_ROLES:
        owned = ProjectDetailWithOwner(
            **fields, contacts=record.contacts, owner_principal_id=record.owner_principal_id
        )
        return owned.model_dump(mode="json")
    return ProjectDetail(**fields, contacts=record.contacts).model_dump(mode="json")


def _next_cursor(more: bool, last: str | None) -> str | None:
    return encode_cursor(last) if more and last is not None else None


# ------------------------------------------------------------------------------- handlers ----
def tenant_context(ctx: Context) -> Response:
    allowed = ctx.allowed
    body = TenantContext(
        principal_id=allowed.principal_id, tenant_id=allowed.tenant_id, role=allowed.role
    )
    return _json(body.model_dump(mode="json"))


def list_projects(ctx: Context) -> Response:
    with ctx.deps.session_factory() as db:
        limit, after = _page_params(ctx, db, uuid_cursor)
        items, more, total = service.list_projects(
            db, tenant_id=ctx.allowed.tenant_id, limit=limit, after=after
        )
        last = str(items[-1].id) if items else None
        return _json(page(list(items), _next_cursor(more, last), total))


def read_project(ctx: Context) -> Response:
    with ctx.deps.session_factory() as db:
        record = service.get_project(db, ctx.allowed.path_ids["project_id"])
        if record is None:
            _vanished(ctx, db)
        return _json(_project_body(record, ctx.allowed.role))


def create_project(ctx: Context) -> Response:
    allowed = ctx.allowed
    with ctx.deps.session_factory() as db:
        raw = _json_object(ctx, db)
        market = raw.get("market")
        # gate 7 precedes body validation (gates.csv order) whenever `market` is a string
        if (
            isinstance(market, str)
            and service.permitted_market(db, tenant_id=allowed.tenant_id, code=market) is None
        ):
            deny(ctx.deps, db, allowed, ErrorCode.AUTHZ_MARKET_DENIED)
        body = _validated(ctx, db, CreateProject, raw)

        for attempt in range(MAX_ATTEMPTS):
            if attempt:
                allowed = reauthorize(ctx.deps, db, allowed)
            market_id = service.permitted_market(db, tenant_id=allowed.tenant_id, code=body.market)
            if market_id is None:
                deny(ctx.deps, db, allowed, ErrorCode.AUTHZ_MARKET_DENIED)
            if service.count_projects(db, allowed.tenant_id) >= service.MAX_PROJECTS_PER_TENANT:
                deny(ctx.deps, db, allowed, ErrorCode.QUOTA_EXCEEDED)  # gate 9
            new_id = service.create_project(
                db, tenant_id=allowed.tenant_id, actor_id=allowed.principal_id,
                market_id=market_id, title=body.title, roles=_roles("project.create"),
            )  # fmt: skip
            if new_id is not None:
                record_allow(ctx.deps, db, allowed, resource_type="project", resource_id=new_id)
                db.commit()
                record = service.get_project(db, new_id)
                if record is None:  # cannot happen: it was just committed
                    raise ApiProblem(ErrorCode.SERVICE_UNAVAILABLE)
                return _json(_project_body(record, allowed.role), status=201)
        raise ApiProblem(ErrorCode.SERVICE_UNAVAILABLE)


def patch_project(ctx: Context) -> Response:
    allowed = ctx.allowed
    project_id = allowed.path_ids["project_id"]
    with ctx.deps.session_factory() as db:
        body = _validated(ctx, db, PatchProject, _json_object(ctx, db))
        for attempt in range(MAX_ATTEMPTS):
            if attempt:
                allowed = reauthorize(ctx.deps, db, allowed)
            stored = service.project_version(db, project_id)
            if stored is None:
                _vanished(ctx, db)
            if stored != body.row_version:  # gate 10
                deny(ctx.deps, db, allowed, ErrorCode.CONFLICT_STALE_REVISION)
            changed = service.update_project(
                db, project_id=project_id, tenant_id=allowed.tenant_id,
                actor_id=allowed.principal_id, row_version=body.row_version, title=body.title,
                status=body.status, roles=_roles("project.write"),
            )  # fmt: skip
            if changed:
                record_allow(ctx.deps, db, allowed)
                db.commit()
                record = service.get_project(db, project_id)
                if record is None:
                    raise ApiProblem(ErrorCode.SERVICE_UNAVAILABLE)
                return _json(_project_body(record, allowed.role))
        raise ApiProblem(ErrorCode.SERVICE_UNAVAILABLE)


def read_private_contacts(ctx: Context) -> Response:
    with ctx.deps.session_factory() as db:
        limit, after = _page_params(ctx, db, uuid_cursor)
        items, more, total = service.list_private_contacts(
            db, project_id=ctx.allowed.path_ids["project_id"], limit=limit, after=after
        )
        record_allow(ctx.deps, db, ctx.allowed)  # a private-contact read is audited (D-10)
        db.commit()
        last = str(items[-1].id) if items else None
        return _json(page(list(items), _next_cursor(more, last), total))


def read_invoice(ctx: Context) -> Response:
    with ctx.deps.session_factory() as db:
        invoice = service.get_invoice(db, ctx.allowed.path_ids["invoice_id"])
        if invoice is None:
            _vanished(ctx, db)
        return _json(invoice.model_dump(mode="json"))


def put_membership(ctx: Context) -> Response:
    allowed = ctx.allowed
    target = allowed.path_ids["principal_id"]
    with ctx.deps.session_factory() as db:
        body = _validated(ctx, db, PutMembership, _json_object(ctx, db))
        for attempt in range(MAX_ATTEMPTS):
            if attempt:
                allowed = reauthorize(ctx.deps, db, allowed)
            current = service.get_membership(db, tenant_id=allowed.tenant_id, principal_id=target)
            if current is None:  # D-34: existing memberships only
                deny(ctx.deps, db, allowed, ErrorCode.RESOURCE_NOT_FOUND)
            if current.version != body.version:  # gate 10
                deny(ctx.deps, db, allowed, ErrorCode.CONFLICT_STALE_REVISION)
            steps_down = current.role == "owner" and current.status == "active"
            steps_down = steps_down and not (body.role == "owner" and body.status == "active")
            if steps_down and not service.other_active_owner_exists(  # gate 11
                db, tenant_id=allowed.tenant_id, excluding=target
            ):
                deny(ctx.deps, db, allowed, ErrorCode.CONFLICT_LAST_OWNER)
            changed = service.update_membership(
                db, tenant_id=allowed.tenant_id, target_id=target, actor_id=allowed.principal_id,
                version=body.version, role=body.role, status=body.status,
                roles=_roles("member.role.write"),
            )  # fmt: skip
            if changed:
                record_allow(ctx.deps, db, allowed)
                db.commit()
                stored = service.get_membership(
                    db, tenant_id=allowed.tenant_id, principal_id=target
                )
                if stored is None:
                    raise ApiProblem(ErrorCode.SERVICE_UNAVAILABLE)
                return _json(
                    {
                        "principal_id": str(target),
                        "tenant_id": str(allowed.tenant_id),
                        "role": stored.role,
                        "status": stored.status,
                        "version": stored.version,
                    }
                )
        raise ApiProblem(ErrorCode.SERVICE_UNAVAILABLE)


def read_audit(ctx: Context) -> Response:
    with ctx.deps.session_factory() as db:
        limit, before = _page_params(ctx, db, int_cursor)
        items, more, total = service.list_audit(
            db, tenant_id=ctx.allowed.tenant_id, limit=limit, before=before
        )
        last = str(items[-1].id) if items else None
        return _json(page(list(items), _next_cursor(more, last), total))


def not_implemented(ctx: Context) -> Response:
    raise ApiProblem(
        ErrorCode.INTERNAL_ERROR, status=NOT_IMPLEMENTED_STATUS, detail=NOT_IMPLEMENTED_DETAIL
    )


HANDLERS: Final[dict[str, Handler]] = {
    "tenant.context.read": tenant_context,
    "project.list": list_projects,
    "project.read": read_project,
    "project.create": create_project,
    "project.write": patch_project,
    "contact.private.read": read_private_contacts,
    "invoice.read": read_invoice,
    "member.role.write": put_membership,
    "audit.read": read_audit,
}
