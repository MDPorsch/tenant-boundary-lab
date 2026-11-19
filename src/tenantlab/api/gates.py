"""The ordered, deny-by-default gate pipeline (oracle/data/gates.csv, docs/api-contract.md s7).

    0 transport_limits  (middleware)      413  no audit row
    1 authenticate                        401  no audit row (pre-authentication: log line only)
    2 principal_status                    403  audit, tenant_id NULL
      path identifiers must be UUIDs      422  audit, tenant_id NULL        (D-11)
    3 tenant_membership                   404  audit, tenant_id NULL
    4 tenant_state                        403  audit, tenant_id = tenant
    5 resource_scope (market)             404  audit, tenant_id NULL        (D-05: before role)
    6 role_capability                     403  audit, tenant_id = tenant
    8 input_validation (query names)      422  audit, tenant_id = tenant
    (7 market_permit, 9 quota, 10-11 state checks need a request body: milestone M2)

Rules this module enforces:
* Authority is read from the database on EVERY request. Nothing is cached, and nothing the client
  sends (headers, query, body, extra token claims) selects a tenant, a role or a principal.
* Every "not visible" case is the same 404, so a hidden object cannot be told from a missing one.
* A denial writes ONE audit row whose tenant_id is NULL unless the actor is an active member of
  the tenant, so nobody can write into another tenant's audit log (D-10).
* The request body is never read here (D-18): bodies are parsed after the gates.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, NoReturn
from uuid import UUID

from sqlalchemy import exists, select
from sqlalchemy.orm import Session, sessionmaker
from starlette.requests import Request

from tenantlab.api.problems import ApiProblem
from tenantlab.api.routes import RouteSpec, Scope
from tenantlab.auth.policy import Role, parse_role, role_holds
from tenantlab.auth.tokens import TokenError, TokenVerifier, VerifiedToken
from tenantlab.db.models import (
    AuditEvent,
    Invoice,
    Membership,
    Principal,
    Project,
    Tenant,
    TenantMarketAccess,
)
from tenantlab.ids import parse_uuid4
from tenantlab.schemas.errors import ErrorCode, FieldError

logger = logging.getLogger("tenantlab.gates")

WWW_AUTHENTICATE: Final = "Bearer"


@dataclass(frozen=True, slots=True)
class Deps:
    session_factory: sessionmaker[Session]
    verifier: TokenVerifier
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class Allowed:
    """What a handler may rely on: all of it was read from the database for THIS request."""

    principal_id: UUID
    tenant_id: UUID
    role: Role
    request_id: UUID
    spec: RouteSpec
    path_ids: dict[str, UUID]


class _Deny(Exception):  # control flow inside this module, not a public error type
    """A gate failed. `tenant_id` is the audit tenant: None unless the actor is an active member."""

    def __init__(self, code: ErrorCode, tenant_id: UUID | None, resource_id: UUID | None) -> None:
        super().__init__(code.value)
        self.code = code
        self.tenant_id = tenant_id
        self.resource_id = resource_id


@dataclass(frozen=True, slots=True)
class _Scope:
    tenant_id: UUID
    market_id: UUID | None  # None: the route has no market dimension


@dataclass(frozen=True, slots=True)
class _Caller:
    """The authenticated principal, as read from the database for this request."""

    principal_id: UUID
    status: str
    request_id: UUID


@dataclass(frozen=True, slots=True)
class _Granted:
    tenant_id: UUID
    role: Role
    path_ids: dict[str, UUID]


def run_gates(request: Request, spec: RouteSpec, deps: Deps) -> Allowed:
    """Evaluate gates 1-8 or raise ApiProblem. Never reads the request body."""
    request_id: UUID = request.state.request_id
    token = _authenticate(request, spec, deps.verifier, request_id)
    with deps.session_factory() as db:
        principal_status = db.scalar(select(Principal.status).where(Principal.id == token.subject))
        if principal_status is None:
            # Validly signed, but no such principal: indistinguishable from any invalid token.
            _reject_credentials(spec, request_id, "unknown_principal")
        caller = _Caller(token.subject, principal_status, request_id)
        try:
            granted = _authorize(db, request, spec, caller)
        except _Deny as deny:
            _record_denial(db, spec, caller, deny, deps.clock())
            logger.info(
                "request denied",
                extra={
                    "event": "authz.denied",
                    "request_id": str(request_id),
                    "reason": deny.code.value,
                    "route": f"{spec.method} {spec.path}",
                },
            )
            raise ApiProblem(deny.code) from None
        return Allowed(
            caller.principal_id, granted.tenant_id, granted.role, request_id, spec, granted.path_ids
        )


# ---------------------------------------------------------------------------- gate 1 ----


def _reject_credentials(spec: RouteSpec, request_id: UUID, reason: str) -> NoReturn:
    """Pre-authentication failure: a structured log line, NEVER a database row, and an identical
    401 whatever the reason. The token itself is never logged."""
    logger.info(
        "authentication rejected",
        extra={
            "event": "auth.rejected",
            "request_id": str(request_id),
            "reason": reason,
            "route": f"{spec.method} {spec.path}",
        },
    )
    raise ApiProblem(ErrorCode.AUTH_TOKEN_INVALID, headers={"WWW-Authenticate": WWW_AUTHENTICATE})


def _authenticate(
    request: Request, spec: RouteSpec, verifier: TokenVerifier, request_id: UUID
) -> VerifiedToken:
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        _reject_credentials(spec, request_id, "no_credentials" if not values else "multiple")
    scheme, separator, token = values[0].partition(" ")
    if scheme.lower() != "bearer" or not separator or not token or token != token.strip():
        _reject_credentials(spec, request_id, "malformed_header")
    try:
        return verifier.verify(token)
    except TokenError as exc:
        _reject_credentials(spec, request_id, exc.reason)


# ----------------------------------------------------------------------- gates 2 to 8 ----


def _authorize(db: Session, request: Request, spec: RouteSpec, caller: _Caller) -> _Granted:
    parsed = {name: parse_uuid4(request.path_params.get(name)) for name in spec.path_params}
    target = parsed[spec.target_param]

    # Gate 2: a disabled principal is stopped before anything about tenants is consulted.
    if caller.status != "active":
        raise _Deny(ErrorCode.AUTH_PRINCIPAL_DISABLED, None, target)

    # D-11: a path identifier that is not a UUID cannot name any resource, so there is nothing
    # to conceal. The offending value is not recorded or echoed.
    ids = {name: value for name, value in parsed.items() if value is not None}
    if len(ids) != len(parsed):
        raise _Deny(ErrorCode.REQUEST_INVALID, None, None)
    target = ids[spec.target_param]

    granted = _evaluate(db, spec, caller, ids)

    # Gate 8 (query part): unknown or repeated query parameters are rejected, never ignored.
    names = [name for name, _ in request.query_params.multi_items()]
    if len(names) != len(set(names)) or not set(names) <= spec.query_params:
        raise _Deny(ErrorCode.REQUEST_INVALID, granted.tenant_id, target)
    return granted


def _evaluate(db: Session, spec: RouteSpec, caller: _Caller, ids: dict[str, UUID]) -> _Granted:
    """Gates 3-6 for already-parsed path ids. Used by the first pass AND by the re-check a
    mutation runs inside its own transaction (D-35)."""
    target = ids[spec.target_param]
    scope = _resolve_scope(db, spec, ids)
    if scope is None:
        raise _Deny(ErrorCode.RESOURCE_NOT_FOUND, None, target)

    # Gate 3: ACTIVE membership in the tenant that owns the target. A revoked member, a stranger
    # and a nonexistent tenant are one and the same case: 404. Ownership of a row grants nothing.
    membership = db.execute(
        select(Membership.role, Tenant.state)
        .join(Tenant, Tenant.id == Membership.tenant_id)
        .where(
            Membership.principal_id == caller.principal_id,
            Membership.tenant_id == scope.tenant_id,
            Membership.status == "active",
        )
    ).one_or_none()
    if membership is None:
        raise _Deny(ErrorCode.RESOURCE_NOT_FOUND, None, target)
    role_text, tenant_state = membership

    # Gate 4: reached only by an active member, so disclosing the suspension leaks nothing.
    if tenant_state != "active":
        raise _Deny(ErrorCode.TENANT_SUSPENDED, scope.tenant_id, target)

    # Gate 5 (D-05, before role): a project in a market the tenant may not use is not visible.
    if scope.market_id is not None and not db.scalar(
        select(
            exists().where(
                TenantMarketAccess.tenant_id == scope.tenant_id,
                TenantMarketAccess.market_id == scope.market_id,
            )
        )
    ):
        raise _Deny(ErrorCode.RESOURCE_NOT_FOUND, None, target)

    # Gate 6: the capability table. Unknown role or operation is denied.
    role = parse_role(role_text)
    if role is None or not role_holds(spec.operation, role):
        raise _Deny(ErrorCode.AUTHZ_FORBIDDEN, scope.tenant_id, target)
    return _Granted(scope.tenant_id, role, ids)


def _project_row(db: Session, project_id: UUID) -> tuple[UUID, UUID] | None:
    row = db.execute(
        select(Project.tenant_id, Project.market_id).where(Project.id == project_id)
    ).one_or_none()
    return None if row is None else (row.tenant_id, row.market_id)


def _resolve_scope(db: Session, spec: RouteSpec, ids: dict[str, UUID]) -> _Scope | None:
    """Find the tenant (and market) that own the target. None means 'not visible'."""
    if spec.scope is Scope.TENANT:
        return _Scope(ids["tenant_id"], None)
    if spec.scope is Scope.PROJECT:
        project = _project_row(db, ids["project_id"])
        return None if project is None else _Scope(*project)

    # Invoice routes: the invoice must belong to a project of the SAME tenant (TL-07 groundwork);
    # the nested route additionally requires it to belong to the project named in the path.
    invoice_query = select(Invoice.tenant_id, Invoice.project_id).where(
        Invoice.id == ids["invoice_id"]
    )
    if spec.scope is Scope.PROJECT_INVOICE:
        invoice_query = invoice_query.where(Invoice.project_id == ids["project_id"])
    invoice = db.execute(invoice_query).one_or_none()
    if invoice is None:
        return None
    project = _project_row(db, invoice.project_id)
    if project is None or project[0] != invoice.tenant_id:
        return None
    return _Scope(*project)


def _record_denial(
    db: Session, spec: RouteSpec, caller: _Caller, deny: _Deny, now: datetime
) -> None:
    db.add(
        AuditEvent(
            actor_id=caller.principal_id,
            tenant_id=deny.tenant_id,
            action=spec.operation,
            resource_type=spec.resource_type,
            resource_id=deny.resource_id,
            decision="deny",
            reason_code=deny.code.value,
            timestamp=now,
            correlation_id=caller.request_id,
        )
    )
    db.commit()


# ------------------------------------------------- helpers for handlers (gates 7-11, audit) ----


def _log_denial(allowed: Allowed, code: ErrorCode) -> None:
    logger.info(
        "request denied",
        extra={
            "event": "authz.denied",
            "request_id": str(allowed.request_id),
            "reason": code.value,
            "route": f"{allowed.spec.method} {allowed.spec.path}",
        },
    )


def deny(
    deps: Deps,
    db: Session,
    allowed: Allowed,
    code: ErrorCode,
    *,
    errors: Sequence[FieldError] = (),
) -> NoReturn:
    """End a request at gate 7 or later: discard anything pending, write ONE tenant-scoped denial
    row in a clean transaction (the actor is an active member of the tenant), then raise."""
    db.rollback()
    db.add(
        AuditEvent(
            actor_id=allowed.principal_id,
            tenant_id=allowed.tenant_id,
            action=allowed.spec.operation,
            resource_type=allowed.spec.resource_type,
            resource_id=allowed.path_ids[allowed.spec.target_param],
            decision="deny",
            reason_code=code.value,
            timestamp=deps.clock(),
            correlation_id=allowed.request_id,
        )
    )
    db.commit()
    _log_denial(allowed, code)
    raise ApiProblem(code, errors=errors)


def reauthorize(deps: Deps, db: Session, allowed: Allowed) -> Allowed:
    """Re-run gates 2-6 inside the caller's own transaction, right before a write. If a gate now
    fails (revocation, suspension, downgrade, market change since the first pass) the denial is
    recorded and raised; otherwise the freshly read role replaces the old one."""
    status = db.scalar(select(Principal.status).where(Principal.id == allowed.principal_id))
    caller = _Caller(allowed.principal_id, status or "missing", allowed.request_id)
    try:
        if caller.status != "active":
            raise _Deny(
                ErrorCode.AUTH_PRINCIPAL_DISABLED,
                None,
                allowed.path_ids[allowed.spec.target_param],
            )
        granted = _evaluate(db, allowed.spec, caller, allowed.path_ids)
    except _Deny as denied:
        db.rollback()
        _record_denial(db, allowed.spec, caller, denied, deps.clock())
        _log_denial(allowed, denied.code)
        raise ApiProblem(denied.code) from None
    return Allowed(
        allowed.principal_id, granted.tenant_id, granted.role, allowed.request_id, allowed.spec,
        allowed.path_ids,
    )  # fmt: skip


def record_allow(
    deps: Deps,
    db: Session,
    allowed: Allowed,
    *,
    resource_type: str | None = None,
    resource_id: UUID | None = None,
) -> None:
    """Add the `allow` audit row to the CALLER's transaction. The caller commits, so the change
    and its audit row succeed or fail together (D-37)."""
    db.add(
        AuditEvent(
            actor_id=allowed.principal_id,
            tenant_id=allowed.tenant_id,
            action=allowed.spec.operation,
            resource_type=resource_type or allowed.spec.resource_type,
            resource_id=resource_id or allowed.path_ids[allowed.spec.target_param],
            decision="allow",
            reason_code="ok",
            timestamp=deps.clock(),
            correlation_id=allowed.request_id,
        )
    )
