"""Route handlers. They receive an `Allowed` produced by the gates and never see unauthenticated or
unauthorized requests.

M1 implements only the context probe. Every other route passes the gates and then answers 501
until milestone M2 (docs/api-contract.md s2); the 501 is a problem+json and is not audited.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from tenantlab.api.gates import Allowed
from tenantlab.api.problems import (
    NOT_IMPLEMENTED_DETAIL,
    NOT_IMPLEMENTED_STATUS,
    ApiProblem,
)
from tenantlab.auth.policy import Role
from tenantlab.schemas.errors import ErrorCode

Handler = Callable[[Allowed, Request], Response]


class TenantContext(BaseModel):
    """Exactly what `GET /v1/tenants/{tenant_id}/me` returns (D-08). Nothing else may be added."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal_id: UUID
    tenant_id: UUID
    role: Role


def tenant_context(allowed: Allowed, request: Request) -> Response:
    body = TenantContext(
        principal_id=allowed.principal_id, tenant_id=allowed.tenant_id, role=allowed.role
    )
    return JSONResponse(body.model_dump(mode="json"))


def not_implemented(allowed: Allowed, request: Request) -> Response:
    raise ApiProblem(
        ErrorCode.INTERNAL_ERROR, status=NOT_IMPLEMENTED_STATUS, detail=NOT_IMPLEMENTED_DETAIL
    )


HANDLERS: Final[dict[str, Handler]] = {"tenant.context.read": tenant_context}
