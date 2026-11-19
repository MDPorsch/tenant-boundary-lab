"""The route registry: every route the API exposes, with the facts the gates need.

Deny by default is structural: `create_app` mounts ONLY routes listed here and wraps each one in the
gate pipeline, so a route cannot exist without passing gates 1-8. A test compares this table with
the route table in docs/api-contract.md s2 and with the oracle's operation list.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal

ResourceType = Literal["tenant", "project", "invoice", "contact", "membership", "audit"]


class Scope(StrEnum):
    """How the tenant (and market) of the target are discovered."""

    TENANT = "tenant"  # {tenant_id} in the path
    PROJECT = "project"  # {project_id}: tenant and market come from the project row
    INVOICE = "invoice"  # {invoice_id}: tenant from the invoice, market from its project
    PROJECT_INVOICE = (
        "project_invoice"  # {project_id} and {invoice_id}: invoice must be the project's
    )


@dataclass(frozen=True, slots=True)
class RouteSpec:
    method: str
    path: str
    operation: str  # key into the capability table and the audit `action`
    resource_type: ResourceType  # audit `resource_type`
    scope: Scope
    target_param: str  # the path parameter naming the audited resource (the audit `resource_id`)
    path_params: tuple[str, ...]
    query_params: frozenset[str] = frozenset()  # anything else is rejected (422)
    implemented: bool = False  # False: passes the gates, then answers 501 (until M2)


_PAGING: Final = frozenset({"limit", "cursor"})

ROUTES: Final[tuple[RouteSpec, ...]] = (
    RouteSpec(
        "GET", "/v1/tenants/{tenant_id}/me", "tenant.context.read", "tenant",
        Scope.TENANT, "tenant_id", ("tenant_id",), implemented=True,
    ),
    RouteSpec(
        "GET", "/v1/tenants/{tenant_id}/projects", "project.list", "tenant",
        Scope.TENANT, "tenant_id", ("tenant_id",), _PAGING,
    ),
    RouteSpec(
        "POST", "/v1/tenants/{tenant_id}/projects", "project.create", "tenant",
        Scope.TENANT, "tenant_id", ("tenant_id",),
    ),
    RouteSpec(
        "GET", "/v1/projects/{project_id}", "project.read", "project",
        Scope.PROJECT, "project_id", ("project_id",),
    ),
    RouteSpec(
        "PATCH", "/v1/projects/{project_id}", "project.write", "project",
        Scope.PROJECT, "project_id", ("project_id",),
    ),
    RouteSpec(
        "GET", "/v1/projects/{project_id}/contacts", "contact.private.read", "contact",
        Scope.PROJECT, "project_id", ("project_id",),
    ),
    RouteSpec(
        "GET", "/v1/invoices/{invoice_id}", "invoice.read", "invoice",
        Scope.INVOICE, "invoice_id", ("invoice_id",),
    ),
    RouteSpec(
        "GET", "/v1/projects/{project_id}/invoices/{invoice_id}", "invoice.read", "invoice",
        Scope.PROJECT_INVOICE, "invoice_id", ("project_id", "invoice_id"),
    ),
    RouteSpec(
        "PUT", "/v1/tenants/{tenant_id}/members/{principal_id}", "member.role.write", "membership",
        Scope.TENANT, "principal_id", ("tenant_id", "principal_id"),
    ),
    RouteSpec(
        "GET", "/v1/tenants/{tenant_id}/audit", "audit.read", "audit",
        Scope.TENANT, "tenant_id", ("tenant_id",), _PAGING,
    ),
)  # fmt: skip
