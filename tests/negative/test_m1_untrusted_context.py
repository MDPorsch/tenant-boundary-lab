"""TL-18 (milestone M1): client-supplied identity, role, tenant or request metadata is data, never
authority (spec s5: do NOT accept tenant_id, role, region, email, X-User or X-Forwarded-For as
proof of permissions).

STATUS: RED by design in M0 (see test_m1_authentication.py).
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from typing import Any

import pytest

from tests.harness import Lab, assert_no_leak, assert_problem, assert_single_deny_audit

pytestmark = pytest.mark.milestone("M1")

OpenLab = Callable[..., Any]
PATCH_BODY = {"title": "renamed", "row_version": 1}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

# Headers a naive app might trust. Each is tried alone so a single trusted header is pinpointed.
AUTHORITY_HEADERS = [
    "X-User",
    "X-User-Id",
    "X-Principal-Id",
    "X-Forwarded-User",
    "X-Auth-Request-User",
    "X-Role",
    "X-User-Role",
    "X-Tenant-Id",
    "X-Tenant",
    "X-Forwarded-For",
    "X-Real-IP",
]


def _spoof(lab: Lab, header: str) -> str:
    """A value that, if trusted, would grant bob (viewer in A) extra authority."""
    if header.lower().endswith("role"):
        return "owner"
    if header.lower().startswith("x-tenant"):
        return lab.fx.tenant("B").id
    if header.lower() in {"x-forwarded-for", "x-real-ip"}:
        return "127.0.0.1"
    return lab.fx.principal("alice").id


@pytest.mark.parametrize("header", AUTHORITY_HEADERS)
async def test_tl18_identity_and_role_headers_are_ignored(open_lab: OpenLab, header: str) -> None:
    lab: Lab = await open_lab()
    tenant_a = lab.fx.tenant("A").id
    response = await lab.request(
        "GET",
        f"/v1/tenants/{tenant_a}/me",
        headers={**lab.bearer("bob"), header: _spoof(lab, header)},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "principal_id": lab.fx.principal("bob").id,  # the TOKEN's principal, not the header's
        "tenant_id": tenant_a,  # the PATH's tenant, not the header's
        "role": "viewer",  # the DATABASE's role, not the header's
    }


async def test_tl18_a_viewer_cannot_mutate_by_claiming_owner_in_headers(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    bob, tenant_a, pa1 = (
        lab.fx.principal("bob").id,
        lab.fx.tenant("A").id,
        lab.fx.project("PA1").id,
    )
    before = lab.snapshot()
    response = await lab.request(
        "PATCH",
        f"/v1/projects/{pa1}",
        headers={**lab.bearer("bob"), "X-Role": "owner", "X-User": lab.fx.principal("alice").id},
        json_body=PATCH_BODY,
    )
    assert_problem(response, status=403, code="authz.forbidden")
    assert_single_deny_audit(
        lab, before, response, actor=bob, tenant=tenant_a, action="project.write",
        resource_type="project", reason_code="authz.forbidden",
    )  # fmt: skip


async def test_tl18_role_in_the_body_is_denied_before_the_body_is_processed(
    open_lab: OpenLab,
) -> None:
    """Capability check precedes validation: the viewer gets 403, not a 422 that would confirm
    the server parsed (and might one day honour) a `role` property."""
    lab: Lab = await open_lab()
    bob, tenant_a, pa1 = (
        lab.fx.principal("bob").id,
        lab.fx.tenant("A").id,
        lab.fx.project("PA1").id,
    )
    before = lab.snapshot()
    response = await lab.request(
        "PATCH",
        f"/v1/projects/{pa1}",
        headers=lab.bearer("bob"),
        json_body={**PATCH_BODY, "role": "owner", "tenant_id": lab.fx.tenant("B").id},
    )
    assert_problem(response, status=403, code="authz.forbidden")
    assert_single_deny_audit(
        lab, before, response, actor=bob, tenant=tenant_a, action="project.write",
        resource_type="project", reason_code="authz.forbidden",
    )  # fmt: skip


async def test_tl18_authority_in_the_query_string_is_rejected_not_honoured(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    bob, tenant_a = lab.fx.principal("bob").id, lab.fx.tenant("A").id
    alice = lab.fx.principal("alice").id
    before = lab.snapshot()
    response = await lab.request(
        "GET",
        f"/v1/tenants/{tenant_a}/me",
        headers=lab.bearer("bob"),
        params={"role": "owner", "tenant_id": lab.fx.tenant("B").id, "user": alice},
    )
    assert_problem(response, status=422, code="request.invalid")
    assert alice not in response.text, "the rejected input was echoed back"
    assert_single_deny_audit(
        lab, before, response, actor=bob, tenant=tenant_a, action="tenant.context.read",
        resource_type="tenant", reason_code="request.invalid",
    )  # fmt: skip


@pytest.mark.parametrize(
    "extra",
    [
        {"role": "owner"},
        {"roles": ["owner", "admin"]},
        {"tenant_id": "20000000-0000-4000-8000-000000000002"},
        {"is_admin": True, "scope": "admin:*"},
    ],
    ids=["role", "roles", "tenant_id", "is_admin_scope"],
)
async def test_tl18_authority_claims_inside_a_valid_token_are_ignored(
    open_lab: OpenLab, extra: dict[str, Any]
) -> None:
    """Even a correctly SIGNED token cannot carry authority: role and tenant come from the DB."""
    lab: Lab = await open_lab()
    tenant_a = lab.fx.tenant("A").id
    response = await lab.request(
        "GET", f"/v1/tenants/{tenant_a}/me", headers=lab.bearer("bob", extra=extra)
    )
    assert response.status_code == 200, response.text
    assert response.json()["role"] == "viewer"
    assert response.json()["tenant_id"] == tenant_a


async def test_tl18_authority_claims_do_not_open_a_tenant_the_principal_is_not_in(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    tenant_b = lab.fx.tenant("B").id
    response = await lab.request(
        "GET",
        f"/v1/tenants/{tenant_b}/me",
        headers=lab.bearer("bob", extra={"role": "owner", "tenant_id": tenant_b}),
    )
    assert_problem(response, status=404, code="resource.not_found")
    assert_no_leak(response.text, lab.fx, forbidden_tenants="B")


@pytest.mark.parametrize(
    "supplied",
    [
        "5e1b0e0e-3b0a-4b86-8a3e-0f4d1e1d2c3b",  # a well-formed UUID the client picked
        "evil id with spaces and 'quotes' <b>x</b>",  # log-injection / markup attempt
    ],
    ids=["client_chosen_uuid", "hostile_text"],
)
@pytest.mark.parametrize("outcome", ["401_anonymous", "404_hidden", "200_ok"])
async def test_tl18_a_client_supplied_request_id_is_never_echoed_or_reused(
    open_lab: OpenLab, supplied: str, outcome: str
) -> None:
    lab: Lab = await open_lab()
    tenant_a, tenant_b = lab.fx.tenant("A").id, lab.fx.tenant("B").id
    path, headers = {
        "401_anonymous": (f"/v1/tenants/{tenant_a}/me", {}),
        "404_hidden": (f"/v1/tenants/{tenant_b}/me", lab.bearer("bob")),
        "200_ok": (f"/v1/tenants/{tenant_a}/me", lab.bearer("bob")),
    }[outcome]
    response = await lab.request("GET", path, headers={**headers, "X-Request-ID": supplied})
    server_id = response.headers["x-request-id"]
    assert UUID_RE.match(server_id), "the server must generate its own UUIDv4 request id"
    assert uuid.UUID(server_id).version == 4
    assert server_id != supplied
    assert supplied not in response.text
    if response.status_code >= 400:
        assert response.json()["request_id"] == server_id  # header and body agree
