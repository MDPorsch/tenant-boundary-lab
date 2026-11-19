"""TL-03, TL-04, TL-05, TL-14 (milestone M1): principal status, tenant membership, tenant state.

STATUS: RED by design in M0 (see test_m1_authentication.py). Expected outcomes: gates 2-4 and 6
of oracle/data/gates.csv, concealment rules of docs/api-contract.md s5.

Every denial must (a) leave business data untouched and (b) write exactly one audit row whose
tenant_id is NULL unless the actor is an active member of that tenant (audit-poisoning guard).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from tests.harness import (
    Lab,
    assert_no_leak,
    assert_problem,
    assert_single_deny_audit,
    body_sans_request_id,
)

pytestmark = pytest.mark.milestone("M1")

OpenLab = Callable[..., Any]
PATCH_BODY = {"title": "renamed", "row_version": 1}


def _me(tenant_id: str) -> str:
    return f"/v1/tenants/{tenant_id}/me"


# --- TL-03: disabled actor / revoked membership ------------------------------------------------
async def test_tl03_disabled_principal_is_403_on_tenant_and_object_routes(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    erin = lab.fx.principal("erin").id  # disabled, yet still holds an ACTIVE tenant A membership
    tenant_a, pa1 = lab.fx.tenant("A").id, lab.fx.project("PA1").id
    cases = [
        ("GET", _me(tenant_a), None, "tenant.context.read", "tenant"),
        ("PATCH", f"/v1/projects/{pa1}", PATCH_BODY, "project.write", "project"),
    ]
    for method, path, body, action, resource_type in cases:
        before = lab.snapshot()
        response = await lab.request(method, path, headers=lab.bearer("erin"), json_body=body)
        assert_problem(response, status=403, code="auth.principal_disabled")
        assert_no_leak(response.text, lab.fx, forbidden_tenants="ABC")
        assert_single_deny_audit(
            lab, before, response, actor=erin, tenant=None, action=action,
            resource_type=resource_type, reason_code="auth.principal_disabled",
        )  # fmt: skip


async def test_tl03_revoked_member_gets_404_even_for_an_object_they_own(
    open_lab: OpenLab,
) -> None:
    """Frank's membership is revoked but he is still project PA1's owner_principal_id. Object
    ownership grants nothing (decision D-04): he must see exactly what a stranger sees."""
    lab: Lab = await open_lab()
    frank = lab.fx.principal("frank").id
    tenant_a, pa1 = lab.fx.tenant("A").id, lab.fx.project("PA1").id
    cases = [
        ("GET", _me(tenant_a), None, "tenant.context.read", "tenant"),
        ("GET", f"/v1/tenants/{tenant_a}/projects", None, "project.list", "tenant"),
        ("PATCH", f"/v1/projects/{pa1}", PATCH_BODY, "project.write", "project"),
    ]
    for method, path, body, action, resource_type in cases:
        before = lab.snapshot()
        response = await lab.request(method, path, headers=lab.bearer("frank"), json_body=body)
        assert_problem(response, status=404, code="resource.not_found")
        assert_no_leak(response.text, lab.fx, forbidden_tenants="ABC")
        assert_single_deny_audit(
            lab, before, response, actor=frank, tenant=None, action=action,
            resource_type=resource_type, reason_code="resource.not_found",
        )  # fmt: skip


async def test_tl03_membership_revoked_after_token_issue_is_denied_on_the_next_request(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    tenant_a = lab.fx.tenant("A").id
    headers = lab.bearer("bob")  # ONE token, reused across the revocation
    allowed = await lab.request("GET", _me(tenant_a), headers=headers)
    assert allowed.status_code == 200, allowed.text
    lab.set_membership("bob", "A", status="revoked")
    denied = await lab.request("GET", _me(tenant_a), headers=headers)
    assert_problem(denied, status=404, code="resource.not_found")


# --- TL-04: guessing another tenant's UUID -----------------------------------------------------
def _hidden_vs_ghost(lab: Lab, kind: str) -> tuple[tuple[str, str, Any], tuple[str, str, Any]]:
    """(foreign-but-real, never-seeded) request pair for the same route."""
    ghost_tenant = lab.fx.never_seeded["tenant"]
    ghost_project = lab.fx.never_seeded["project"]
    tenant_b, pb1 = lab.fx.tenant("B").id, lab.fx.project("PB1").id
    pairs = {
        "tenant_context": (("GET", _me(tenant_b), None), ("GET", _me(ghost_tenant), None)),
        "tenant_projects": (
            ("GET", f"/v1/tenants/{tenant_b}/projects", None),
            ("GET", f"/v1/tenants/{ghost_tenant}/projects", None),
        ),
        "project_patch": (
            ("PATCH", f"/v1/projects/{pb1}", PATCH_BODY),
            ("PATCH", f"/v1/projects/{ghost_project}", PATCH_BODY),
        ),
    }
    return pairs[kind]


@pytest.mark.parametrize("kind", ["tenant_context", "tenant_projects", "project_patch"])
async def test_tl04_a_real_foreign_resource_is_indistinguishable_from_a_nonexistent_one(
    open_lab: OpenLab, kind: str
) -> None:
    """Existence-oracle test. bob (tenant A viewer) probes tenant B's real id and a never-seeded
    id: status, code, body (minus request_id), headers and audit shape must all be identical."""
    lab: Lab = await open_lab()
    bob = lab.fx.principal("bob").id
    foreign, ghost = _hidden_vs_ghost(lab, kind)
    bodies, audit_shapes = [], []
    for method, path, body in (foreign, ghost):
        before = lab.snapshot()
        response = await lab.request(method, path, headers=lab.bearer("bob"), json_body=body)
        problem = assert_problem(response, status=404, code="resource.not_found")
        assert_no_leak(response.text, lab.fx, forbidden_tenants="B")
        rows = lab.snapshot().new_audit_rows(before)
        assert len(rows) == 1
        audit_shapes.append(
            {k: rows[0][k] for k in ("action", "resource_type", "decision", "reason_code")}
        )
        assert rows[0]["tenant_id"] is None
        bodies.append((body_sans_request_id(problem), response.headers["content-type"]))
        assert str(rows[0]["actor_id"]).replace("-", "") == bob.replace("-", "")
    assert bodies[0] == bodies[1], "a hidden resource is distinguishable from a missing one"
    assert audit_shapes[0] == audit_shapes[1], "audit rows reveal which resource exists"


# --- TL-05: multi-membership roles must not bleed across tenants -------------------------------
ACTIVE_MEMBERS = [
    ("alice", "A", "owner"),
    ("bob", "A", "viewer"),
    ("carla", "B", "admin"),
    ("dave", "A", "editor"),
    ("dave", "B", "viewer"),
]


@pytest.mark.parametrize(("who", "tenant", "role"), ACTIVE_MEMBERS)
async def test_tl05_context_reports_the_database_role_for_the_path_tenant(
    open_lab: OpenLab, who: str, tenant: str, role: str
) -> None:
    """Positive control for every active member; dave appears twice with DIFFERENT roles."""
    lab: Lab = await open_lab()
    tenant_id = lab.fx.tenant(tenant).id
    response = await lab.request("GET", _me(tenant_id), headers=lab.bearer(who))
    assert response.status_code == 200, response.text
    assert response.json() == {
        "principal_id": lab.fx.principal(who).id,
        "tenant_id": tenant_id,
        "role": role,
    }


async def test_tl05_a_non_member_cannot_reach_a_tenant_and_learns_nothing_about_it(
    open_lab: OpenLab,
) -> None:
    """dave is in A and B but not C. C is SUSPENDED: a non-member must still get the plain 404,
    never the 403 tenant.suspended that would disclose C's state."""
    lab: Lab = await open_lab()
    tenant_c = lab.fx.tenant("C").id
    ghost = lab.fx.never_seeded["tenant"]
    shown = await lab.request("GET", _me(tenant_c), headers=lab.bearer("dave"))
    hidden = await lab.request("GET", _me(ghost), headers=lab.bearer("dave"))
    a = assert_problem(shown, status=404, code="resource.not_found")
    b = assert_problem(hidden, status=404, code="resource.not_found")
    assert body_sans_request_id(a) == body_sans_request_id(b)
    assert_no_leak(shown.text, lab.fx, forbidden_tenants="C")


async def test_tl05_a_role_held_in_one_tenant_does_not_apply_in_another(
    open_lab: OpenLab,
) -> None:
    """dave EDITS in A but only VIEWS in B: patching B's project is 403 (he can see it, he may
    not write it), even when he claims tenant A and role editor in headers."""
    lab: Lab = await open_lab()
    dave, tenant_b, pb1 = (
        lab.fx.principal("dave").id,
        lab.fx.tenant("B").id,
        lab.fx.project("PB1").id,
    )
    before = lab.snapshot()
    response = await lab.request(
        "PATCH",
        f"/v1/projects/{pb1}",
        headers={**lab.bearer("dave"), "X-Tenant-Id": lab.fx.tenant("A").id, "X-Role": "editor"},
        json_body=PATCH_BODY,
    )
    assert_problem(response, status=403, code="authz.forbidden")
    assert_single_deny_audit(
        lab, before, response, actor=dave, tenant=tenant_b, action="project.write",
        resource_type="project", reason_code="authz.forbidden",
    )  # fmt: skip


async def test_tl05_a_tenant_header_never_selects_the_evaluated_tenant(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    tenant_a, tenant_b = lab.fx.tenant("A").id, lab.fx.tenant("B").id
    response = await lab.request(
        "GET", _me(tenant_b), headers={**lab.bearer("dave"), "X-Tenant-Id": tenant_a}
    )
    assert response.status_code == 200, response.text
    assert response.json()["tenant_id"] == tenant_b  # path wins; header ignored
    assert response.json()["role"] == "viewer"  # dave's role in B, not in A


# --- TL-14: suspended tenant, state changes, nothing cached ------------------------------------
async def test_tl14_a_suspended_tenant_denies_its_own_owner(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    gina, tenant_c, pc1 = (
        lab.fx.principal("gina").id,
        lab.fx.tenant("C").id,
        lab.fx.project("PC1").id,
    )
    cases = [
        ("GET", _me(tenant_c), None, "tenant.context.read", "tenant"),
        ("PATCH", f"/v1/projects/{pc1}", PATCH_BODY, "project.write", "project"),
    ]
    for method, path, body, action, resource_type in cases:
        before = lab.snapshot()
        response = await lab.request(method, path, headers=lab.bearer("gina"), json_body=body)
        assert_problem(response, status=403, code="tenant.suspended")
        assert_single_deny_audit(
            lab, before, response, actor=gina, tenant=tenant_c, action=action,
            resource_type=resource_type, reason_code="tenant.suspended",
        )  # fmt: skip


async def test_tl14_suspension_and_reactivation_take_effect_on_the_very_next_request(
    open_lab: OpenLab,
) -> None:
    """No cached membership or tenant state: flip the row, the next request sees it, both ways."""
    lab: Lab = await open_lab()
    tenant_a, pa1 = lab.fx.tenant("A").id, lab.fx.project("PA1").id
    headers = lab.bearer("alice")
    assert (await lab.request("GET", _me(tenant_a), headers=headers)).status_code == 200

    lab.set_tenant_state("A", "suspended")
    for method, path, body in (
        ("GET", _me(tenant_a), None),
        ("PATCH", f"/v1/projects/{pa1}", PATCH_BODY),
    ):
        response = await lab.request(method, path, headers=headers, json_body=body)
        assert_problem(response, status=403, code="tenant.suspended")

    lab.set_tenant_state("A", "active")
    assert (await lab.request("GET", _me(tenant_a), headers=headers)).status_code == 200


async def test_tl14_a_role_downgrade_is_effective_on_the_next_request(open_lab: OpenLab) -> None:
    """Monotonic revocation: removing a capability is enforced immediately, never after a delay."""
    lab: Lab = await open_lab()
    tenant_a, pa1 = lab.fx.tenant("A").id, lab.fx.project("PA1").id
    headers = lab.bearer("dave")  # editor in A
    before_role = await lab.request("GET", _me(tenant_a), headers=headers)
    assert before_role.json()["role"] == "editor"

    lab.set_membership("dave", "A", role="viewer")
    after_role = await lab.request("GET", _me(tenant_a), headers=headers)
    assert after_role.json()["role"] == "viewer"
    denied = await lab.request(
        "PATCH", f"/v1/projects/{pa1}", headers=headers, json_body=PATCH_BODY
    )
    assert_problem(denied, status=403, code="authz.forbidden")
