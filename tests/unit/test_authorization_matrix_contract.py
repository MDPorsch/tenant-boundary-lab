"""Contract tests for the oracle data (capabilities / gates / field policy).

These assert the SPEC PROSE (specifications/01_tenant_boundary_lab.md s5/s6, shared standard
s2) a second time, in a different shape from the CSVs: as an explicit table and as invariants.
If someone edits only one encoding, a test here fails. They pass in M0 and must keep passing.
"""

from __future__ import annotations

import pytest

from tenantlab.oracle.matrix import (
    ROLE_RANK,
    Role,
    load_capabilities,
    load_field_policy,
    load_gates,
)
from tenantlab.schemas.errors import ErrorCode

ALL = {Role.OWNER, Role.ADMIN, Role.EDITOR, Role.VIEWER}
WRITERS = {Role.OWNER, Role.ADMIN, Role.EDITOR}
ADMINS = {Role.OWNER, Role.ADMIN}

# Second, independent encoding of spec s5 "Policy invariants" and s6 "API contracts".
EXPECTED_ROLES: dict[str, set[Role]] = {
    "tenant.context.read": ALL,
    "project.list": ALL,  # s5 list + s6: projects:read
    "project.read": ALL,  # s5: viewer/editor/admin/owner
    "project.create": WRITERS,  # s5: editor/admin/owner
    "project.write": WRITERS,  # s5: editor/admin/owner
    "invoice.read": ALL,  # s5: role viewer+
    "contact.private.read": ADMINS,  # s5: admin/owner explicitly
    "member.role.write": {Role.OWNER},  # s5: owner only
    "audit.read": ADMINS,  # s6: owner/admin read
}
EXPECTED_CAPABILITY = {
    "project.list": "projects:read",
    "project.read": "projects:read",
    "project.create": "projects:create",
    "project.write": "projects:write",
    "contact.private.read": "contacts:private:read",  # named in spec s6
    "member.role.write": "members:write",  # named in spec s6
    "invoice.read": "invoices:read",
    "audit.read": "audit:read",
}


def test_capability_table_matches_spec_exactly() -> None:
    matrix = load_capabilities()
    actual = {r.operation: set(r.allowed_roles) for r in matrix.rules}
    assert actual == EXPECTED_ROLES


def test_capability_names_match_spec() -> None:
    by_op = {r.operation: r.capability for r in load_capabilities().rules}
    for operation, capability in EXPECTED_CAPABILITY.items():
        assert by_op[operation] == capability


@pytest.mark.parametrize("operation", sorted(EXPECTED_ROLES))
def test_allows_agrees_with_table_for_every_role(operation: str) -> None:
    matrix = load_capabilities()
    for role in Role:
        assert matrix.allows(operation, role) is (role in EXPECTED_ROLES[operation])


def test_default_deny_for_unknown_operation_role_and_blank() -> None:
    matrix = load_capabilities()
    assert matrix.allows("project.delete", Role.OWNER) is False  # operation not in the matrix
    assert matrix.allows("project.read", "root") is False  # role not in the enum
    assert matrix.allows("project.read", "") is False
    assert matrix.allows("", Role.OWNER) is False


def test_permissions_are_monotonic_by_role() -> None:
    """owner >= admin >= editor >= viewer: a higher role never loses a capability."""
    ordered = sorted(Role, key=lambda r: ROLE_RANK[r])
    for rule in load_capabilities().rules:
        held = [role in rule.allowed_roles for role in ordered]  # viewer .. owner
        assert held == sorted(held), f"{rule.operation} is not monotonic: {held}"


def test_viewer_holds_only_read_capabilities() -> None:
    for rule in load_capabilities().rules:
        if Role.VIEWER in rule.allowed_roles:
            assert rule.operation.endswith(".read") or rule.operation.endswith(".list"), (
                f"viewer must be read-only, but holds {rule.operation}"
            )


def test_membership_write_is_owner_only_and_there_is_no_global_admin() -> None:
    matrix = load_capabilities()
    for role in Role:
        assert matrix.allows("member.role.write", role) is (role is Role.OWNER)
    # spec s5 "admin endpoint: tenant-admin capabilities only; no global admin route in MVP"
    assert not any("global" in r.operation or "platform" in r.operation for r in matrix.rules)


def test_private_contact_never_reachable_by_editor_or_viewer() -> None:
    matrix = load_capabilities()
    assert not matrix.allows("contact.private.read", Role.EDITOR)
    assert not matrix.allows("contact.private.read", Role.VIEWER)


# ------------------------------------------------------------------- gates ----


def _by_name() -> dict[str, int]:
    return {g.gate: g.order for g in load_gates()}


def test_gate_orders_are_unique_and_strictly_increasing() -> None:
    orders = [g.order for g in load_gates()]
    assert orders == sorted(orders)
    assert len(orders) == len(set(orders))
    assert orders[0] == 0


def test_gate_sequence_follows_the_standard_with_documented_deviations() -> None:
    """Shared standard s2 order, with D-05: resource scope is evaluated BEFORE role so that
    404-vs-403 never depends on hidden state."""
    o = _by_name()
    chain = [
        "transport_limits",
        "authenticate",
        "principal_status",
        "tenant_membership",
        "tenant_state",
        "resource_scope",  # D-05 deviation (before role_capability)
        "role_capability",
        "input_validation",  # nothing is parsed or validated for an actor not yet authorised
        "quota",
        "state_precondition",
    ]
    assert [o[name] for name in chain] == sorted(o[name] for name in chain)
    assert o["role_capability"] < o["state_invariant"]
    assert o["market_permit"] > o["role_capability"]


def test_every_gate_uses_a_known_error_code_and_a_client_error_status() -> None:
    for gate in load_gates():
        assert isinstance(gate.problem_code, ErrorCode)
        assert 400 <= gate.http_status <= 499


def test_status_semantics_401_403_404_409_422() -> None:
    status_of = {g.gate: g.http_status for g in load_gates()}
    assert status_of["authenticate"] == 401
    assert status_of["principal_status"] == 403
    assert status_of["role_capability"] == 403
    assert status_of["tenant_state"] == 403
    assert status_of["input_validation"] == 422
    assert status_of["state_precondition"] == 409
    assert {
        g.http_status for g in load_gates() if g.problem_code is ErrorCode.AUTH_TOKEN_INVALID
    } == {401}
    # 401 is reserved for authentication failures: no other code may use it.
    assert [g.gate for g in load_gates() if g.http_status == 401] == ["authenticate"]


def test_concealment_is_uniform_every_hidden_outcome_is_the_same_404() -> None:
    """Existence-oracle invariant (TL-04): all 'not visible' gates return one identical
    (status, code), and their audit rows are indistinguishable (tenant NULL)."""
    hidden = [g for g in load_gates() if g.http_status == 404]
    assert {g.gate for g in hidden} == {"tenant_membership", "resource_scope"}
    assert {(g.http_status, g.problem_code) for g in hidden} == {
        (404, ErrorCode.RESOURCE_NOT_FOUND)
    }
    assert {g.audit for g in hidden} == {"tenant_null"}


def test_pre_authentication_failures_never_write_to_the_database() -> None:
    """TL-01/TL-02 'no DB change': gates 0-1 are log-only; every later gate is audited."""
    for gate in load_gates():
        if gate.order <= 1:
            assert gate.audit == "none", gate.gate
        else:
            assert gate.audit != "none", gate.gate


def test_no_unauthorised_actor_can_write_into_a_tenant_audit_log() -> None:
    """Audit-poisoning guard: a row is tenant-scoped only after the actor is an active member
    of that tenant AND the target is visible to them."""
    o = _by_name()
    for gate in load_gates():
        if gate.audit == "tenant":
            assert gate.order > o["tenant_membership"], gate.gate


# ------------------------------------------------------------ field policy ----


def test_private_contact_fields_have_exactly_one_surface_and_admin_floor() -> None:
    rules = {(r.resource, r.field): r for r in load_field_policy()}
    for field in ("email_private", "phone_private"):
        rule = rules[("contact", field)]
        assert rule.surfaces == {"contacts.private"}
        assert rule.read_min_role is Role.ADMIN


def test_private_fields_are_absent_from_general_project_and_list_surfaces() -> None:
    for rule in load_field_policy():
        if rule.field in {"email_private", "phone_private"}:
            assert not rule.surfaces & {"project.list_item", "project.detail", "audit.list_item"}


def test_never_fields_have_no_surface_and_are_server_owned() -> None:
    never = [r for r in load_field_policy() if r.read_min_role is None]
    assert {(r.resource, r.field) for r in never} == {
        ("principal", "email"),
        ("principal", "auth_version"),
    }
    assert all(not r.surfaces for r in never)


def test_authority_fields_are_never_client_writable() -> None:
    """Mass-assignment guard (TL-06, TL-18): tenant, owner and id are server-owned."""
    rules = {(r.resource, r.field): r for r in load_field_policy()}
    for key in (
        ("project", "id"),
        ("project", "tenant_id"),
        ("project", "owner_principal_id"),
        ("membership", "principal_id"),
        ("membership", "tenant_id"),
    ):
        assert rules[key].on_create in {"server", "n/a"}, key
        assert rules[key].on_update in {"server", "n/a"}, key


def test_client_writable_project_fields_are_exactly_title_market_status() -> None:
    rules = [r for r in load_field_policy() if r.resource == "project"]
    on_create = {r.field for r in rules if r.on_create == "client"}
    on_update = {r.field for r in rules if r.on_update == "client"}
    assert on_create == {"market", "title"}
    assert on_update == {"title", "status"}
    assert {r.field for r in rules if r.on_update == "precondition"} == {"row_version"}


def test_only_owner_principal_id_is_projected_within_a_route() -> None:
    """Effective read floor on a surface = max(route floor, field floor).

    A field whose floor is ABOVE its route's floor is stripped for the lower roles that may
    still call the route (property-level projection, API3). The design allows exactly one:
    project.owner_principal_id on project.detail (editor+). Every other private datum is
    protected by a separate route (403), never by silently stripping a 200 (no BOPLA fallback).
    """
    ops = {r.operation: r for r in load_capabilities().rules}
    surface_op = {
        "contacts.private": "contact.private.read",
        "audit.list_item": "audit.read",
        "membership.detail": "member.role.write",
        "invoice.detail": "invoice.read",
        "tenant.context": "tenant.context.read",
        "project.list_item": "project.list",
        "project.detail": "project.read",
    }
    projected: set[tuple[str, str, str]] = set()
    for rule in load_field_policy():
        if rule.read_min_role is None:
            continue
        for surface in rule.surfaces:
            route_floor = min(ROLE_RANK[r] for r in ops[surface_op[surface]].allowed_roles)
            if ROLE_RANK[rule.read_min_role] > route_floor:
                projected.add((rule.resource, rule.field, surface))
    assert projected == {("project", "owner_principal_id", "project.detail")}


def test_every_surface_maps_to_a_known_operation() -> None:
    """A surface that no operation serves would be unreachable (dead) or unauthorised data."""
    known = {
        "contacts.private",
        "audit.list_item",
        "membership.detail",
        "invoice.detail",
        "tenant.context",
        "project.list_item",
        "project.detail",
    }
    used = {s for r in load_field_policy() for s in r.surfaces}
    assert used == known
