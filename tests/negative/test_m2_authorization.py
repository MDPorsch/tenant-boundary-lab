"""TL-06, TL-07, TL-08, TL-13 (milestone M2): the data-bearing routes honour the gates.

STATUS: written RED-FIRST for M2. Several assertions already hold because the M1 gates cover them;
the rest fail (the handlers answer 501) until M2 builds the operations. Never skipped, xfailed or
weakened. Expected outcomes: docs/api-contract.md s10 and the case catalog.
"""

from __future__ import annotations

import json
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
from tests.support_m2 import body_routes

pytestmark = pytest.mark.milestone("M2")

OpenLab = Callable[..., Any]
PATCH_BODY = {"title": "renamed", "row_version": 1}


def _ids(lab: Lab) -> dict[str, str]:
    return {
        "A": lab.fx.tenant("A").id,
        "B": lab.fx.tenant("B").id,
        "PA1": lab.fx.project("PA1").id,
        "PA2": lab.fx.project("PA2").id,
        "PB1": lab.fx.project("PB1").id,
        "IA1": lab.fx.invoice("IA1").id,
        "IA2": lab.fx.invoice("IA2").id,
        "IB1": lab.fx.invoice("IB1").id,
        "GHOST_P": lab.fx.never_seeded["project"],
        "GHOST_I": lab.fx.never_seeded["invoice"],
    }


# ---------------------------------------------------------------------------- TL-06 ----
async def test_tl06_a_viewer_cannot_patch_or_create(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    routes = body_routes(lab)
    for name in ("patch", "create"):
        method, path, action, resource_type, body = routes[name]
        before = lab.snapshot()
        response = await lab.request(method, path, headers=lab.bearer("bob"), json_body=body)
        assert_problem(response, status=403, code="authz.forbidden")
        assert_single_deny_audit(
            lab, before, response, actor=lab.fx.principal("bob").id,
            tenant=lab.fx.tenant("A").id, action=action, resource_type=resource_type,
            reason_code="authz.forbidden",
        )  # fmt: skip


@pytest.mark.parametrize("who", ["bob", "dave"])
@pytest.mark.parametrize("route", ["audit", "contacts"])
async def test_tl06_editor_and_viewer_are_forbidden_on_audit_and_contacts(
    open_lab: OpenLab, who: str, route: str
) -> None:
    """403, never a 200 with fields stripped (D-13). The audit row is scoped to the tenant."""
    lab: Lab = await open_lab()
    ids = _ids(lab)
    path, action, resource_type = {
        "audit": (f"/v1/tenants/{ids['A']}/audit", "audit.read", "audit"),
        "contacts": (f"/v1/projects/{ids['PA1']}/contacts", "contact.private.read", "contact"),
    }[route]
    before = lab.snapshot()
    response = await lab.request("GET", path, headers=lab.bearer(who))
    assert_problem(response, status=403, code="authz.forbidden")
    assert_no_leak(response.text, lab.fx, forbidden_tenants="ABC")
    assert_single_deny_audit(
        lab, before, response, actor=lab.fx.principal(who).id, tenant=ids["A"], action=action,
        resource_type=resource_type, reason_code="authz.forbidden",
    )  # fmt: skip


OVERPOSTING = {
    "create": [
        "tenant_id",
        "owner_principal_id",
        "id",
        "role",
        "status",
        "row_version",
        "created_at",
    ],
    "patch": ["tenant_id", "owner_principal_id", "market", "id", "role", "created_at"],
    "put": ["principal_id", "tenant_id", "id", "email", "is_owner"],
}


@pytest.mark.parametrize(
    ("route", "extra_key"),
    [(route, key) for route, keys in OVERPOSTING.items() for key in keys],
)
async def test_tl06_server_owned_fields_in_a_body_are_422_and_change_nothing(
    open_lab: OpenLab, route: str, extra_key: str
) -> None:
    lab: Lab = await open_lab()
    method, path, action, resource_type, body = body_routes(lab)[route]
    marker = "OVERPOST-MARKER-7f3a"
    before = lab.snapshot()
    response = await lab.request(
        method, path, headers=lab.bearer("alice"), json_body={**body, extra_key: marker}
    )
    problem = assert_problem(response, status=422, code="request.invalid")
    assert marker not in response.text, "the value was echoed"
    # structural, not textual: "id" and "status" appear in every problem body by design
    assert extra_key not in json.dumps(problem["errors"]), "the key name was echoed"
    assert problem["errors"] == [{"loc": ["body"], "code": "unknown_field"}]
    assert_single_deny_audit(
        lab, before, response, actor=lab.fx.principal("alice").id, tenant=lab.fx.tenant("A").id,
        action=action, resource_type=resource_type, reason_code="request.invalid",
    )  # fmt: skip


async def test_tl06_several_unknown_keys_are_reported_once_and_none_by_name(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    method, path, _, _, body = body_routes(lab)["patch"]
    response = await lab.request(
        method,
        path,
        headers=lab.bearer("alice"),
        json_body={**body, "tenant_id": "x", "owner_principal_id": "y", "role": "owner"},
    )
    problem = assert_problem(response, status=422, code="request.invalid")
    assert problem["errors"] == [{"loc": ["body"], "code": "unknown_field"}]


async def test_tl06_the_owner_field_is_set_by_the_server_never_by_the_client(
    open_lab: OpenLab,
) -> None:
    """Anti-vacuity for the 422s above: a create WITHOUT the extra key succeeds, and the owner is
    the caller."""
    lab: Lab = await open_lab()
    _, path, _, _, body = body_routes(lab)["create"]
    response = await lab.request("POST", path, headers=lab.bearer("dave"), json_body=body)
    assert response.status_code == 201, response.text
    assert response.json()["owner_principal_id"] == lab.fx.principal("dave").id
    assert response.json()["tenant_id"] == lab.fx.tenant("A").id


# ---------------------------------------------------------------------------- TL-07 ----
NESTED_MISMATCHES = [
    ("alice", "/v1/projects/{PA1}/invoices/{IB1}", "/v1/projects/{PA1}/invoices/{GHOST_I}"),
    ("alice", "/v1/projects/{PB1}/invoices/{IA1}", "/v1/projects/{GHOST_P}/invoices/{IA1}"),
    ("alice", "/v1/invoices/{IB1}", "/v1/invoices/{GHOST_I}"),
    ("carla", "/v1/projects/{PB1}/invoices/{IA1}", "/v1/projects/{PB1}/invoices/{GHOST_I}"),
    ("carla", "/v1/projects/{PA1}/invoices/{IB1}", "/v1/projects/{GHOST_P}/invoices/{IB1}"),
]


@pytest.mark.parametrize(("who", "mismatch", "ghost"), NESTED_MISMATCHES)
async def test_tl07_a_foreign_or_mismatched_nested_id_is_a_404_equal_to_a_missing_one(
    open_lab: OpenLab, who: str, mismatch: str, ghost: str
) -> None:
    lab: Lab = await open_lab()
    ids = _ids(lab)
    seen = []
    for template in (mismatch, ghost):
        before = lab.snapshot()
        response = await lab.request("GET", template.format(**ids), headers=lab.bearer(who))
        problem = assert_problem(response, status=404, code="resource.not_found")
        assert_no_leak(response.text, lab.fx, forbidden_tenants="ABC")
        rows = lab.snapshot().new_audit_rows(before)
        assert len(rows) == 1
        seen.append(
            (
                body_sans_request_id(problem),
                {k: rows[0][k] for k in ("action", "resource_type", "decision", "reason_code")},
                rows[0]["tenant_id"],
            )
        )
    assert seen[0] == seen[1], "a mismatched pair is distinguishable from a missing id"


async def test_tl07_a_coherent_invoice_is_served_on_both_routes(open_lab: OpenLab) -> None:
    """Positive control: a deny-everything server would pass every 404 test above."""
    lab: Lab = await open_lab()
    ids = _ids(lab)
    expected = {
        "id": ids["IA1"],
        "tenant_id": ids["A"],
        "project_id": ids["PA1"],
        "amount_minor": 125000,
        "currency": "GBP",
        "status": "issued",
    }
    for path in (f"/v1/invoices/{ids['IA1']}", f"/v1/projects/{ids['PA1']}/invoices/{ids['IA1']}"):
        response = await lab.request("GET", path, headers=lab.bearer("alice"))
        assert response.status_code == 200, response.text
        assert response.json() == expected


@pytest.mark.parametrize("who", ["alice", "carla"])
async def test_tl07_an_incoherent_invoice_is_never_served(open_lab: OpenLab, who: str) -> None:
    """IA1 is injected as tenant B's invoice although its project is tenant A's."""
    lab: Lab = await open_lab()
    ids = _ids(lab)
    lab.sql(
        "UPDATE invoices SET tenant_id = (SELECT id FROM tenants WHERE slug = 'tenant-b') "
        "WHERE amount_minor = 125000"
    )
    for path in (
        f"/v1/invoices/{ids['IA1']}",
        f"/v1/projects/{ids['PA1']}/invoices/{ids['IA1']}",
        f"/v1/projects/{ids['PB1']}/invoices/{ids['IA1']}",
    ):
        response = await lab.request("GET", path, headers=lab.bearer(who))
        assert_problem(response, status=404, code="resource.not_found")
        assert "125000" not in response.text
        assert "GBP" not in response.text


# ---------------------------------------------------------------------------- TL-08 ----
async def test_tl08_a_hidden_market_project_is_unreachable_for_the_owner(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    ids = _ids(lab)
    before = lab.snapshot()
    for method, path, body in (
        ("GET", f"/v1/projects/{ids['PA2']}", None),
        ("PATCH", f"/v1/projects/{ids['PA2']}", PATCH_BODY),
        ("GET", f"/v1/projects/{ids['PA2']}/contacts", None),
        ("GET", f"/v1/invoices/{ids['IA2']}", None),
        ("GET", f"/v1/projects/{ids['PA2']}/invoices/{ids['IA2']}", None),
    ):
        response = await lab.request(method, path, headers=lab.bearer("alice"), json_body=body)
        assert_problem(response, status=404, code="resource.not_found")
        for needle in ("US pilot", "CA2", "5000", "USD"):
            assert needle not in response.text, needle
    after = lab.snapshot()
    assert after.business == before.business, "a denied write changed the hidden row"


async def test_tl08_creating_in_a_market_the_tenant_may_not_use_is_403_market_denied(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    tenant_a = lab.fx.tenant("A").id
    for market in ("US", "XX", "us", "UK "):
        before = lab.snapshot()
        response = await lab.request(
            "POST",
            f"/v1/tenants/{tenant_a}/projects",
            headers=lab.bearer("alice"),
            json_body={"title": "Pilot", "market": market},
        )
        assert_problem(response, status=403, code="authz.market_denied")
        assert_single_deny_audit(
            lab, before, response, actor=lab.fx.principal("alice").id, tenant=tenant_a,
            action="project.create", resource_type="tenant", reason_code="authz.market_denied",
        )  # fmt: skip


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        ({"title": "x" * 121, "market": "US"}, 403, "authz.market_denied"),  # gate 7 before gate 8
        ({"title": "", "market": "XX"}, 403, "authz.market_denied"),
        ({"title": "x" * 121, "market": "UK"}, 422, "request.invalid"),  # permitted: gate 8 speaks
        ({"title": "ok", "market": 5}, 422, "request.invalid"),  # not a string: gate 8 speaks
        ({"title": "ok"}, 422, "request.invalid"),
    ],
)
async def test_tl08_gate_7_is_evaluated_before_body_validation(
    open_lab: OpenLab, body: dict[str, Any], status: int, code: str
) -> None:
    """gates.csv order: market_permit (7) precedes input_validation (8) whenever `market` is a
    string; a body that cannot be evaluated at gate 7 falls through to gate 8."""
    lab: Lab = await open_lab()
    response = await lab.request(
        "POST",
        f"/v1/tenants/{lab.fx.tenant('A').id}/projects",
        headers=lab.bearer("alice"),
        json_body=body,
    )
    assert_problem(response, status=status, code=code)


async def test_tl08_a_nonexistent_market_looks_exactly_like_a_forbidden_one(
    open_lab: OpenLab,
) -> None:
    """D-31: the 403 must not map the market catalogue."""
    lab: Lab = await open_lab()
    tenant_a = lab.fx.tenant("A").id
    bodies = []
    for market in ("US", "XX"):
        response = await lab.request(
            "POST",
            f"/v1/tenants/{tenant_a}/projects",
            headers=lab.bearer("alice"),
            json_body={"title": "Pilot", "market": market},
        )
        problem = assert_problem(response, status=403, code="authz.market_denied")
        bodies.append(body_sans_request_id(problem))
    assert bodies[0] == bodies[1]


async def test_tl08_the_hidden_project_is_absent_from_lists_and_totals_and_leaves_no_trace(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    ids = _ids(lab)
    texts = []
    for path in (
        f"/v1/tenants/{ids['A']}/projects",
        f"/v1/projects/{ids['PA1']}",
        f"/v1/projects/{ids['PA1']}/contacts",
        f"/v1/tenants/{ids['A']}/audit",
    ):
        response = await lab.request("GET", path, headers=lab.bearer("alice"))
        assert response.status_code == 200, (path, response.text)
        texts.append(response.text)
    listing = await lab.request(
        "GET", f"/v1/tenants/{ids['A']}/projects", headers=lab.bearer("alice")
    )
    assert [item["id"] for item in listing.json()["items"]] == [ids["PA1"]]
    assert listing.json()["total"] == 1
    for text in texts:
        for needle in (
            "SENTINEL-TENANT-A US pilot",
            "SENTINEL-PRIV-EMAIL-CA2",
            "SENTINEL-PRIV-PHONE-CA2",
            ids["PA2"],
        ):
            assert needle not in text, f"hidden data leaked: {needle}"


async def test_tl08_granting_the_market_makes_the_project_visible_and_counted_at_once(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    ids = _ids(lab)
    lab.sql(
        "INSERT INTO tenant_market_access (tenant_id, market_id) "
        "SELECT t.id, m.id FROM tenants t, markets m WHERE t.slug = 'tenant-a' AND m.code = 'US'"
    )
    listing = await lab.request(
        "GET", f"/v1/tenants/{ids['A']}/projects", headers=lab.bearer("alice")
    )
    assert listing.json()["total"] == 2
    assert {item["id"] for item in listing.json()["items"]} == {ids["PA1"], ids["PA2"]}
    created = await lab.request(
        "POST",
        f"/v1/tenants/{ids['A']}/projects",
        headers=lab.bearer("alice"),
        json_body={"title": "Pilot", "market": "US"},
    )
    assert created.status_code == 201, created.text


# ---------------------------------------------------------------------------- TL-13 ----
async def test_tl13_a_membership_revoked_between_list_and_read_is_404_on_the_next_request(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    ids = _ids(lab)
    headers = lab.bearer("bob")  # one token across the revocation
    listing = await lab.request("GET", f"/v1/tenants/{ids['A']}/projects", headers=headers)
    assert listing.status_code == 200, listing.text
    assert [item["id"] for item in listing.json()["items"]] == [ids["PA1"]]
    first = await lab.request("GET", f"/v1/projects/{ids['PA1']}", headers=headers)
    assert first.status_code == 200, first.text

    lab.set_membership("bob", "A", status="revoked")
    for path in (f"/v1/projects/{ids['PA1']}", f"/v1/tenants/{ids['A']}/projects"):
        response = await lab.request("GET", path, headers=headers)
        assert_problem(response, status=404, code="resource.not_found")
        assert "SENTINEL" not in response.text

    lab.set_membership("bob", "A", status="active")  # nothing is cached in either direction
    again = await lab.request("GET", f"/v1/projects/{ids['PA1']}", headers=headers)
    assert again.status_code == 200, again.text


async def test_tl13_a_market_revoked_between_list_and_read_is_404_on_the_next_request(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    ids = _ids(lab)
    headers = lab.bearer("alice")
    listing = await lab.request("GET", f"/v1/tenants/{ids['A']}/projects", headers=headers)
    assert listing.json()["total"] == 1
    lab.sql(
        "DELETE FROM tenant_market_access WHERE "
        "tenant_id = (SELECT id FROM tenants WHERE slug = 'tenant-a') AND "
        "market_id = (SELECT id FROM markets WHERE code = 'UK')"
    )
    gone = await lab.request("GET", f"/v1/projects/{ids['PA1']}", headers=headers)
    assert_problem(gone, status=404, code="resource.not_found")
    empty = await lab.request("GET", f"/v1/tenants/{ids['A']}/projects", headers=headers)
    assert empty.json() == {"items": [], "next_cursor": None, "total": 0}
