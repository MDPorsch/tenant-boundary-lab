"""TL-09 and TL-19 (milestone M2): property-level exposure, totals and timing.

STATUS: written RED-FIRST for M2 (see test_m2_authorization.py). Expected field sets come from the
ORACLE (`field_policy.csv`) through tests/support_m2.py, never from application code.
"""

from __future__ import annotations

import statistics
import time
from collections.abc import Callable
from typing import Any

import pytest

from tests.harness import Lab, assert_no_leak, assert_problem
from tests.support_m2 import (
    insert_audit_rows,
    insert_projects,
    oracle_resource_fields,
)

pytestmark = pytest.mark.milestone("M2")

OpenLab = Callable[..., Any]

# (who, tenant key, project key, invoice key, role): every role, in a tenant where it exists
ACTORS = [
    ("alice", "A", "PA1", "IA1", "owner"),
    ("carla", "B", "PB1", "IB1", "admin"),
    ("dave", "A", "PA1", "IA1", "editor"),
    ("bob", "A", "PA1", "IA1", "viewer"),
]
ACTOR_IDS = [f"{who}-{role}" for who, _, _, _, role in ACTORS]


def _emails(lab: Lab) -> list[str]:
    return [p.email for p in lab.fx.principals]


def _assert_no_principal_email(lab: Lab, text: str) -> None:
    for email in _emails(lab):
        assert email not in text, f"a principal e-mail ({email.split('@')[0]}) leaked"


# ---------------------------------------------------------------------------- TL-09 ----
@pytest.mark.parametrize(("who", "tenant", "project", "invoice", "role"), ACTORS, ids=ACTOR_IDS)
async def test_tl09_every_readable_surface_exposes_exactly_the_oracle_fields(
    open_lab: OpenLab, *, who: str, tenant: str, project: str, invoice: str, role: str
) -> None:
    lab: Lab = await open_lab()
    tenant_id, project_id = lab.fx.tenant(tenant).id, lab.fx.project(project).id
    headers = lab.bearer(who)

    listing = await lab.request("GET", f"/v1/tenants/{tenant_id}/projects", headers=headers)
    assert listing.status_code == 200, listing.text
    assert set(listing.json()) == {"items", "next_cursor", "total"}
    assert listing.json()["items"], "the fixture tenant has at least one visible project"
    for item in listing.json()["items"]:
        assert set(item) == oracle_resource_fields("project", "project.list_item", role)

    detail = await lab.request("GET", f"/v1/projects/{project_id}", headers=headers)
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert set(body) == oracle_resource_fields("project", "project.detail", role) | {"contacts"}
    assert body["contacts"], "the fixture project has a public contact"
    for contact in body["contacts"]:
        assert set(contact) == oracle_resource_fields("contact", "project.detail", role)

    for path in (
        f"/v1/invoices/{lab.fx.invoice(invoice).id}",
        f"/v1/projects/{project_id}/invoices/{lab.fx.invoice(invoice).id}",
    ):
        response = await lab.request("GET", path, headers=headers)
        assert response.status_code == 200, response.text
        assert set(response.json()) == oracle_resource_fields("invoice", "invoice.detail", role)


async def test_tl09_the_owner_principal_is_shown_to_editors_and_above_only(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    pa1 = lab.fx.project("PA1").id
    shown = {}
    for who in ("alice", "dave", "bob"):
        response = await lab.request("GET", f"/v1/projects/{pa1}", headers=lab.bearer(who))
        shown[who] = response.json().get("owner_principal_id")
    assert shown["alice"] == shown["dave"] == lab.fx.principal("frank").id
    assert shown["bob"] is None
    assert (
        "owner_principal_id"
        not in (await lab.request("GET", f"/v1/projects/{pa1}", headers=lab.bearer("bob"))).json()
    )


@pytest.mark.parametrize(("who", "tenant", "project", "invoice", "role"), ACTORS, ids=ACTOR_IDS)
async def test_tl09_private_contact_fields_exist_on_the_contacts_surface_only(
    open_lab: OpenLab, *, who: str, tenant: str, project: str, invoice: str, role: str
) -> None:
    lab: Lab = await open_lab()
    tenant_id, project_id = lab.fx.tenant(tenant).id, lab.fx.project(project).id
    headers = lab.bearer(who)
    general = [
        f"/v1/tenants/{tenant_id}/projects",
        f"/v1/projects/{project_id}",
        f"/v1/invoices/{lab.fx.invoice(invoice).id}",
        f"/v1/tenants/{tenant_id}/me",
    ]
    for path in general:
        response = await lab.request("GET", path, headers=headers)
        assert response.status_code == 200, (path, response.text)
        assert_no_leak(response.text, lab.fx)
        _assert_no_principal_email(lab, response.text)

    contacts = await lab.request("GET", f"/v1/projects/{project_id}/contacts", headers=headers)
    if role in ("owner", "admin"):
        assert contacts.status_code == 200, contacts.text
        items = contacts.json()["items"]
        assert items
        for item in items:
            assert set(item) == oracle_resource_fields("contact", "contacts.private", role)
        assert lab.fx.private_sentinel in contacts.text
        _assert_no_principal_email(lab, contacts.text)
    else:  # no BOPLA fallback: a refusal, not a 200 with the fields removed
        assert_problem(contacts, status=403, code="authz.forbidden")
        assert_no_leak(contacts.text, lab.fx)


async def test_tl09_the_contacts_surface_holds_only_the_projects_own_contacts(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    response = await lab.request(
        "GET", f"/v1/projects/{lab.fx.project('PA1').id}/contacts", headers=lab.bearer("alice")
    )
    assert [c["public_name"] for c in response.json()["items"]] == ["Ada Example"]
    assert "SENTINEL-PRIV-EMAIL-CB1" not in response.text
    assert "SENTINEL-PRIV-EMAIL-CA2" not in response.text


@pytest.mark.parametrize(
    ("who", "tenant", "role"), [("alice", "A", "owner"), ("carla", "B", "admin")]
)
async def test_tl09_the_audit_surface_has_the_oracle_fields_and_only_its_own_tenants_rows(
    open_lab: OpenLab, who: str, tenant: str, role: str
) -> None:
    lab: Lab = await open_lab()
    tenant_id = lab.fx.tenant(tenant).id
    # noise from other tenants and from tenant-less (hidden) denials must never show up here
    await lab.request("GET", f"/v1/tenants/{lab.fx.tenant('C').id}/me", headers=lab.bearer("bob"))
    await lab.request(
        "PATCH",
        f"/v1/projects/{lab.fx.project('PB1').id}",
        headers=lab.bearer("bob"),
        json_body={"title": "x", "row_version": 1},
    )
    await lab.request(
        "PATCH",
        f"/v1/projects/{lab.fx.project('PA1').id}",
        headers=lab.bearer("bob"),
        json_body={"title": "x", "row_version": 1},
    )
    await lab.request(  # dave only VIEWS in B: a 403 that lands in tenant B's own log
        "PATCH",
        f"/v1/projects/{lab.fx.project('PB1').id}",
        headers=lab.bearer("dave"),
        json_body={"title": "x", "row_version": 1},
    )
    response = await lab.request("GET", f"/v1/tenants/{tenant_id}/audit", headers=lab.bearer(who))
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    assert items, "the tenant's own denial must be listed (anti-vacuity)"
    for item in items:
        assert set(item) == oracle_resource_fields("audit_event", "audit.list_item", role)
        assert item["tenant_id"] == tenant_id, "another tenant's (or a NULL-tenant) row leaked"
    assert_no_leak(response.text, lab.fx)
    _assert_no_principal_email(lab, response.text)
    assert [(i["action"], i["decision"]) for i in items] == [("project.write", "deny")]


async def test_tl09_error_bodies_never_carry_private_data_or_input(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    ids = {
        "PA1": lab.fx.project("PA1").id,
        "PB1": lab.fx.project("PB1").id,
        "A": lab.fx.tenant("A").id,
    }
    probes = [
        ("bob", "GET", f"/v1/projects/{ids['PA1']}/contacts", None, 403),
        ("bob", "GET", f"/v1/projects/{ids['PB1']}", None, 404),
        ("bob", "PATCH", f"/v1/projects/{ids['PA1']}", {"title": "x", "row_version": 1}, 403),
        (
            "alice",
            "PATCH",
            f"/v1/projects/{ids['PA1']}",
            {"title": "ECHO-ME", "row_version": 9},
            409,
        ),
        ("alice", "PATCH", f"/v1/projects/{ids['PA1']}", {"title": "ECHO-ME", "bogus": 1}, 422),
        ("alice", "GET", f"/v1/tenants/{ids['A']}/projects?limit=ECHO-ME", None, 422),
    ]
    for who, method, path, body, status in probes:
        response = await lab.request(method, path, headers=lab.bearer(who), json_body=body)
        assert response.status_code == status, (path, response.status_code, response.text)
        assert_no_leak(response.text, lab.fx, forbidden_tenants="BC")
        _assert_no_principal_email(lab, response.text)
        assert "ECHO-ME" not in response.text


# ---------------------------------------------------------------------------- TL-19 ----
async def _total(lab: Lab, who: str, tenant: str) -> tuple[int, int]:
    response = await lab.request(
        "GET", f"/v1/tenants/{lab.fx.tenant(tenant).id}/projects?limit=100", headers=lab.bearer(who)
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["total"], len(body["items"])


async def test_tl19_the_total_counts_only_what_the_actor_may_read(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    baseline = {
        who: await _total(lab, who, t) for who, t in (("alice", "A"), ("bob", "A"), ("carla", "B"))
    }
    assert baseline == {"alice": (1, 1), "bob": (1, 1), "carla": (1, 1)}

    insert_projects(lab, tenant="B", market="US", count=30, owner="carla")  # another tenant
    insert_projects(lab, tenant="A", market="US", count=20)  # tenant A, hidden market
    after = {
        who: await _total(lab, who, t) for who, t in (("alice", "A"), ("bob", "A"), ("carla", "B"))
    }
    assert after["alice"] == after["bob"] == (1, 1), "hidden rows changed an A total"
    assert after["carla"] == (31, 31)

    insert_projects(lab, tenant="A", market="UK", count=5)  # visible rows DO count
    assert await _total(lab, "alice", "A") == (6, 6)
    assert await _total(lab, "bob", "A") == (6, 6)


async def test_tl19_the_total_is_the_same_on_every_page(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    insert_projects(lab, tenant="A", market="UK", count=6)
    insert_projects(lab, tenant="A", market="US", count=9)  # hidden
    path = f"/v1/tenants/{lab.fx.tenant('A').id}/projects?limit=3"
    totals, seen = [], []
    cursor = None
    while True:
        url = path + (f"&cursor={cursor}" if cursor else "")
        body = (await lab.request("GET", url, headers=lab.bearer("alice"))).json()
        totals.append(body["total"])
        seen += [item["id"] for item in body["items"]]
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert set(totals) == {7}
    assert len(seen) == len(set(seen)) == 7


async def test_tl19_the_audit_total_ignores_other_tenants_and_tenantless_rows(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    path = f"/v1/tenants/{lab.fx.tenant('A').id}/audit"
    assert (await lab.request("GET", path, headers=lab.bearer("alice"))).json()["total"] == 0
    insert_audit_rows(lab, tenant="B", count=4)
    insert_audit_rows(lab, tenant=None, count=4)
    assert (await lab.request("GET", path, headers=lab.bearer("alice"))).json()["total"] == 0
    insert_audit_rows(lab, tenant="A", count=3)
    body = (await lab.request("GET", path, headers=lab.bearer("alice"))).json()
    assert body["total"] == 3
    assert len(body["items"]) == 3


async def _median(lab: Lab, path: str, headers: dict[str, str], runs: int) -> float:
    samples = []
    for _ in range(runs):
        started = time.perf_counter()
        response = await lab.request("GET", path, headers=headers)
        samples.append(time.perf_counter() - started)
        assert response.status_code == 404
    return statistics.median(samples)


async def test_tl19_timing_smoke_a_hidden_project_is_not_grossly_slower_than_a_missing_one(
    open_lab: OpenLab,
) -> None:
    """A GROSS-difference smoke test only. Constant-time behaviour is explicitly NOT claimed
    (LIMITATIONS L-07). Best of three rounds; the tolerance is a factor of five."""
    lab: Lab = await open_lab()
    headers = lab.bearer("alice")
    hidden = f"/v1/projects/{lab.fx.project('PA2').id}"  # exists, but its market is not permitted
    missing = f"/v1/projects/{lab.fx.never_seeded['project']}"
    ratios = []
    for _ in range(3):
        h = await _median(lab, hidden, headers, 25)
        m = await _median(lab, missing, headers, 25)
        ratios.append(max(h, m) / min(h, m))
    assert min(ratios) < 5.0, f"hidden vs missing latency ratios {ratios}"
