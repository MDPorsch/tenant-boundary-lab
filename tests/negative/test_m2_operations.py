"""M2 operations: exact response shapes, success audit rows, quota, atomicity.

STATUS: written RED-FIRST for M2 (see test_m2_authorization.py). These tests are the positive
controls for every denial in the other M2 files (a deny-everything server would pass those) and pin
docs/api-contract.md s10 exactly. Not part of one catalogue case.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime
from typing import Any

import pytest
from sqlalchemy import text

from tests.harness import (
    BUSINESS_TABLES,
    Lab,
    Snapshot,
    assert_problem,
    assert_single_deny_audit,
    norm_uuid,
)
from tests.support_m2 import (
    MAX_PROJECTS_PER_TENANT,
    body_routes,
    insert_contacts,
    insert_projects,
)

pytestmark = pytest.mark.milestone("M2")

OpenLab = Callable[..., Any]
UUID4 = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"


def _changed(before: Snapshot, after: Snapshot) -> set[str]:
    return {t for t in before.business if before.business[t] != after.business[t]}


def _item(lab: Lab, key: str, **override: Any) -> dict[str, Any]:
    p = lab.fx.project(key)
    market = {"A": "UK", "B": "US", "C": "UK"}[p.tenant]
    base = {
        "id": p.id,
        "tenant_id": lab.fx.tenant(p.tenant).id,
        "market": market,
        "title": p.title,
        "status": p.status,
        "row_version": p.row_version,
    }
    return {**base, **override}


# ------------------------------------------------------------------------------ reads ----
@pytest.mark.parametrize(
    ("who", "tenant", "project"),
    [
        ("alice", "A", "PA1"),
        ("bob", "A", "PA1"),
        ("dave", "A", "PA1"),
        ("carla", "B", "PB1"),
        ("dave", "B", "PB1"),
    ],
)
async def test_the_project_list_is_the_exact_page(
    open_lab: OpenLab, who: str, tenant: str, project: str
) -> None:
    lab: Lab = await open_lab()
    response = await lab.request(
        "GET", f"/v1/tenants/{lab.fx.tenant(tenant).id}/projects", headers=lab.bearer(who)
    )
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].split(";")[0] == "application/json"
    assert response.json() == {"items": [_item(lab, project)], "next_cursor": None, "total": 1}


async def test_the_project_detail_embeds_public_contacts_and_hides_the_owner_from_viewers(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    pa1 = lab.fx.project("PA1").id
    contact = {"id": lab.fx.contacts[0].id, "public_name": "Ada Example"}
    editor = await lab.request("GET", f"/v1/projects/{pa1}", headers=lab.bearer("dave"))
    assert editor.json() == {
        **_item(lab, "PA1"),
        "contacts": [contact],
        "owner_principal_id": lab.fx.principal("frank").id,
    }
    viewer = await lab.request("GET", f"/v1/projects/{pa1}", headers=lab.bearer("bob"))
    assert viewer.json() == {**_item(lab, "PA1"), "contacts": [contact]}


async def test_ordinary_reads_write_nothing_at_all(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    ids = {k: lab.fx.project(k).id for k in ("PA1",)} | {"A": lab.fx.tenant("A").id}
    before = lab.snapshot()
    for who, path in (
        ("alice", f"/v1/tenants/{ids['A']}/projects"),
        ("bob", f"/v1/projects/{ids['PA1']}"),
        ("alice", f"/v1/invoices/{lab.fx.invoice('IA1').id}"),
        ("alice", f"/v1/tenants/{ids['A']}/audit"),
        ("alice", f"/v1/tenants/{ids['A']}/me"),
    ):
        response = await lab.request("GET", path, headers=lab.bearer(who))
        assert response.status_code == 200, (path, response.text)
    assert lab.snapshot() == before


# --------------------------------------------------------------------- private contacts ----
async def test_private_contacts_are_served_to_admins_and_the_read_is_audited(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    pa1 = lab.fx.project("PA1").id
    before = lab.snapshot()
    response = await lab.request("GET", f"/v1/projects/{pa1}/contacts", headers=lab.bearer("alice"))
    assert response.status_code == 200, response.text
    assert response.json() == {
        "items": [
            {
                "id": lab.fx.contacts[0].id,
                "public_name": "Ada Example",
                "email_private": lab.fx.contacts[0].email_private,
                "phone_private": lab.fx.contacts[0].phone_private,
            }
        ],
        "next_cursor": None,
        "total": 1,
    }
    after = lab.snapshot()
    assert after.business == before.business
    rows = after.new_audit_rows(before)
    assert len(rows) == 1
    row = rows[0]
    assert norm_uuid(row["actor_id"]) == lab.fx.principal("alice").id
    assert norm_uuid(row["tenant_id"]) == lab.fx.tenant("A").id
    assert (row["action"], row["resource_type"], row["decision"], row["reason_code"]) == (
        "contact.private.read", "contact", "allow", "ok",
    )  # fmt: skip
    assert norm_uuid(row["resource_id"]) == pa1
    assert norm_uuid(row["correlation_id"]) == response.headers["x-request-id"]
    assert lab.fx.private_sentinel not in str(row), "the audit row must not hold the data"


async def test_an_admin_reads_only_her_own_tenants_contacts(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    own = await lab.request(
        "GET", f"/v1/projects/{lab.fx.project('PB1').id}/contacts", headers=lab.bearer("carla")
    )
    assert own.status_code == 200, own.text
    assert [c["public_name"] for c in own.json()["items"]] == ["Bea Example"]
    other = await lab.request(
        "GET", f"/v1/projects/{lab.fx.project('PA1').id}/contacts", headers=lab.bearer("carla")
    )
    assert_problem(other, status=404, code="resource.not_found")


async def test_private_contacts_are_paginated_in_id_order(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    extra = insert_contacts(lab, project="PA1", count=5)
    expected = sorted([lab.fx.contacts[0].id, *extra])
    path = f"/v1/projects/{lab.fx.project('PA1').id}/contacts"
    pages, cursor = [], None
    while True:
        query = "?limit=2" + (f"&cursor={cursor}" if cursor else "")
        body = (await lab.request("GET", path + query, headers=lab.bearer("alice"))).json()
        assert body["total"] == 6
        pages.append([c["id"] for c in body["items"]])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert [len(p) for p in pages] == [2, 2, 2]
    assert [i for page in pages for i in page] == expected


async def test_the_detail_embeds_at_most_100_contacts(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    insert_contacts(lab, project="PA1", count=130)
    response = await lab.request(
        "GET", f"/v1/projects/{lab.fx.project('PA1').id}", headers=lab.bearer("alice")
    )
    assert len(response.json()["contacts"]) == 100


# ------------------------------------------------------------------------------ create ----
async def test_an_editor_creates_a_project_and_the_server_sets_every_owned_field(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    method, path, _, _, body = body_routes(lab)["create"]
    before = lab.snapshot()
    response = await lab.request(method, path, headers=lab.bearer("dave"), json_body=body)
    assert response.status_code == 201, response.text
    created = response.json()
    assert set(created) == {
        "id", "tenant_id", "market", "title", "status", "row_version", "contacts",
        "owner_principal_id",
    }  # fmt: skip
    assert re.match(UUID4, created["id"])
    assert created["tenant_id"] == lab.fx.tenant("A").id
    assert created["owner_principal_id"] == lab.fx.principal("dave").id
    assert (created["market"], created["title"], created["status"], created["row_version"]) == (
        "UK", "A new project", "draft", 1,
    )  # fmt: skip
    assert created["contacts"] == []

    after = lab.snapshot()
    assert _changed(before, after) == {"projects"}
    assert len(after.business["projects"]) == len(before.business["projects"]) + 1
    rows = after.new_audit_rows(before)
    assert len(rows) == 1
    row = rows[0]
    assert (row["action"], row["resource_type"], row["decision"], row["reason_code"]) == (
        "project.create", "project", "allow", "ok",
    )  # fmt: skip
    assert norm_uuid(row["resource_id"]) == created["id"]
    assert norm_uuid(row["actor_id"]) == lab.fx.principal("dave").id
    assert norm_uuid(row["tenant_id"]) == lab.fx.tenant("A").id
    assert norm_uuid(row["correlation_id"]) == response.headers["x-request-id"]

    for who in ("alice", "bob"):  # visible to everyone who may read the tenant's projects
        listing = await lab.request(
            "GET", f"/v1/tenants/{lab.fx.tenant('A').id}/projects", headers=lab.bearer(who)
        )
        assert listing.json()["total"] == 2
        assert created["id"] in {i["id"] for i in listing.json()["items"]}


async def test_each_create_gets_its_own_id(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    _, path, _, _, body = body_routes(lab)["create"]
    ids = {
        (await lab.request("POST", path, headers=lab.bearer("alice"), json_body=body)).json()["id"]
        for _ in range(3)
    }
    assert len(ids) == 3


async def test_a_tenant_cannot_create_in_a_market_only_another_tenant_has(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    path = f"/v1/tenants/{lab.fx.tenant('B').id}/projects"
    ok = await lab.request(
        "POST", path, headers=lab.bearer("carla"), json_body={"title": "B", "market": "US"}
    )
    assert ok.status_code == 201, ok.text
    denied = await lab.request(
        "POST", path, headers=lab.bearer("carla"), json_body={"title": "B", "market": "UK"}
    )
    assert_problem(denied, status=403, code="authz.market_denied")


async def test_the_project_quota_is_1000_per_tenant_and_counts_hidden_projects(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    tenant_a = lab.fx.tenant("A").id
    # A already holds PA1 (visible) and PA2 (hidden market): 2 rows. Fill to 999.
    insert_projects(lab, tenant="A", market="UK", count=MAX_PROJECTS_PER_TENANT - 3)
    path = f"/v1/tenants/{tenant_a}/projects"
    last = await lab.request(
        "POST", path, headers=lab.bearer("alice"), json_body={"title": "No. 1000", "market": "UK"}
    )
    assert last.status_code == 201, last.text

    before = lab.snapshot()
    over = await lab.request(
        "POST", path, headers=lab.bearer("alice"), json_body={"title": "No. 1001", "market": "UK"}
    )
    assert_problem(over, status=429, code="quota.exceeded")
    assert_single_deny_audit(
        lab, before, over, actor=lab.fx.principal("alice").id, tenant=tenant_a,
        action="project.create", resource_type="tenant", reason_code="quota.exceeded",
    )  # fmt: skip

    other = await lab.request(  # the quota is per tenant
        "POST", f"/v1/tenants/{lab.fx.tenant('B').id}/projects", headers=lab.bearer("carla"),
        json_body={"title": "B is unaffected", "market": "US"},
    )  # fmt: skip
    assert other.status_code == 201, other.text


# ------------------------------------------------------------------------------- patch ----
async def test_a_patch_changes_exactly_the_requested_fields_and_bumps_the_version(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    pa1 = lab.fx.project("PA1").id
    before = lab.snapshot()
    response = await lab.request(
        "PATCH", f"/v1/projects/{pa1}", headers=lab.bearer("alice"),
        json_body={"title": "Renamed", "status": "archived", "row_version": 1},
    )  # fmt: skip
    assert response.status_code == 200, response.text
    assert response.json() == {
        **_item(lab, "PA1", title="Renamed", status="archived", row_version=2),
        "contacts": [{"id": lab.fx.contacts[0].id, "public_name": "Ada Example"}],
        "owner_principal_id": lab.fx.principal("frank").id,
    }
    after = lab.snapshot()
    assert _changed(before, after) == {"projects"}
    old_rows = set(before.business["projects"])
    new_rows = [r for r in after.business["projects"] if r not in old_rows]
    assert len(new_rows) == 1, "exactly one project row may change"
    rows = after.new_audit_rows(before)
    assert [(r["action"], r["decision"], r["reason_code"]) for r in rows] == [
        ("project.write", "allow", "ok")
    ]
    assert norm_uuid(rows[0]["resource_id"]) == pa1
    assert norm_uuid(rows[0]["correlation_id"]) == response.headers["x-request-id"]


@pytest.mark.parametrize(
    ("body", "title", "status"),
    [
        ({"title": "Only the title"}, "Only the title", "active"),
        ({"status": "draft"}, "SENTINEL-TENANT-A UK launch", "draft"),
        (
            {"status": "active"},
            "SENTINEL-TENANT-A UK launch",
            "active",
        ),  # same value: still versioned
    ],
)
async def test_a_patch_leaves_the_fields_it_does_not_mention_alone(
    open_lab: OpenLab, body: dict[str, str], title: str, status: str
) -> None:
    lab: Lab = await open_lab()
    response = await lab.request(
        "PATCH", f"/v1/projects/{lab.fx.project('PA1').id}", headers=lab.bearer("dave"),
        json_body={**body, "row_version": 1},
    )  # fmt: skip
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["title"], body["status"], body["row_version"]) == (title, status, 2)


# -------------------------------------------------------------------------------- audit ----
async def test_the_audit_list_is_newest_first_typed_and_paginated(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    pa1, tenant_a = lab.fx.project("PA1").id, lab.fx.tenant("A").id
    await lab.request(
        "PATCH",
        f"/v1/projects/{pa1}",
        headers=lab.bearer("bob"),
        json_body={"title": "x", "row_version": 1},
    )
    await lab.request(
        "PATCH",
        f"/v1/projects/{pa1}",
        headers=lab.bearer("alice"),
        json_body={"title": "y", "row_version": 1},
    )
    await lab.request("GET", f"/v1/projects/{pa1}/contacts", headers=lab.bearer("alice"))

    full = (
        await lab.request("GET", f"/v1/tenants/{tenant_a}/audit", headers=lab.bearer("alice"))
    ).json()
    assert full["total"] == 3
    assert [(i["action"], i["decision"]) for i in full["items"]] == [
        ("contact.private.read", "allow"),
        ("project.write", "allow"),
        ("project.write", "deny"),
    ]  # newest first
    ids = [i["id"] for i in full["items"]]
    assert ids == sorted(ids, reverse=True)
    for item in full["items"]:
        assert isinstance(item["id"], int)
        stamp = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
        assert stamp.tzinfo is not None

    pages, cursor = [], None
    while True:
        query = "?limit=2" + (f"&cursor={cursor}" if cursor else "")
        body = (
            await lab.request(
                "GET", f"/v1/tenants/{tenant_a}/audit{query}", headers=lab.bearer("alice")
            )
        ).json()
        pages.append([i["id"] for i in body["items"]])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert [len(p) for p in pages] == [2, 1]
    assert [i for page in pages for i in page] == ids


# ------------------------------------------------------------------ audit is atomic (D-37) ----
def _business_rows(lab: Lab) -> dict[str, list[Any]]:
    with lab.engine.connect() as conn:
        return {
            t: [tuple(r) for r in conn.execute(text(f"SELECT * FROM {t} ORDER BY 1"))]  # noqa: S608
            for t in BUSINESS_TABLES
        }


@pytest.mark.parametrize("route", ["create", "patch", "put"])
async def test_a_mutation_whose_audit_row_cannot_be_written_is_rolled_back_and_503(
    open_lab: OpenLab, route: str
) -> None:
    """The change and its audit row commit together or not at all."""
    lab: Lab = await open_lab()
    method, path, _, _, body = body_routes(lab)[route]
    before = _business_rows(lab)
    lab.sql("DROP TABLE audit_events")
    response = await lab.request(method, path, headers=lab.bearer("alice"), json_body=body)
    assert_problem(response, status=503, code="service.unavailable")
    assert _business_rows(lab) == before, "the change survived a failed audit write"
