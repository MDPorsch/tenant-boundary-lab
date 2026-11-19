"""TL-11 and TL-12 (milestone M2): the last owner, and two writers on one version.

STATUS: written RED-FIRST for M2 (see test_m2_authorization.py).

TL-12 here is the SEQUENTIAL case plus a best-effort concurrent run on SQLite. SQLite cannot
represent PostgreSQL row-lock behaviour (LIMITATIONS L-08): the trustworthy concurrent test is M5.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from tests.harness import (
    Lab,
    assert_no_leak,
    assert_problem,
    assert_single_deny_audit,
    body_sans_request_id,
    norm_uuid,
)

pytestmark = pytest.mark.milestone("M2")

OpenLab = Callable[..., Any]


def _member_path(lab: Lab, tenant: str, principal: str) -> str:
    return f"/v1/tenants/{lab.fx.tenant(tenant).id}/members/{lab.fx.principal(principal).id}"


async def _put(  # noqa: PLR0917 - a terse positional helper used by every test
    lab: Lab, who: str, tenant: str, principal: str, role: str, status: str, version: int
) -> httpx.Response:
    return await lab.request(
        "PUT",
        _member_path(lab, tenant, principal),
        headers=lab.bearer(who),
        json_body={"role": role, "status": status, "version": version},
    )


def _row(lab: Lab, principal: str, tenant: str) -> tuple[Any, ...]:
    """(role, status, version) of one membership, by NATURAL keys."""
    with lab.engine.connect() as conn:
        from sqlalchemy import text  # noqa: PLC0415

        return tuple(
            conn.execute(
                text(
                    "SELECT role, status, version FROM memberships WHERE "
                    "principal_id = (SELECT id FROM principals WHERE email = :e) AND "
                    "tenant_id = (SELECT id FROM tenants WHERE slug = :s)"
                ),
                {"e": lab.fx.principal(principal).email, "s": lab.fx.tenant(tenant).slug},
            ).one()
        )


def _audit(lab: Lab, who: str, tenant: str | None, code: str) -> dict[str, Any]:
    return {
        "actor": lab.fx.principal(who).id,
        "tenant": lab.fx.tenant(tenant).id if tenant else None,
        "action": "member.role.write",
        "resource_type": "membership",
        "reason_code": code,
    }


# ---------------------------------------------------------------------------- TL-11 ----
@pytest.mark.parametrize(
    ("role", "status"),
    [("admin", "active"), ("viewer", "active"), ("owner", "revoked"), ("admin", "revoked")],
)
async def test_tl11_the_sole_owner_cannot_demote_or_revoke_herself(
    open_lab: OpenLab, role: str, status: str
) -> None:
    lab: Lab = await open_lab()
    before = lab.snapshot()
    response = await _put(lab, "alice", "A", "alice", role, status, 1)
    problem = assert_problem(response, status=409, code="conflict.last_owner")
    assert problem["errors"] == []
    assert_single_deny_audit(
        lab, before, response, **_audit(lab, "alice", "A", "conflict.last_owner")
    )
    assert _row(lab, "alice", "A") == ("owner", "active", 1)  # atomic: nothing was written


async def test_tl11_a_stale_version_is_reported_before_the_last_owner_rule(
    open_lab: OpenLab,
) -> None:
    """Gate 10 (precondition) precedes gate 11 (invariant)."""
    lab: Lab = await open_lab()
    before = lab.snapshot()
    response = await _put(lab, "alice", "A", "alice", "admin", "active", 99)
    assert_problem(response, status=409, code="conflict.stale_revision")
    assert_single_deny_audit(
        lab, before, response, **_audit(lab, "alice", "A", "conflict.stale_revision")
    )


async def test_tl11_with_a_second_active_owner_the_first_may_step_down(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    lab.set_membership("dave", "A", role="owner")
    response = await _put(lab, "alice", "A", "alice", "admin", "active", 1)
    assert response.status_code == 200, response.text
    assert response.json() == {
        "principal_id": lab.fx.principal("alice").id,
        "tenant_id": lab.fx.tenant("A").id,
        "role": "admin",
        "status": "active",
        "version": 2,
    }
    me = await lab.request(
        "GET", f"/v1/tenants/{lab.fx.tenant('A').id}/me", headers=lab.bearer("alice")
    )
    assert me.json()["role"] == "admin"  # enforced on the very next request
    # ... and now dave is the sole owner, so the rule applies to him
    before = lab.snapshot()
    blocked = await _put(lab, "dave", "A", "dave", "viewer", "active", 1)
    assert_problem(blocked, status=409, code="conflict.last_owner")
    assert lab.snapshot().business == before.business


async def test_tl11_a_revoked_second_owner_does_not_count(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    lab.set_membership("dave", "A", role="owner", status="revoked")
    before = lab.snapshot()
    response = await _put(lab, "alice", "A", "alice", "admin", "active", 1)
    assert_problem(response, status=409, code="conflict.last_owner")
    assert lab.snapshot().business == before.business


NON_OWNER_WRITES = [
    ("bob", "A", "bob", "owner"),  # viewer self-promotion
    ("dave", "A", "dave", "owner"),  # editor self-promotion
    ("dave", "A", "bob", "editor"),  # editor changing someone else
    ("bob", "A", "alice", "viewer"),  # viewer demoting the owner
    ("carla", "B", "carla", "owner"),  # an ADMIN may not promote herself either
    ("dave", "B", "dave", "admin"),  # viewer in B (his role in A does not apply)
]


@pytest.mark.parametrize(("who", "tenant", "target", "role"), NON_OWNER_WRITES)
async def test_tl11_a_non_owner_put_is_403_including_self_promotion(
    open_lab: OpenLab, who: str, tenant: str, target: str, role: str
) -> None:
    lab: Lab = await open_lab()
    current = _row(lab, target, tenant)
    before = lab.snapshot()
    response = await _put(lab, who, tenant, target, role, "active", current[2])
    assert_problem(response, status=403, code="authz.forbidden")
    assert_single_deny_audit(lab, before, response, **_audit(lab, who, tenant, "authz.forbidden"))
    assert _row(lab, target, tenant) == current


async def test_tl11_the_owner_of_one_tenant_has_no_reach_into_another(open_lab: OpenLab) -> None:
    """alice owns A, is nobody in B: B's members are as hidden as a tenant that does not exist."""
    lab: Lab = await open_lab()
    seen = []
    for tenant_id, principal_id in (
        (lab.fx.tenant("B").id, lab.fx.principal("carla").id),
        (lab.fx.never_seeded["tenant"], lab.fx.principal("carla").id),
    ):
        before = lab.snapshot()
        response = await lab.request(
            "PUT",
            f"/v1/tenants/{tenant_id}/members/{principal_id}",
            headers=lab.bearer("alice"),
            json_body={"role": "owner", "status": "active", "version": 1},
        )
        problem = assert_problem(response, status=404, code="resource.not_found")
        assert_no_leak(response.text, lab.fx, forbidden_tenants="BC")
        assert_single_deny_audit(
            lab, before, response, **_audit(lab, "alice", None, "resource.not_found")
        )
        seen.append(body_sans_request_id(problem))
    assert seen[0] == seen[1]


async def test_tl11_an_unknown_member_is_404_and_a_ghost_principal_looks_the_same(
    open_lab: OpenLab,
) -> None:
    """The route updates EXISTING memberships only (D-34): carla is real but not in A."""
    lab: Lab = await open_lab()
    bodies = []
    for principal_id in (lab.fx.principal("carla").id, lab.fx.never_seeded["principal"]):
        before = lab.snapshot()
        response = await lab.request(
            "PUT",
            f"/v1/tenants/{lab.fx.tenant('A').id}/members/{principal_id}",
            headers=lab.bearer("alice"),
            json_body={"role": "viewer", "status": "active", "version": 1},
        )
        problem = assert_problem(response, status=404, code="resource.not_found")
        assert_single_deny_audit(
            lab, before, response, **_audit(lab, "alice", "A", "resource.not_found")
        )
        bodies.append(body_sans_request_id(problem))
    assert bodies[0] == bodies[1]


async def test_tl11_a_suspended_tenants_owner_cannot_change_memberships(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    before = lab.snapshot()
    response = await _put(lab, "gina", "C", "gina", "admin", "active", 1)
    assert_problem(response, status=403, code="tenant.suspended")
    assert_single_deny_audit(lab, before, response, **_audit(lab, "gina", "C", "tenant.suspended"))


async def test_tl11_an_owner_changes_a_role_and_it_is_enforced_on_the_next_request(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    tenant_a = lab.fx.tenant("A").id
    before = lab.snapshot()
    response = await _put(lab, "alice", "A", "bob", "editor", "active", 1)
    assert response.status_code == 200, response.text
    assert response.json() == {
        "principal_id": lab.fx.principal("bob").id,
        "tenant_id": tenant_a,
        "role": "editor",
        "status": "active",
        "version": 2,
    }
    after = lab.snapshot()
    changed = [r for r in after.business["memberships"] if r not in before.business["memberships"]]
    assert len(changed) == 1, "exactly the targeted membership row may change"
    for table in after.business:
        if table != "memberships":
            assert after.business[table] == before.business[table], table
    created = await lab.request(
        "POST",
        f"/v1/tenants/{tenant_a}/projects",
        headers=lab.bearer("bob"),
        json_body={"title": "Now I can", "market": "UK"},
    )
    assert created.status_code == 201, created.text  # bob is an editor from this request on

    revoked = await _put(lab, "alice", "A", "bob", "editor", "revoked", 2)
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["version"] == 3
    gone = await lab.request("GET", f"/v1/tenants/{tenant_a}/me", headers=lab.bearer("bob"))
    assert_problem(gone, status=404, code="resource.not_found")


async def test_tl11_a_revoked_member_can_be_reactivated(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    assert _row(lab, "frank", "A") == ("editor", "revoked", 2)
    response = await _put(lab, "alice", "A", "frank", "editor", "active", 2)
    assert response.status_code == 200, response.text
    me = await lab.request(
        "GET", f"/v1/tenants/{lab.fx.tenant('A').id}/me", headers=lab.bearer("frank")
    )
    assert me.status_code == 200, me.text
    assert me.json()["role"] == "editor"


async def test_tl11_a_successful_change_is_audited_in_the_tenants_log(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    before = lab.snapshot()
    response = await _put(lab, "alice", "A", "bob", "admin", "active", 1)
    rows = lab.snapshot().new_audit_rows(before)
    assert len(rows) == 1
    row = rows[0]
    assert norm_uuid(row["actor_id"]) == lab.fx.principal("alice").id
    assert norm_uuid(row["tenant_id"]) == lab.fx.tenant("A").id
    assert (row["action"], row["resource_type"], row["decision"], row["reason_code"]) == (
        "member.role.write", "membership", "allow", "ok",
    )  # fmt: skip
    assert norm_uuid(row["resource_id"]) == lab.fx.principal("bob").id
    assert norm_uuid(row["correlation_id"]) == response.headers["x-request-id"]


# ---------------------------------------------------------------------------- TL-12 ----
def _project_row(lab: Lab) -> tuple[Any, ...]:
    """(title, status, row_version) of PA1, found by NATURAL keys (its owner and tenant)."""
    from sqlalchemy import text  # noqa: PLC0415

    with lab.engine.connect() as conn:
        return tuple(
            conn.execute(
                text(
                    "SELECT title, status, row_version FROM projects WHERE "
                    "owner_principal_id = (SELECT id FROM principals WHERE email = :e) AND "
                    "tenant_id = (SELECT id FROM tenants WHERE slug = :s)"
                ),
                {"e": lab.fx.principal("frank").email, "s": lab.fx.tenant("A").slug},
            ).one()
        )


async def _patch(lab: Lab, who: str, body: dict[str, Any]) -> httpx.Response:
    return await lab.request(
        "PATCH", f"/v1/projects/{lab.fx.project('PA1').id}", headers=lab.bearer(who), json_body=body
    )


async def test_tl12_a_second_writer_with_the_same_version_gets_409_and_changes_nothing(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    first = await _patch(lab, "alice", {"title": "renamed-first", "row_version": 1})
    assert first.status_code == 200, first.text
    assert first.json()["row_version"] == 2
    assert first.json()["title"] == "renamed-first"

    before = lab.snapshot()
    second = await _patch(lab, "dave", {"title": "renamed-second", "row_version": 1})
    assert_problem(second, status=409, code="conflict.stale_revision")
    assert "renamed-second" not in second.text
    assert_single_deny_audit(
        lab, before, second, actor=lab.fx.principal("dave").id, tenant=lab.fx.tenant("A").id,
        action="project.write", resource_type="project", reason_code="conflict.stale_revision",
    )  # fmt: skip
    assert _project_row(lab) == ("renamed-first", "active", 2), "the final row equals the winner"


async def test_tl12_every_successful_write_increments_the_version_by_exactly_one(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    version = 1
    for n in range(4):
        response = await _patch(
            lab, "alice", {"status": ("archived", "draft")[n % 2], "row_version": version}
        )
        assert response.status_code == 200, response.text
        version += 1
        assert response.json()["row_version"] == version
    assert (await _patch(lab, "alice", {"title": "stale", "row_version": 1})).status_code == 409


@pytest.mark.parametrize("stale", [2, 3, 2147483647])
async def test_tl12_any_version_other_than_the_stored_one_is_409(
    open_lab: OpenLab, stale: int
) -> None:
    lab: Lab = await open_lab()
    response = await _patch(lab, "alice", {"title": "x", "row_version": stale})
    assert_problem(response, status=409, code="conflict.stale_revision")
    assert _project_row(lab)[2] == 1


async def test_tl12_two_concurrent_writers_with_one_version_have_exactly_one_winner_on_sqlite(
    open_lab: OpenLab,
) -> None:
    """Best effort on SQLite (single writer). The trustworthy run is M5 on PostgreSQL."""
    lab: Lab = await open_lab()
    for _ in range(3):
        stored = _project_row(lab)
        version = stored[2]
        results = await asyncio.gather(
            _patch(lab, "alice", {"title": f"renamed-a-{version}", "row_version": version}),
            _patch(lab, "dave", {"title": f"renamed-b-{version}", "row_version": version}),
        )
        statuses = sorted(r.status_code for r in results)
        assert statuses == [200, 409], statuses
        winner = next(r for r in results if r.status_code == 200)
        loser = next(r for r in results if r.status_code == 409)
        assert_problem(loser, status=409, code="conflict.stale_revision")
        assert _project_row(lab) == (winner.json()["title"], "active", version + 1)


async def test_tl12_membership_versions_are_preconditions_too(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    assert (await _put(lab, "alice", "A", "bob", "editor", "active", 1)).status_code == 200
    before = lab.snapshot()
    stale = await _put(lab, "alice", "A", "bob", "admin", "active", 1)
    assert_problem(stale, status=409, code="conflict.stale_revision")
    assert_single_deny_audit(
        lab, before, stale, **_audit(lab, "alice", "A", "conflict.stale_revision")
    )
    assert _row(lab, "bob", "A") == ("editor", "active", 2)
