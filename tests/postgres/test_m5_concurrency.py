"""TL-11, TL-12 and TL-20 on a REAL PostgreSQL server (milestone M5).

The spec: "SQLite is not an adequate substitute for PostgreSQL row-locking behaviour; concurrency
tests must run on PostgreSQL". SQLite serialises every writer, so none of these races can happen
there. Each race below is made DETERMINISTIC (tests/support_m5.py): a separate transaction holds a
row lock, the request under test is observed to be blocked on it, a competing change is started, and
only then is the lock released.

STATUS: written RED-FIRST for M5. TL-12 already held (the version compare-and-set is atomic). The
rest failed against the M2 write statements, which re-check authority with plain `EXISTS` sub-selects
that take no lock (D-35 closed the check-then-write gap but not the race between two transactions):
see DECISIONS D-56.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from typing import Any, Final

import httpx
import psycopg
import pytest

from tests.harness import Lab
from tests.support_m5 import Competing, Holder, conninfo, wait_until_blocked

pytestmark = [pytest.mark.docker, pytest.mark.postgres, pytest.mark.milestone("M5")]

OpenPg = Callable[..., Any]
STATUS_OK: Final = 200


# ------------------------------------------------------------------------------ helpers ----
def _scalar(lab: Lab, sql: str, *params: Any) -> Any:
    with psycopg.connect(conninfo(lab.engine), autocommit=True) as conn:
        row = conn.execute(sql, params).fetchone()
    assert row is not None
    return row[0]


async def _patch(
    lab: Lab, who: str, project: str = "PA1", title: str = "TL-20 write"
) -> httpx.Response:
    return await lab.request(
        "PATCH", f"/v1/projects/{lab.fx.project(project).id}", headers=lab.bearer(who),
        json_body={"title": title, "row_version": 1},
    )  # fmt: skip


async def _put(
    lab: Lab, actor: str, tenant: str, target: str, role: str, *, version: int = 1
) -> httpx.Response:
    return await lab.request(
        "PUT", f"/v1/tenants/{lab.fx.tenant(tenant).id}/members/{lab.fx.principal(target).id}",
        headers=lab.bearer(actor), json_body={"role": role, "status": "active", "version": version},
    )  # fmt: skip


async def _create(
    lab: Lab, who: str, tenant: str = "A", title: str = "TL-20 create"
) -> httpx.Response:
    return await lab.request(
        "POST", f"/v1/tenants/{lab.fx.tenant(tenant).id}/projects", headers=lab.bearer(who),
        json_body={"title": title, "market": "UK"},
    )  # fmt: skip


def _title(lab: Lab, project: str = "PA1") -> str:
    return str(
        _scalar(lab, "SELECT title FROM projects WHERE id = %s::uuid", lab.fx.project(project).id)
    )


# ---------------------------------------------------------------------------- TL-12 ----
async def test_tl12_pg_eight_concurrent_writers_on_one_version_have_exactly_one_winner(
    open_pg_lab: OpenPg,
) -> None:
    lab: Lab = await open_pg_lab()
    responses = await asyncio.gather(
        *[_patch(lab, who, title=f"writer {n}") for n, who in enumerate(["alice", "dave"] * 4)]
    )
    assert sorted(r.status_code for r in responses) == [200] + [409] * 7
    winner = next(r for r in responses if r.status_code == STATUS_OK)
    assert _title(lab) == winner.json()["title"]
    assert (
        _scalar(
            lab, "SELECT row_version FROM projects WHERE id = %s::uuid", lab.fx.project("PA1").id
        )
        == 2
    )


async def test_tl12_pg_concurrent_role_changes_on_one_version_have_exactly_one_winner(
    open_pg_lab: OpenPg,
) -> None:
    lab: Lab = await open_pg_lab()
    responses = await asyncio.gather(
        *[_put(lab, "alice", "A", "bob", role) for role in ("editor", "admin") * 3]
    )
    assert sorted(r.status_code for r in responses) == [200] + [409] * 5
    version = _scalar(
        lab, "SELECT version FROM memberships WHERE tenant_id = %s::uuid AND principal_id = %s::uuid",
        lab.fx.tenant("A").id, lab.fx.principal("bob").id,
    )  # fmt: skip
    assert version == 2


# ---------------------------------------------------------------------------- TL-11 ----
async def test_tl11_pg_two_owners_demoting_each_other_at_once_leave_one_owner(
    open_pg_lab: OpenPg,
) -> None:
    """Write skew: each demotion checks 'another active owner exists' against a snapshot in which the
    other owner is still active, so at READ COMMITTED both pass and the tenant is left with none."""
    lab: Lab = await open_pg_lab()
    lab.set_membership("dave", "A", role="owner")  # alice and dave now own tenant A
    tenant, alice, dave = (
        lab.fx.tenant("A").id,
        lab.fx.principal("alice").id,
        lab.fx.principal("dave").id,
    )
    with Holder(lab) as holder:
        holder.lock(
            "SELECT 1 FROM memberships WHERE tenant_id = %s::uuid "
            "AND principal_id IN (%s::uuid, %s::uuid) FOR UPDATE", tenant, alice, dave,
        )  # fmt: skip
        first = asyncio.create_task(_put(lab, "alice", "A", "dave", "viewer"))
        second = asyncio.create_task(_put(lab, "dave", "A", "alice", "viewer"))
        await wait_until_blocked(lab, 2)
        holder.release()
        responses = await asyncio.gather(first, second)
    assert sorted(r.status_code for r in responses) == [200, 409], [r.text[:120] for r in responses]
    owners = _scalar(
        lab, "SELECT count(*) FROM memberships WHERE tenant_id = %s::uuid "
        "AND role = 'owner' AND status = 'active'", tenant,
    )  # fmt: skip
    assert owners == 1, "a tenant must never be left without an active owner"


# ---------------------------------------------------------------------------- quota ----
async def test_tl20_pg_concurrent_creates_at_the_quota_never_exceed_it(open_pg_lab: OpenPg) -> None:
    """The quota is 1000 projects. At 999 two creators both see room (write skew) unless creation is
    serialised per tenant."""
    lab: Lab = await open_pg_lab()
    tenant = lab.fx.tenant("A").id
    with psycopg.connect(conninfo(lab.engine), autocommit=True) as conn:
        conn.execute(
            "INSERT INTO projects (id, tenant_id, market_id, owner_principal_id, title, status, row_version) "
            "SELECT gen_random_uuid(), %s::uuid, (SELECT id FROM markets WHERE code = 'UK'), "
            "(SELECT id FROM principals WHERE email = %s), 'bulk ' || g, 'active', 1 "
            "FROM generate_series(1, 997) AS g",
            (tenant, lab.fx.principal("alice").email),
        )
    assert _scalar(lab, "SELECT count(*) FROM projects WHERE tenant_id = %s::uuid", tenant) == 999
    with Holder(lab) as holder:
        holder.lock("SELECT 1 FROM tenants WHERE id = %s::uuid FOR UPDATE", tenant)
        creators = [asyncio.create_task(_create(lab, who)) for who in ("alice", "dave")]
        await wait_until_blocked(lab, 2)
        holder.release()
        responses = await asyncio.gather(*creators)
    assert sorted(r.status_code for r in responses) == [201, 429], [r.text[:100] for r in responses]
    assert _scalar(lab, "SELECT count(*) FROM projects WHERE tenant_id = %s::uuid", tenant) == 1000


# ---------------------------------------------------------------------------- TL-20 ----
def _revocations(lab: Lab) -> dict[str, tuple[str, tuple[str, ...]]]:
    tenant, dave = lab.fx.tenant("A").id, lab.fx.principal("dave").id
    return {
        "membership_revoked": (
            "UPDATE memberships SET status = 'revoked' WHERE principal_id = %s::uuid AND tenant_id = %s::uuid",
            (dave, tenant),
        ),
        "role_downgraded": (
            "UPDATE memberships SET role = 'viewer' WHERE principal_id = %s::uuid AND tenant_id = %s::uuid",
            (dave, tenant),
        ),
        "principal_disabled": (
            "UPDATE principals SET status = 'disabled' WHERE id = %s::uuid",
            (dave,),
        ),
        "tenant_suspended": (
            "UPDATE tenants SET state = 'suspended' WHERE id = %s::uuid",
            (tenant,),
        ),
        "market_access_removed": (
            "DELETE FROM tenant_market_access WHERE tenant_id = %s::uuid "
            "AND market_id = (SELECT id FROM markets WHERE code = 'UK')",
            (tenant,),
        ),
    }


@pytest.mark.parametrize(
    "change",
    [
        "membership_revoked",
        "role_downgraded",
        "principal_disabled",
        "tenant_suspended",
        "market_access_removed",
    ],
)
async def test_tl20_pg_an_authority_change_cannot_complete_while_a_patch_that_relies_on_it_is_in_flight(
    open_pg_lab: OpenPg, change: str
) -> None:
    """The in-flight PATCH is held at its UPDATE by a row lock. If the competing change completes now,
    the revoked write can still commit AFTER the revocation did: authority changes and writes are not
    ordered. They must be: the change has to wait for the write (or the write be refused)."""
    lab: Lab = await open_pg_lab()
    statement, params = _revocations(lab)[change]
    with Holder(lab) as holder:
        holder.lock(
            "SELECT 1 FROM projects WHERE id = %s::uuid FOR UPDATE", lab.fx.project("PA1").id
        )
        write = asyncio.create_task(_patch(lab, "dave"))
        await wait_until_blocked(lab, 1)
        competing = Competing(lab, statement, *params)
        got_through = await competing.got_through(blocked=2)
        holder.release()
        response = await write
        await competing.finish()
    assert not got_through, f"{change} completed while the write that relies on it was in flight"
    # whichever way they were ordered, a refused write wrote nothing
    assert response.status_code in {200, 403, 404, 409}, response.text[:200]
    assert (_title(lab) == "TL-20 write") == (response.status_code == STATUS_OK)


@pytest.mark.parametrize(
    "change", ["membership_revoked", "tenant_suspended", "market_access_removed"]
)
async def test_tl20_pg_an_authority_change_cannot_complete_while_a_create_that_relies_on_it_is_in_flight(
    open_pg_lab: OpenPg, change: str
) -> None:
    lab: Lab = await open_pg_lab()
    statement, params = _revocations(lab)[change]
    tenant = lab.fx.tenant("A").id
    with Holder(lab) as holder:
        holder.lock(
            "SELECT 1 FROM markets WHERE code = 'UK' FOR UPDATE"
        )  # the INSERT's foreign key waits
        create = asyncio.create_task(_create(lab, "dave"))
        await wait_until_blocked(lab, 1)
        competing = Competing(lab, statement, *params)
        got_through = await competing.got_through(blocked=2)
        holder.release()
        response = await create
        await competing.finish()
    assert not got_through, f"{change} completed while the create that relies on it was in flight"
    created = _scalar(
        lab,
        "SELECT count(*) FROM projects WHERE title = 'TL-20 create' AND tenant_id = %s::uuid",
        tenant,
    )
    assert created == (1 if response.status_code == 201 else 0)


async def test_tl20_pg_an_actors_own_revocation_cannot_complete_while_her_role_change_is_in_flight(
    open_pg_lab: OpenPg,
) -> None:
    lab: Lab = await open_pg_lab()
    tenant, alice, bob = (
        lab.fx.tenant("A").id,
        lab.fx.principal("alice").id,
        lab.fx.principal("bob").id,
    )
    with Holder(lab) as holder:
        holder.lock(
            "SELECT 1 FROM memberships WHERE tenant_id = %s::uuid AND principal_id = %s::uuid FOR UPDATE",
            tenant, bob,
        )  # fmt: skip
        change = asyncio.create_task(_put(lab, "alice", "A", "bob", "editor"))
        await wait_until_blocked(lab, 1)
        competing = Competing(
            lab, "UPDATE memberships SET status = 'revoked' WHERE principal_id = %s::uuid AND tenant_id = %s::uuid",
            alice, tenant,
        )  # fmt: skip
        got_through = await competing.got_through(blocked=2)
        holder.release()
        response = await change
        await competing.finish()
    assert not got_through, "the actor's revocation completed while her role change was in flight"
    assert response.status_code in {200, 403, 404, 409}, response.text[:200]


def test_the_helpers_use_a_fresh_database_per_lab() -> None:
    """A guard on the harness itself: databases are unique, so no test can see another's rows."""
    from tests.pgserver import server  # noqa: PLC0415

    first, second = server().new_database_url(), server().new_database_url()
    assert first != second
    assert uuid.UUID(first.rsplit("tl_", 1)[1]) != uuid.UUID(second.rsplit("tl_", 1)[1])
