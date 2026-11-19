"""Authority that changes BETWEEN a handler's pre-check and its write (decision D-35, L-16).

A wrapper changes the database from outside at exactly that moment. The write statement must then
change nothing; the handler re-runs the gates and reports the TRUE reason (404/403/409/429), writes
one denial row and no `allow` row. If the race never settles, the request fails closed with 503.

This is the window an HTTP test normally cannot hit, which is why the statement-level predicates
exist at all: without them these tests would see a 200 and a changed row.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import pytest

from tenantlab.lab.patched import service
from tests.harness import Lab, assert_problem
from tests.support_m2 import hexid, insert_projects

pytestmark = pytest.mark.milestone("M2")

OpenLab = Callable[..., Any]


def _race_once(monkeypatch: pytest.MonkeyPatch, name: str, action: Callable[[], None]) -> list[int]:
    """Run `action` once, just before the first call of `service.<name>` returns."""
    original = getattr(service, name)
    calls: list[int] = []

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        if len(calls) == 1:
            action()
        return original(*args, **kwargs)

    monkeypatch.setattr(service, name, wrapper)
    return calls


def _scalar(lab: Lab, statement: str, **params: Any) -> Any:
    from sqlalchemy import text  # noqa: PLC0415

    with lab.engine.connect() as conn:
        return conn.execute(text(statement), params).scalar()


TENANT_A = "(SELECT id FROM tenants WHERE slug = 'tenant-a')"


def _audit_rows(lab: Lab) -> list[dict[str, Any]]:
    return list(lab.snapshot().audit)


def _project(lab: Lab) -> tuple[Any, ...]:
    from sqlalchemy import text  # noqa: PLC0415

    with lab.engine.connect() as conn:
        return tuple(
            conn.execute(
                text(
                    "SELECT title, status, row_version FROM projects WHERE owner_principal_id = "
                    "(SELECT id FROM principals WHERE email = :e)"
                ),
                {"e": lab.fx.principal("frank").email},
            ).one()
        )


# (what changes underneath, expected status, code, audit tenant is the tenant?)
AUTHORITY_RACES: dict[str, tuple[Callable[[Lab], None], int, str, bool]] = {
    "membership_revoked": (
        lambda lab: lab.set_membership("dave", "A", status="revoked"),
        404, "resource.not_found", False,
    ),
    "role_downgraded": (
        lambda lab: lab.set_membership("dave", "A", role="viewer"),
        403, "authz.forbidden", True,
    ),
    "tenant_suspended": (
        lambda lab: lab.set_tenant_state("A", "suspended"), 403, "tenant.suspended", True,
    ),
    "principal_disabled": (
        lambda lab: lab.sql(
            "UPDATE principals SET status = 'disabled' WHERE email = :e",
            e=lab.fx.principal("dave").email,
        ),
        403,
        "auth.principal_disabled",
        False,
    ),
}  # fmt: skip


# --------------------------------------------------------------------------------- PATCH ----
@pytest.mark.parametrize("race", sorted(AUTHORITY_RACES))
async def test_a_patch_racing_an_authority_change_writes_nothing(
    open_lab: OpenLab, monkeypatch: pytest.MonkeyPatch, race: str
) -> None:
    lab: Lab = await open_lab()
    change, status, code, tenant_scoped = AUTHORITY_RACES[race]
    stored = _project(lab)
    _race_once(monkeypatch, "project_version", lambda: change(lab))
    response = await lab.request(
        "PATCH",
        f"/v1/projects/{lab.fx.project('PA1').id}",
        headers=lab.bearer("dave"),
        json_body={"title": "must not land", "row_version": 1},
    )
    assert_problem(response, status=status, code=code)
    assert _project(lab) == stored, "the write landed although authority had changed"
    rows = _audit_rows(lab)
    assert [(r["decision"], r["reason_code"]) for r in rows] == [("deny", code)]
    assert (rows[0]["tenant_id"] is not None) is tenant_scoped


async def test_a_patch_racing_a_market_revocation_writes_nothing(
    open_lab: OpenLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab: Lab = await open_lab()
    stored = _project(lab)
    _race_once(
        monkeypatch, "project_version",
        lambda: lab.sql(
            "DELETE FROM tenant_market_access WHERE tenant_id = "
            "(SELECT id FROM tenants WHERE slug = 'tenant-a') AND market_id = "
            "(SELECT id FROM markets WHERE code = 'UK')"
        ),
    )  # fmt: skip
    response = await lab.request(
        "PATCH", f"/v1/projects/{lab.fx.project('PA1').id}", headers=lab.bearer("dave"),
        json_body={"title": "must not land", "row_version": 1},
    )  # fmt: skip
    assert_problem(response, status=404, code="resource.not_found")
    assert _project(lab) == stored


async def test_a_patch_racing_another_writer_reports_a_stale_version_not_a_server_error(
    open_lab: OpenLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab: Lab = await open_lab()
    _race_once(
        monkeypatch, "project_version",
        lambda: lab.sql(
            "UPDATE projects SET title = 'the other writer', row_version = 2 "
            "WHERE owner_principal_id = (SELECT id FROM principals WHERE email = :e)",
            e=lab.fx.principal("frank").email,
        ),
    )  # fmt: skip
    response = await lab.request(
        "PATCH", f"/v1/projects/{lab.fx.project('PA1').id}", headers=lab.bearer("alice"),
        json_body={"title": "must not land", "row_version": 1},
    )  # fmt: skip
    assert_problem(response, status=409, code="conflict.stale_revision")
    assert _project(lab) == ("the other writer", "active", 2)


# --------------------------------------------------------------------------------- create ----
@pytest.mark.parametrize("race", sorted(AUTHORITY_RACES))
async def test_a_create_racing_an_authority_change_writes_nothing(
    open_lab: OpenLab, monkeypatch: pytest.MonkeyPatch, race: str
) -> None:
    lab: Lab = await open_lab()
    change, status, code, _ = AUTHORITY_RACES[race]
    before = lab.snapshot()
    _race_once(monkeypatch, "count_projects", lambda: change(lab))
    response = await lab.request(
        "POST", f"/v1/tenants/{lab.fx.tenant('A').id}/projects", headers=lab.bearer("dave"),
        json_body={"title": "must not land", "market": "UK"},
    )  # fmt: skip
    assert_problem(response, status=status, code=code)
    assert lab.snapshot().business["projects"] == before.business["projects"]
    assert [r["decision"] for r in _audit_rows(lab)] == ["deny"]


async def test_a_create_racing_a_market_revocation_is_market_denied(
    open_lab: OpenLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab: Lab = await open_lab()
    before = lab.snapshot()
    _race_once(
        monkeypatch, "count_projects",
        lambda: lab.sql(
            "DELETE FROM tenant_market_access WHERE tenant_id = "
            "(SELECT id FROM tenants WHERE slug = 'tenant-a') AND market_id = "
            "(SELECT id FROM markets WHERE code = 'UK')"
        ),
    )  # fmt: skip
    response = await lab.request(
        "POST", f"/v1/tenants/{lab.fx.tenant('A').id}/projects", headers=lab.bearer("alice"),
        json_body={"title": "must not land", "market": "UK"},
    )  # fmt: skip
    assert_problem(response, status=403, code="authz.market_denied")
    assert lab.snapshot().business["projects"] == before.business["projects"]


async def test_a_create_racing_the_quota_is_429_and_never_the_1001st_row(
    open_lab: OpenLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The count the handler read said 'room for one more'; before the insert another writer took
    the last slot. The insert statement itself counts again and writes nothing."""
    lab: Lab = await open_lab()
    insert_projects(lab, tenant="A", market="UK", count=service.MAX_PROJECTS_PER_TENANT - 3)
    _race_once(
        monkeypatch,
        "count_projects",
        lambda: insert_projects(lab, tenant="A", market="UK", count=1),
    )
    response = await lab.request(
        "POST", f"/v1/tenants/{lab.fx.tenant('A').id}/projects", headers=lab.bearer("alice"),
        json_body={"title": "the 1001st", "market": "UK"},
    )  # fmt: skip
    assert_problem(response, status=429, code="quota.exceeded")
    assert _scalar(lab, "SELECT count(*) FROM projects WHERE title = 'the 1001st'") == 0
    total = _scalar(lab, f"SELECT count(*) FROM projects WHERE tenant_id = {TENANT_A}")  # noqa: S608
    assert total == service.MAX_PROJECTS_PER_TENANT


# ------------------------------------------------------------------------------ membership ----
@pytest.mark.parametrize(
    ("race", "status", "code"),
    [
        ("actor_revoked", 404, "resource.not_found"),
        ("actor_demoted", 403, "authz.forbidden"),
        ("tenant_suspended", 403, "tenant.suspended"),
        ("target_version_bumped", 409, "conflict.stale_revision"),
    ],
)
async def test_a_membership_change_racing_an_authority_change_writes_nothing(
    open_lab: OpenLab, monkeypatch: pytest.MonkeyPatch, race: str, status: int, code: str
) -> None:
    lab: Lab = await open_lab()
    changes: dict[str, Callable[[], None]] = {
        "actor_revoked": lambda: lab.set_membership("alice", "A", status="revoked"),
        "actor_demoted": lambda: lab.set_membership("alice", "A", role="admin"),
        "tenant_suspended": lambda: lab.set_tenant_state("A", "suspended"),
        "target_version_bumped": lambda: lab.sql(
            "UPDATE memberships SET version = 7 WHERE principal_id = "
            "(SELECT id FROM principals WHERE email = :e)",
            e=lab.fx.principal("bob").email,
        ),
    }
    _race_once(monkeypatch, "get_membership", changes[race])
    response = await lab.request(
        "PUT",
        f"/v1/tenants/{lab.fx.tenant('A').id}/members/{lab.fx.principal('bob').id}",
        headers=lab.bearer("alice"),
        json_body={"role": "admin", "status": "active", "version": 1},
    )
    assert_problem(response, status=status, code=code)
    role = _scalar(
        lab,
        "SELECT role FROM memberships WHERE principal_id = "
        "(SELECT id FROM principals WHERE email = :e)",
        e=lab.fx.principal("bob").email,
    )
    assert role == "viewer", "bob was promoted although the owner's authority had changed"
    assert [(r["decision"], r["reason_code"]) for r in _audit_rows(lab)] == [("deny", code)]


async def test_the_last_owner_rule_holds_against_a_race_not_only_a_pre_check(
    open_lab: OpenLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two owners; alice steps down. The pre-check sees dave as the other owner. Before the write,
    dave is revoked. The statement itself must refuse, leaving the tenant with an owner."""
    lab: Lab = await open_lab()
    lab.set_membership("dave", "A", role="owner")
    _race_once(
        monkeypatch, "get_membership", lambda: lab.set_membership("dave", "A", status="revoked")
    )
    response = await lab.request(
        "PUT",
        f"/v1/tenants/{lab.fx.tenant('A').id}/members/{lab.fx.principal('alice').id}",
        headers=lab.bearer("alice"),
        json_body={"role": "admin", "status": "active", "version": 1},
    )
    assert_problem(response, status=409, code="conflict.last_owner")
    owners = _scalar(
        lab,
        "SELECT count(*) FROM memberships WHERE role = 'owner' AND status = 'active' "  # noqa: S608
        f"AND tenant_id = {TENANT_A}",
    )
    assert owners == 1, "the tenant was left without an active owner"


# ---------------------------------------------------------------- a race that never settles ----
@pytest.mark.parametrize(
    ("method", "path_template", "body", "function"),
    [
        ("PATCH", "/v1/projects/{PA1}", {"title": "x", "row_version": 1}, "update_project"),
        ("POST", "/v1/tenants/{A}/projects", {"title": "x", "market": "UK"}, "create_project"),
        (
            "PUT",
            "/v1/tenants/{A}/members/{BOB}",
            {"role": "editor", "status": "active", "version": 1},
            "update_membership",
        ),
    ],
)
async def test_a_write_that_keeps_losing_the_race_fails_closed_with_503(
    open_lab: OpenLab,
    monkeypatch: pytest.MonkeyPatch,
    *,
    method: str,
    path_template: str,
    body: dict[str, Any],
    function: str,
) -> None:
    lab: Lab = await open_lab()
    attempts: list[int] = []
    never = None if function == "create_project" else False

    def always_lost(*args: Any, **kwargs: Any) -> Any:
        attempts.append(1)
        return never

    monkeypatch.setattr(service, function, always_lost)
    path = path_template.format(
        PA1=lab.fx.project("PA1").id, A=lab.fx.tenant("A").id, BOB=lab.fx.principal("bob").id
    )
    before = lab.snapshot()
    response = await lab.request(method, path, headers=lab.bearer("alice"), json_body=body)
    assert_problem(response, status=503, code="service.unavailable")
    assert len(attempts) == 3, "the handler must retry a bounded number of times, then fail closed"
    after = lab.snapshot()
    assert after.business == before.business
    assert after.audit == before.audit, "no allow row, no deny row: nothing happened"


def test_hexid_is_the_storage_form() -> None:
    value = uuid.uuid4()
    assert hexid(value) == value.hex


# ------------------------------------------------ the target vanishes after the gates passed ----
async def test_a_project_that_vanishes_after_the_gates_is_a_plain_404_with_a_tenant_audit_row(
    open_lab: OpenLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No route deletes anything, but the database can change underneath the request. The handler
    re-runs the gates for the true reason and, finding none, answers the ordinary 404."""
    lab: Lab = await open_lab()
    monkeypatch.setattr(service, "get_project", lambda *a, **k: None)
    before = lab.snapshot()
    response = await lab.request(
        "GET", f"/v1/projects/{lab.fx.project('PA1').id}", headers=lab.bearer("alice")
    )
    assert_problem(response, status=404, code="resource.not_found")
    after = lab.snapshot()
    assert after.business == before.business
    assert [(r["decision"], r["reason_code"]) for r in after.new_audit_rows(before)] == [
        ("deny", "resource.not_found")
    ]


async def test_an_invoice_that_vanishes_after_the_gates_is_a_404(
    open_lab: OpenLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab: Lab = await open_lab()
    monkeypatch.setattr(service, "get_invoice", lambda *a, **k: None)
    response = await lab.request(
        "GET", f"/v1/invoices/{lab.fx.invoice('IA1').id}", headers=lab.bearer("alice")
    )
    assert_problem(response, status=404, code="resource.not_found")


async def test_a_project_that_vanishes_before_a_patch_is_a_404_and_nothing_is_written(
    open_lab: OpenLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab: Lab = await open_lab()
    stored = _project(lab)
    monkeypatch.setattr(service, "project_version", lambda *a, **k: None)
    response = await lab.request(
        "PATCH", f"/v1/projects/{lab.fx.project('PA1').id}", headers=lab.bearer("alice"),
        json_body={"title": "must not land", "row_version": 1},
    )  # fmt: skip
    assert_problem(response, status=404, code="resource.not_found")
    assert _project(lab) == stored


@pytest.mark.parametrize(
    ("method", "path_template", "body", "reader"),
    [
        ("POST", "/v1/tenants/{A}/projects", {"title": "x", "market": "UK"}, "get_project"),
        ("PATCH", "/v1/projects/{PA1}", {"title": "x", "row_version": 1}, "get_project"),
        (
            "PUT",
            "/v1/tenants/{A}/members/{BOB}",
            {"role": "editor", "status": "active", "version": 1},
            "get_membership",
        ),
    ],
)
async def test_a_committed_write_whose_read_back_fails_is_503_never_a_wrong_body(
    open_lab: OpenLab,
    monkeypatch: pytest.MonkeyPatch,
    *,
    method: str,
    path_template: str,
    body: dict[str, Any],
    reader: str,
) -> None:
    """The read-back after the commit 'cannot' fail. If it does, the client gets a fail-closed
    503 rather than a made-up success body; the change itself (and its audit row) is committed."""
    lab: Lab = await open_lab()
    real = getattr(service, reader)
    calls: list[int] = []

    def read_back(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        # membership: the pre-check read must work, only the post-commit read is sabotaged
        return None if reader == "get_project" or len(calls) > 1 else real(*args, **kwargs)

    monkeypatch.setattr(service, reader, read_back)
    if method == "PATCH":  # keep the pre-checks working: only the post-commit read-back fails
        monkeypatch.setattr(service, "project_version", lambda db, pid: 1)
    path = path_template.format(
        PA1=lab.fx.project("PA1").id, A=lab.fx.tenant("A").id, BOB=lab.fx.principal("bob").id
    )
    response = await lab.request(method, path, headers=lab.bearer("alice"), json_body=body)
    assert_problem(response, status=503, code="service.unavailable")
    assert [r["decision"] for r in lab.snapshot().audit] == ["allow"]
