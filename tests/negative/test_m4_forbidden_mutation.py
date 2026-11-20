"""TL-17 (milestone M4): a refused write must leave business data untouched, and a "write, then
deny" bug is caught by a STATE diff even though its status code is exactly what the oracle expects.

STATUS: written RED-FIRST for M4. The patched-app sweep and the detector controls already hold (the
patched app was built right in M2); what fails until M4 ships is everything that needs the fifth
controlled flaw, WRITE_BEFORE_AUTHORIZATION (decision D-53). Never skipped, xfailed or weakened.

Independence: the judge is `tests.support_m4.diff_business`, a raw-SQL snapshot diff. It never calls
application code. Audit rows are not part of the diff (a denial appends one by design).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any, Final

import pytest
from sqlalchemy import text

from tests.harness import Lab, body_sans_request_id, norm_uuid
from tests.support_m2 import hexid
from tests.support_m4 import diff_business

pytestmark = pytest.mark.milestone("M4")

OpenLab = Callable[..., Any]
DENIALS: Final = frozenset({401, 403, 404})
PROBE_TITLE: Final = "TL-17 forbidden write"


def _requests(lab: Lab) -> dict[str, tuple[str, str, dict[str, object]]]:
    """Every write a refusal can be asked of: name -> (method, path, a VALID body)."""
    fx = lab.fx
    tenant = {key: fx.tenant(key).id for key in "ABC"}
    project = {key: fx.project(key).id for key in ("PA1", "PA2", "PB1", "PC1")}
    patch: dict[str, object] = {"title": PROBE_TITLE, "row_version": 1}
    return {
        "patch PA1": ("PATCH", f"/v1/projects/{project['PA1']}", patch),
        "patch PA2": ("PATCH", f"/v1/projects/{project['PA2']}", patch),
        "patch PB1": ("PATCH", f"/v1/projects/{project['PB1']}", patch),
        "patch PC1": ("PATCH", f"/v1/projects/{project['PC1']}", patch),
        "create A": (
            "POST", f"/v1/tenants/{tenant['A']}/projects", {"title": PROBE_TITLE, "market": "UK"},
        ),
        "create B": (
            "POST", f"/v1/tenants/{tenant['B']}/projects", {"title": PROBE_TITLE, "market": "US"},
        ),
        "create C": (
            "POST", f"/v1/tenants/{tenant['C']}/projects", {"title": PROBE_TITLE, "market": "UK"},
        ),
        "create A in US": (
            "POST", f"/v1/tenants/{tenant['A']}/projects", {"title": PROBE_TITLE, "market": "US"},
        ),
        "put A bob": (
            "PUT", f"/v1/tenants/{tenant['A']}/members/{fx.principal('bob').id}",
            {"role": "editor", "status": "active", "version": 1},
        ),
        "put B dave": (
            "PUT", f"/v1/tenants/{tenant['B']}/members/{fx.principal('dave').id}",
            {"role": "editor", "status": "active", "version": 1},
        ),
    }  # fmt: skip


# (request, principal or None for no token, why it must be refused)
DENIED: Final[tuple[tuple[str, str | None, str], ...]] = (
    ("patch PA1", "bob", "a viewer may not write"),
    ("patch PA1", "carla", "a member of another tenant"),
    ("patch PA1", "frank", "membership revoked"),
    ("patch PA1", "erin", "principal disabled"),
    ("patch PA1", None, "no credential"),
    ("patch PA2", "alice", "a project in a market tenant A may not use"),
    ("patch PB1", "alice", "an owner of A is nobody in B"),
    ("patch PB1", "dave", "a viewer in B"),
    ("patch PC1", "gina", "the tenant is suspended"),
    ("create A", "bob", "a viewer may not create"),
    ("create A", "carla", "a member of another tenant"),
    ("create A", None, "no credential"),
    ("create A in US", "alice", "the tenant has no access to that market"),
    ("create B", "dave", "a viewer in B"),
    ("create C", "gina", "the tenant is suspended"),
    ("put A bob", "bob", "a viewer may not change roles"),
    ("put A bob", "dave", "only an owner changes roles"),
    ("put A bob", "carla", "a member of another tenant"),
    ("put A bob", None, "no credential"),
    ("put B dave", "carla", "an admin is not an owner"),
)


async def _send(lab: Lab, name: str, who: str | None, body: object | None = None) -> Any:
    method, path, valid = _requests(lab)[name]
    headers = {} if who is None else lab.bearer(who)
    return await lab.request(method, path, headers=headers, json_body=valid if body is None else body)


def _title(lab: Lab, project: str) -> str:
    with lab.engine.connect() as conn:
        value = conn.execute(
            text("SELECT title FROM projects WHERE id = :id"),
            {"id": hexid(uuid.UUID(lab.fx.project(project).id))},
        ).scalar_one()
    return str(value)


# ----------------------------------------------------------- the patched app: no mutation ----
@pytest.mark.parametrize(
    ("name", "who", "why"), DENIED, ids=[f"{n}-by-{w or 'anonymous'}" for n, w, _ in DENIED]
)
async def test_tl17_a_denied_write_to_the_patched_app_changes_no_business_data(
    open_lab: OpenLab, name: str, who: str | None, why: str
) -> None:
    lab: Lab = await open_lab()
    before = lab.snapshot()
    response = await _send(lab, name, who)
    assert response.status_code in DENIALS, f"{why}: expected a denial, got {response.status_code}"
    assert diff_business(before, lab.snapshot()) == [], f"{why}: a refused write changed state"


@pytest.mark.parametrize(
    ("name", "who", "body", "status"),
    [
        ("patch PA1", "alice", {"title": PROBE_TITLE, "row_version": 99}, 409),
        ("patch PA1", "alice", {"title": PROBE_TITLE, "row_version": 1, "tenant_id": "x"}, 422),
        ("put A bob", "alice", {"role": "bogus", "status": "active", "version": 1}, 422),
        ("put A bob", "alice", {"role": "editor", "status": "active", "version": 99}, 409),
    ],
    ids=["stale-version", "unknown-key", "unknown-role", "stale-member-version"],
)
async def test_tl17_a_refused_request_from_an_authorised_user_changes_nothing_either(
    open_lab: OpenLab, name: str, who: str, body: dict[str, object], status: int
) -> None:
    lab: Lab = await open_lab()
    before = lab.snapshot()
    response = await _send(lab, name, who, body)
    assert response.status_code == status, response.text[:200]
    assert diff_business(before, lab.snapshot()) == []


async def test_tl17_the_last_owner_cannot_demote_herself_and_nothing_is_written(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    alice = lab.fx.principal("alice").id
    path = f"/v1/tenants/{lab.fx.tenant('A').id}/members/{alice}"
    before = lab.snapshot()
    response = await lab.request(
        "PUT", path, headers=lab.bearer("alice"),
        json_body={"role": "admin", "status": "active", "version": 1},
    )  # fmt: skip
    assert response.status_code == 409
    assert diff_business(before, lab.snapshot()) == []


# ------------------------------------------- the detector has teeth: it sees a real write ----
async def test_tl17_the_detector_sees_an_authorised_patch(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    before = lab.snapshot()
    response = await _send(lab, "patch PA1", "alice")
    assert response.status_code == 200
    changes = diff_business(before, lab.snapshot())
    assert [(c.table, c.kind) for c in changes] == [("projects", "modified")]
    assert norm_uuid(changes[0].key) == lab.fx.project("PA1").id
    assert _title(lab, "PA1") == PROBE_TITLE


async def test_tl17_the_detector_sees_an_authorised_create(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    before = lab.snapshot()
    response = await _send(lab, "create A", "alice")
    assert response.status_code == 201
    assert [(c.table, c.kind) for c in diff_business(before, lab.snapshot())] == [
        ("projects", "added")
    ]


async def test_tl17_the_detector_sees_an_authorised_membership_change(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    before = lab.snapshot()
    response = await _send(lab, "put A bob", "alice")
    assert response.status_code == 200
    assert [(c.table, c.kind) for c in diff_business(before, lab.snapshot())] == [
        ("memberships", "modified")
    ]


# ------------------- the vulnerable lab: write first, deny afterwards (flaw 5, decision D-53) ----
FLAW: Final = "WRITE_BEFORE_AUTHORIZATION"
# (principal, project, the denial the ORACLE expects and the flawed app still returns)
REFUSED_BUT_WRITTEN: Final = (
    ("bob", "PA1", 403),  # a viewer
    ("carla", "PA1", 404),  # a member of another tenant
    ("gina", "PC1", 403),  # the tenant is suspended
    ("alice", "PB1", 404),  # an owner of A is nobody in B
)


@pytest.mark.parametrize(("who", "project", "status"), REFUSED_BUT_WRITTEN)
async def test_tl17_write_before_authorization_persists_a_write_it_then_refuses(
    open_vuln: OpenLab, who: str, project: str, status: int
) -> None:
    lab: Lab = await open_vuln([FLAW])
    before = lab.snapshot()
    response = await _send(lab, f"patch {project}", who)
    assert response.status_code == status  # the status code is what the oracle expects ...
    changes = diff_business(before, lab.snapshot())
    assert [(c.table, c.kind) for c in changes] == [("projects", "modified")]  # ... state moved
    assert norm_uuid(changes[0].key) == lab.fx.project(project).id
    assert _title(lab, project) == PROBE_TITLE


async def test_tl17_the_flawed_answer_is_indistinguishable_from_the_patched_one(
    open_lab: OpenLab, open_vuln: OpenLab
) -> None:
    """Why a status-only test can never catch this bug: the response is the same."""
    patched: Lab = await open_lab()
    flawed: Lab = await open_vuln([FLAW])
    good = await _send(patched, "patch PC1", "gina")
    bad = await _send(flawed, "patch PC1", "gina")
    assert good.status_code == bad.status_code == 403
    assert good.json()["code"] == bad.json()["code"] == "tenant.suspended"
    assert body_sans_request_id(good).get("code") == body_sans_request_id(bad).get("code")


@pytest.mark.parametrize(("who", "project", "status"), REFUSED_BUT_WRITTEN)
async def test_tl17_without_the_flaw_the_same_request_writes_nothing(
    open_vuln: OpenLab, who: str, project: str, status: int
) -> None:
    lab: Lab = await open_vuln([])
    before = lab.snapshot()
    response = await _send(lab, f"patch {project}", who)
    assert response.status_code in DENIALS
    assert diff_business(before, lab.snapshot()) == []


@pytest.mark.parametrize(
    "other",
    ["TENANT_PREDICATE_OMITTED", "ROLE_CHECK_MISSING", "PRIVATE_PROPERTY_SERIALIZED",
     "MARKET_BOUNDARY_OMITTED"],
)  # fmt: skip
async def test_tl17_no_other_flaw_makes_a_suspended_tenants_write_stick(
    open_vuln: OpenLab, other: str
) -> None:
    """Confinement: the suspended-tenant refusal survives every OTHER flaw, so only flaw 5 can
    explain a changed row."""
    lab: Lab = await open_vuln([other])
    before = lab.snapshot()
    response = await _send(lab, "patch PC1", "gina")
    assert response.status_code == 403
    assert diff_business(before, lab.snapshot()) == []


async def test_tl17_the_flaw_never_writes_to_a_project_that_does_not_exist(
    open_vuln: OpenLab,
) -> None:
    lab: Lab = await open_vuln([FLAW])
    ghost = lab.fx.never_seeded["project"]
    before = lab.snapshot()
    response = await lab.request(
        "PATCH", f"/v1/projects/{ghost}", headers=lab.bearer("gina"),
        json_body={"title": PROBE_TITLE, "row_version": 1},
    )  # fmt: skip
    assert response.status_code == 404
    assert diff_business(before, lab.snapshot()) == []


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"title": PROBE_TITLE, "row_version": 99}, 409),
        ({"title": PROBE_TITLE, "row_version": 1, "tenant_id": "x"}, 422),
        ({"title": "", "row_version": 1}, 422),
    ],
    ids=["stale-version", "unknown-key", "empty-title"],
)
async def test_tl17_the_flaw_only_moves_authorization_validation_still_comes_first(
    open_vuln: OpenLab, body: dict[str, object], status: int
) -> None:
    lab: Lab = await open_vuln([FLAW])
    before = lab.snapshot()
    response = await _send(lab, "patch PC1", "gina", body)
    assert response.status_code == status
    assert diff_business(before, lab.snapshot()) == []
