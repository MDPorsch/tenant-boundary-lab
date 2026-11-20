"""Shared by the M5 sweep and the Hypothesis properties: every route, every kind of caller, every kind
of target, and ONE checker that judges a response against facts that do not come from the
application: the fixtures, the authorization matrix (docs/authorization-matrix.md) and a raw-SQL
state diff (tests/support_m4.py).

Independence (as in tests/harness.py): the checker never imports application code. The route table
below is a literal copy of docs/api-contract.md s2; tests/unit/test_route_registry.py already pins
the app's registry to that document, so a drift shows up there.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import httpx
from sqlalchemy import create_engine

from tenantlab.schemas.errors import PROBLEM_MEDIA_TYPE, ProblemDetail
from tests.harness import AUDIENCE, BASE_URL, ISSUER, KeyPair, Lab, TokenMint
from tests.support_m4 import diff_business

# (name, method, path template, kind of the target, needs a body)
ROUTES: Final = (
    ("me", "GET", "/v1/tenants/{tenant}/me", "tenant", False),
    ("list", "GET", "/v1/tenants/{tenant}/projects", "tenant", False),
    ("create", "POST", "/v1/tenants/{tenant}/projects", "tenant", True),
    ("audit", "GET", "/v1/tenants/{tenant}/audit", "tenant", False),
    ("put", "PUT", "/v1/tenants/{tenant}/members/{member}", "member", True),
    ("project", "GET", "/v1/projects/{project}", "project", False),
    ("patch", "PATCH", "/v1/projects/{project}", "project", True),
    ("contacts", "GET", "/v1/projects/{project}/contacts", "project", False),
    ("invoice", "GET", "/v1/invoices/{invoice}", "invoice", False),
    ("nested", "GET", "/v1/projects/{project}/invoices/{invoice}", "nested", False),
)  # fmt: skip
CREDENTIALS: Final = (
    "none", "garbage", "attacker", "alg_none", "hs256_confusion", "truncated",
    "alice", "bob", "carla", "dave", "erin", "frank", "gina",
)  # fmt: skip
BAD_TOKENS: Final = frozenset(
    {"none", "garbage", "attacker", "alg_none", "hs256_confusion", "truncated"}
)
WRITES: Final = frozenset({"create", "patch", "put"})
TENANTS: Final = ("A", "B", "C", "ghost")
PROJECTS: Final = ("PA1", "PA2", "PB1", "PC1", "ghost")
INVOICES: Final = ("IA1", "IA2", "IB1", "ghost")
#: the project a hidden-market tenant must never reveal, and an invoice that hangs off it
HIDDEN_PROJECT, HIDDEN_INVOICE = "PA2", "IA2"


@dataclass(frozen=True)
class Probe:
    """One request the sweep or a property sends."""

    route: str
    method: str
    path: str
    body: Any
    tenant: str | None  # the tenant key of the target, None for something that does not exist
    project: str | None
    invoice: str | None
    member: str | None = None


def build_probe(lab: Lab, route: str, target: dict[str, str]) -> Probe:
    """Resolve a route template against a target. `target` may carry tenant, project, invoice, member."""
    name, method, template, _kind, has_body = next(r for r in ROUTES if r[0] == route)
    fx = lab.fx
    ids = {"tenant": fx.never_seeded["tenant"], "project": fx.never_seeded["project"],
           "invoice": fx.never_seeded["invoice"], "member": fx.never_seeded["principal"]}  # fmt: skip
    tenant = project = invoice = member = None
    if "tenant" in target and target["tenant"] != "ghost":
        tenant = target["tenant"]
        ids["tenant"] = fx.tenant(tenant).id
    if "project" in target and target["project"] != "ghost":
        project = target["project"]
        ids["project"] = fx.project(project).id
    if "invoice" in target and target["invoice"] != "ghost":
        invoice = target["invoice"]
        ids["invoice"] = fx.invoice(invoice).id
    if "member" in target and target["member"] != "ghost":
        member = target["member"]
        ids["member"] = fx.principal(member).id
    owner = _owner_tenant(lab, project, invoice, tenant)
    body: Any = None
    if has_body:
        body = {
            "create": {"title": "TL-M5 probe", "market": "UK"},
            "patch": {"title": "TL-M5 probe", "row_version": 1},
            "put": {"role": "viewer", "status": "active", "version": 1},
        }[name]
    return Probe(name, method, template.format(**ids), body, owner, project, invoice, member)


def _owner_tenant(
    lab: Lab, project: str | None, invoice: str | None, tenant: str | None
) -> str | None:
    if tenant is not None:
        return tenant
    if project is not None:
        return lab.fx.project(project).tenant
    if invoice is not None:
        return lab.fx.invoice(invoice).tenant
    return None


def targets_for(route: str) -> list[dict[str, str]]:
    kind = next(r[3] for r in ROUTES if r[0] == route)
    if kind == "tenant":
        return [{"tenant": t} for t in TENANTS]
    if kind == "member":
        return [
            {"tenant": t, "member": m} for t in TENANTS for m in ("alice", "bob", "dave", "ghost")
        ]
    if kind == "project":
        return [{"project": p} for p in PROJECTS]
    if kind == "invoice":
        return [{"invoice": i} for i in INVOICES]
    return [
        {"project": p, "invoice": i} for p in PROJECTS for i in INVOICES
    ]  # parent/child confusion


PROJECTS_OF: Final = {"A": ("PA1", "PA2"), "B": ("PB1",), "C": ("PC1",), "ghost": ()}
INVOICES_OF: Final = {"A": ("IA1", "IA2"), "B": ("IB1",), "C": (), "ghost": ()}
MEMBERS: Final = ("alice", "bob", "dave", "ghost")


def targets_around(route: str, tenant: str) -> list[dict[str, str]]:
    """Every target of a route that is about ONE tenant (or about nothing, for "ghost").

    Hypothesis picks a (caller, tenant) pair first and a route second, so that each pair of the 13
    callers and 4 tenants is drawn about equally often. Picking caller, route and target independently
    let a rare pair (a member of the SUSPENDED tenant meeting that tenant) go unseen for a whole run;
    the M5 mutation check found exactly that gap."""
    kind = next(r[3] for r in ROUTES if r[0] == route)
    projects = [*PROJECTS_OF[tenant], "ghost"]
    invoices = [*INVOICES_OF[tenant], "ghost"]
    if kind == "tenant":
        return [{"tenant": tenant}]
    if kind == "member":
        return [{"tenant": tenant, "member": m} for m in MEMBERS]
    if kind == "project":
        return [{"project": p} for p in projects]
    if kind == "invoice":
        return [{"invoice": i} for i in invoices]
    return [{"project": p, "invoice": i} for p in projects for i in invoices]


def headers_for(lab: Lab, credential: str) -> dict[str, str]:
    """The request headers for one kind of caller: no token, a forged token, or a real principal."""
    mint, subject = lab.mint, lab.fx.principal("alice").id
    forged = {
        "garbage": lambda: "not-a-token",
        "attacker": lambda: mint.signed_by_attacker(subject),
        "alg_none": lambda: mint.alg_none(subject),
        "hs256_confusion": lambda: mint.hs256_key_confusion(subject),
        "truncated": lambda: mint.truncated_signature(subject),
    }
    if credential == "none":
        return {}
    if credential in forged:
        return {"Authorization": f"Bearer {forged[credential]()}"}
    return lab.bearer(credential)


# ------------------------------------------------------------------------------ judging ----
def _active_role(lab: Lab, credential: str, tenant: str | None) -> str | None:
    if credential in BAD_TOKENS or tenant is None:
        return None
    if lab.fx.principal(credential).status != "active":
        return None
    for m in lab.fx.memberships:
        if m.principal == credential and m.tenant == tenant and m.status == "active":
            return m.role
    return None


def _coherent(lab: Lab, probe: Probe) -> bool:
    """The nested route's invoice really is the project's child (both exist)."""
    if probe.project is None or probe.invoice is None:
        return False
    return lab.fx.invoice(probe.invoice).project == probe.project


def assert_problem_shape(response: httpx.Response) -> None:
    """An error is an RFC 9457 problem that satisfies the M0 schema (the code is not judged here)."""
    assert response.headers["content-type"].split(";")[0].strip() == PROBLEM_MEDIA_TYPE
    body = response.json()
    ProblemDetail.model_validate(body)
    assert body["status"] == response.status_code


def check(
    lab: Lab, credential: str, probe: Probe, response: httpx.Response, *, before: Any, after: Any
) -> None:
    """Raise AssertionError, with the request in the message, if the response breaks a rule."""
    where = (
        f"{credential} {probe.method} {probe.path} -> {response.status_code}: {response.text[:200]}"
    )
    status = response.status_code
    assert status < 500, f"a server error: {where}"
    if status >= 400:
        assert_problem_shape(response)
    # --- no leakage -------------------------------------------------------------------------
    for tenant in "ABC":
        if _active_role(lab, credential, tenant) is None:
            assert f"SENTINEL-TENANT-{tenant}" not in response.text, (
                f"a foreign tenant's data leaked: {where}"
            )
    assert lab.fx.project(HIDDEN_PROJECT).title not in response.text, (
        f"a hidden-market project leaked: {where}"
    )
    role = _active_role(lab, credential, probe.tenant)
    private_allowed = (
        probe.route == "contacts"
        and status == 200
        and role in {"admin", "owner"}
        and probe.project is not None
    )
    if not private_allowed:
        assert lab.fx.private_sentinel not in response.text, f"private data leaked: {where}"
    # --- authentication and the oracle's answer for a caller with no right to know -------------
    if credential in BAD_TOKENS:
        assert status == 401, f"an invalid credential was not a plain 401: {where}"
    elif lab.fx.principal(credential).status != "active":
        assert status == 403, f"a disabled principal must be refused (403): {where}"
    elif role is None:
        assert status == 404, f"a caller with no membership must see 404, never more: {where}"
    elif probe.route == "nested" and not _coherent(lab, probe):
        # TL-07: an invoice reached through a project that is not its parent does not exist there
        assert status == 404, f"a project paired with another project's invoice: {where}"
    elif probe.tenant is not None and lab.fx.tenant(probe.tenant).state != "active":
        assert status == 403, f"a suspended tenant must refuse its members: {where}"
    elif probe.project == HIDDEN_PROJECT or probe.invoice == HIDDEN_INVOICE:
        assert status == 404, f"a hidden-market object must look like a missing one: {where}"
    # --- state --------------------------------------------------------------------------------
    changes = diff_business(before, after)
    if status >= 400 or probe.route not in WRITES:
        assert changes == [], (
            f"state changed on a request that should not change it: {where}: {changes}"
        )
    else:
        expected = {
            "create": ("projects", "added"),
            "patch": ("projects", "modified"),
            "put": ("memberships", "modified"),
        }
        assert [(c.table, c.kind) for c in changes] == [expected[probe.route]], (
            f"unexpected state change: {where}: {changes}"
        )


async def send_and_check(lab: Lab, credential: str, probe: Probe) -> httpx.Response:
    """Send one probe, take a raw-SQL snapshot before and after, and judge the outcome."""
    before = lab.snapshot()
    response = await lab.request(
        probe.method, probe.path, headers=headers_for(lab, credential), json_body=probe.body
    )
    check(lab, credential, probe, response, before=before, after=lab.snapshot())
    return response


# ------------------------------------------------------------------------ a cheap fresh lab ----
async def lab_from_template(
    template: Path, destination: Path, trusted: KeyPair, attacker: KeyPair
) -> Lab:
    """A lab on a COPY of a migrated, seeded database: an example costs milliseconds, not a migration."""
    from tenantlab.api.app import create_app  # noqa: PLC0415
    from tenantlab.config import Settings  # noqa: PLC0415
    from tenantlab.lab.fixtures.loader import load_fixtures  # noqa: PLC0415

    shutil.copyfile(template, destination)
    url = f"sqlite+pysqlite:///{destination}"
    app = create_app(
        Settings(
            database_url=url,  # type: ignore[arg-type]
            jwt_issuer=ISSUER,
            jwt_audience=AUDIENCE,
            jwt_public_key_pem=trusted.public_pem,
        )
    )
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)
    lab = Lab(client, create_engine(url), TokenMint(trusted, attacker), load_fixtures())
    lab.on_close.append(lambda: lifespan.__aexit__(None, None, None))
    return lab


def build_template(path: Path) -> None:
    from tenantlab.db.migrate import upgrade_to_head  # noqa: PLC0415
    from tenantlab.db.seed import seed_fixtures  # noqa: PLC0415

    url = f"sqlite+pysqlite:///{path}"
    upgrade_to_head(url)
    seed_fixtures(url)
