"""M1 supplementary tests: gate-pipeline behaviour that the TL-01..05/14/18 files do not pin.

These were added after mutation-testing the REAL M1 implementation showed which injected bugs the
original red tests could not see (market gate, path-id validation, invoice coherence, the body cap,
fail-closed on a database error, duplicate credentials ...). They are green from the start and are
not part of any catalogue case; M2 adds TL-06..12/15 on top of the same pipeline.

Positive controls use only GET routes and the set {200, 501} ("passed every gate"), so they stay
valid when M2 replaces the 501 placeholders with real handlers.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import create_engine, inspect

from tenantlab.api.app import create_app
from tenantlab.config import Settings
from tests.harness import (
    AUDIENCE,
    BASE_URL,
    ISSUER,
    KeyPair,
    Lab,
    assert_no_leak,
    assert_problem,
    assert_single_deny_audit,
    body_sans_request_id,
    norm_uuid,
)

OpenLab = Callable[..., Any]
PATCH_BODY = {"title": "renamed", "row_version": 1}
PASSED_THE_GATES = {200, 501}
UUID4 = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"


def _ids(lab: Lab) -> dict[str, str]:
    return {
        "A": lab.fx.tenant("A").id,
        "B": lab.fx.tenant("B").id,
        "PA1": lab.fx.project("PA1").id,
        "PA2": lab.fx.project("PA2").id,
        "PB1": lab.fx.project("PB1").id,
        "IA1": lab.fx.invoice("IA1").id,
        "IA2": lab.fx.invoice("IA2").id,
        "GHOST_P": lab.fx.never_seeded["project"],
        "GHOST_I": lab.fx.never_seeded["invoice"],
    }


def _me(lab: Lab) -> str:
    return f"/v1/tenants/{lab.fx.tenant('A').id}/me"


# ============================================================ gate 0: transport limits ====
@pytest.mark.parametrize("who", ["anonymous", "alice", "bob", "garbage_token"])
async def test_gate0_an_oversized_declared_body_is_413_whoever_sends_it(
    open_lab: OpenLab, who: str
) -> None:
    lab: Lab = await open_lab()
    pa1 = lab.fx.project("PA1").id
    headers = {
        "anonymous": {},
        "alice": lab.bearer("alice"),
        "bob": lab.bearer("bob"),
        "garbage_token": {"Authorization": "Bearer not-a-jwt"},
    }[who]
    before = lab.snapshot()
    response = await lab.request(
        "PATCH",
        f"/v1/projects/{pa1}",
        content=b"x" * 65_537,
        headers={**headers, "Content-Type": "application/json"},
    )
    assert_problem(response, status=413, code="request.too_large")
    assert lab.snapshot() == before, "gate 0 must not write anything, audit included"


async def test_gate0_the_cap_is_exactly_65536_bytes(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    pa1 = lab.fx.project("PA1").id
    at_cap = await lab.request("PATCH", f"/v1/projects/{pa1}", content=b"x" * 65_536)
    assert_problem(at_cap, status=401, code="auth.token_invalid")  # allowed through to gate 1
    over = await lab.request("PATCH", f"/v1/projects/{pa1}", content=b"x" * 65_537)
    assert_problem(over, status=413, code="request.too_large")


@pytest.mark.parametrize(
    "value",
    ["abc", "-1", "1.5", "0x10", "", "1 2", "١٢٣".encode()],  # the last: non-ASCII digits, as bytes
)
async def test_gate0_a_malformed_content_length_is_422_and_writes_nothing(
    open_lab: OpenLab, value: str | bytes
) -> None:
    lab: Lab = await open_lab()
    before = lab.snapshot()
    response = await lab.request("GET", _me(lab), headers={"Content-Length": value})
    assert_problem(response, status=422, code="request.invalid")
    assert lab.snapshot() == before


# ================================================================ gate 1: the credential ====
async def test_gate1_two_authorization_headers_are_refused_even_if_both_are_valid(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    pair = [
        ("Authorization", f"Bearer {lab.token('alice')}"),
        ("Authorization", f"Bearer {lab.token('alice')}"),
    ]
    response = await lab.client.request("GET", _me(lab), headers=pair)
    assert_problem(response, status=401, code="auth.token_invalid")


async def test_gate1_extra_whitespace_in_the_header_is_refused(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    response = await lab.request(
        "GET", _me(lab), headers={"Authorization": f"Bearer  {lab.token('alice')}"}
    )
    assert_problem(response, status=401, code="auth.token_invalid")


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER"])
async def test_gate1_the_scheme_name_is_case_insensitive(open_lab: OpenLab, scheme: str) -> None:
    """RFC 9110 s11.1: the auth-scheme is case-insensitive."""
    lab: Lab = await open_lab()
    response = await lab.request(
        "GET", _me(lab), headers={"Authorization": f"{scheme} {lab.token('alice')}"}
    )
    assert response.status_code == 200, response.text


async def test_gate1_every_failure_reason_looks_identical_on_the_wire(open_lab: OpenLab) -> None:
    """No oracle: the client cannot tell WHY a credential was refused (account existence, expiry,
    audience ...). Bodies and headers are equal apart from the per-request id."""
    lab: Lab = await open_lab()
    alice = lab.fx.principal("alice").id
    variants: dict[str, dict[str, str]] = {
        "missing": {},
        "garbage": {"Authorization": "Bearer not-a-jwt"},
        "wrong_key": {"Authorization": f"Bearer {lab.mint.signed_by_attacker(alice)}"},
        "expired": lab.bearer("alice", iat_offset=-600, nbf_offset=-600, exp_offset=-60),
        "wrong_audience": lab.bearer("alice", aud="other-api"),
        "wrong_issuer": lab.bearer("alice", iss="https://evil.invalid"),
        "too_long_lived": lab.bearer("alice", exp_offset=901),
        "unknown_principal": {
            "Authorization": f"Bearer {lab.mint.mint(lab.fx.never_seeded['principal'])}"
        },
        "alg_none": {"Authorization": f"Bearer {lab.mint.alg_none(alice)}"},
    }
    seen: list[tuple[dict[str, Any], dict[str, str]]] = []
    for name, headers in variants.items():
        response = await lab.request("GET", _me(lab), headers=headers)
        problem = assert_problem(response, status=401, code="auth.token_invalid")
        wire_headers = {k: v for k, v in response.headers.items() if k != "x-request-id"}
        seen.append((body_sans_request_id(problem), wire_headers))
        assert "detail" in problem
        assert name not in response.text
    assert all(item == seen[0] for item in seen), "the 401 response leaks the failure reason"


# ======================================================= gate 5: market scope (D-05) ====
HIDDEN_ROUTES = [
    ("GET", "/v1/projects/{PA2}", None, "project.read", "project"),
    ("PATCH", "/v1/projects/{PA2}", PATCH_BODY, "project.write", "project"),
    ("GET", "/v1/projects/{PA2}/contacts", None, "contact.private.read", "contact"),
    ("GET", "/v1/invoices/{IA2}", None, "invoice.read", "invoice"),
    ("GET", "/v1/projects/{PA2}/invoices/{IA2}", None, "invoice.read", "invoice"),
]


@pytest.mark.parametrize("who", ["alice", "dave", "bob"])
@pytest.mark.parametrize(
    ("method", "template", "body", "action", "resource_type"),
    HIDDEN_ROUTES,
    ids=[f"{m} {t}" for m, t, *_ in HIDDEN_ROUTES],
)
async def test_gate5_an_object_in_a_market_the_tenant_may_not_use_is_a_404_for_every_role(
    open_lab: OpenLab,
    *,
    who: str,
    method: str,
    template: str,
    body: Any,
    action: str,
    resource_type: str,
) -> None:
    """PA2 (tenant A, market US) exists, but A has no US access. Market scope is checked BEFORE
    role, so even an owner gets the plain 404, and a viewer gets 404 rather than the 403 that
    would confirm the object exists. It must equal the answer for an id that never existed."""
    lab: Lab = await open_lab()
    ids = _ids(lab)
    actor = lab.fx.principal(who).id
    before = lab.snapshot()
    hidden = await lab.request(
        method, template.format(**ids), headers=lab.bearer(who), json_body=body
    )
    problem = assert_problem(hidden, status=404, code="resource.not_found")
    assert_no_leak(hidden.text, lab.fx, forbidden_tenants="ABC")
    mid = assert_single_deny_audit(
        lab, before, hidden, actor=actor, tenant=None, action=action,
        resource_type=resource_type, reason_code="resource.not_found",
    )  # fmt: skip

    ghost_ids = {**ids, "PA2": ids["GHOST_P"], "IA2": ids["GHOST_I"]}
    ghost = await lab.request(
        method, template.format(**ghost_ids), headers=lab.bearer(who), json_body=body
    )
    ghost_problem = assert_problem(ghost, status=404, code="resource.not_found")
    assert body_sans_request_id(problem) == body_sans_request_id(ghost_problem)
    shape = ("action", "resource_type", "decision", "reason_code", "tenant_id")
    assert {k: mid.audit[-1][k] for k in shape} == {k: lab.snapshot().audit[-1][k] for k in shape}


async def test_gate5_market_access_is_re_read_on_every_request(open_lab: OpenLab) -> None:
    """Granting US to tenant A exposes PA2 at once; revoking UK hides PA1 at once (no cache)."""
    lab: Lab = await open_lab()
    ids = _ids(lab)
    headers = lab.bearer("alice")
    pa1 = f"/v1/projects/{ids['PA1']}"
    pa2 = f"/v1/projects/{ids['PA2']}"
    assert (await lab.request("GET", pa1, headers=headers)).status_code in PASSED_THE_GATES
    assert (await lab.request("GET", pa2, headers=headers)).status_code == 404

    lab.sql(
        "INSERT INTO tenant_market_access (tenant_id, market_id) "
        "SELECT t.id, m.id FROM tenants t, markets m WHERE t.slug = 'tenant-a' AND m.code = 'US'"
    )
    assert (await lab.request("GET", pa2, headers=headers)).status_code in PASSED_THE_GATES

    lab.sql(
        "DELETE FROM tenant_market_access WHERE "
        "tenant_id = (SELECT id FROM tenants WHERE slug = 'tenant-a') AND "
        "market_id = (SELECT id FROM markets WHERE code = 'UK')"
    )
    assert (await lab.request("GET", pa1, headers=headers)).status_code == 404


# ============================================ invoice resolution (groundwork for TL-07) ====
async def test_an_invoice_whose_tenant_differs_from_its_projects_tenant_is_not_visible(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    ids = _ids(lab)
    routes = [f"/v1/invoices/{ids['IA1']}", f"/v1/projects/{ids['PA1']}/invoices/{ids['IA1']}"]
    for route in routes:  # control: coherent baseline passes the gates
        assert (await lab.request("GET", route, headers=lab.bearer("alice"))).status_code in (
            PASSED_THE_GATES
        )
    lab.sql(
        "UPDATE invoices SET tenant_id = (SELECT id FROM tenants WHERE slug = 'tenant-b') "
        "WHERE amount_minor = 125000"
    )  # IA1 now claims tenant B while its project is in tenant A
    for who in ("alice", "carla"):
        for route in routes:
            before = lab.snapshot()
            response = await lab.request("GET", route, headers=lab.bearer(who))
            assert_problem(response, status=404, code="resource.not_found")
            assert_single_deny_audit(
                lab, before, response, actor=lab.fx.principal(who).id, tenant=None,
                action="invoice.read", resource_type="invoice", reason_code="resource.not_found",
            )  # fmt: skip


async def test_the_nested_invoice_route_requires_the_invoice_to_belong_to_that_project(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    ids = _ids(lab)
    project_id, invoice_id = uuid.uuid4(), uuid.uuid4()
    lab.sql(
        "INSERT INTO projects (id, tenant_id, market_id, owner_principal_id, title, status, "
        "row_version) SELECT :id, t.id, m.id, p.id, 'SENTINEL-TENANT-A second', 'active', 1 "
        "FROM tenants t, markets m, principals p WHERE t.slug = 'tenant-a' AND m.code = 'UK' "
        "AND p.email = :email",
        id=project_id.hex,
        email=lab.fx.principal("alice").email,
    )
    lab.sql(
        "INSERT INTO invoices (id, tenant_id, project_id, amount_minor, currency, status) "
        "SELECT :id, t.id, :pid, 777, 'GBP', 'issued' FROM tenants t WHERE t.slug = 'tenant-a'",
        id=invoice_id.hex,
        pid=project_id.hex,
    )
    alice = lab.bearer("alice")
    own = f"/v1/projects/{project_id}/invoices/{invoice_id}"
    assert (await lab.request("GET", own, headers=alice)).status_code in PASSED_THE_GATES
    # right tenant, both visible, but the invoice is the OTHER project's: 404 either way round
    for wrong in (
        f"/v1/projects/{ids['PA1']}/invoices/{invoice_id}",
        f"/v1/projects/{project_id}/invoices/{ids['IA1']}",
    ):
        response = await lab.request("GET", wrong, headers=alice)
        assert_problem(response, status=404, code="resource.not_found")


# ====================================================== D-11: path ids are strict UUIDs ====
BAD_IDS = {
    "word": "not-a-uuid",
    "upper_case": "2000000a-0000-4000-8000-00000000000b".upper(),
    "no_hyphens": "20000000000040008000000000000001",
    "urn": "urn:uuid:20000000-0000-4000-8000-000000000001",
    "version_1": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "nil": "00000000-0000-0000-0000-000000000000",
    "very_long": "a" * 5000,
    "sql": "' OR 1=1 --",
    "markup": "<img src=x onerror=alert(1)>",  # no "/": a slash would be another path segment
    "unicode": "é" * 10,
}
ID_ROUTES = [
    ("GET", "/v1/tenants/{x}/me", None, "tenant.context.read", "tenant"),
    ("GET", "/v1/projects/{x}", None, "project.read", "project"),
    ("GET", "/v1/invoices/{x}", None, "invoice.read", "invoice"),
]


@pytest.mark.parametrize("bad", sorted(BAD_IDS))
@pytest.mark.parametrize(
    ("method", "template", "body", "action", "resource_type"),
    ID_ROUTES,
    ids=[t for _, t, *_ in ID_ROUTES],
)
async def test_d11_a_malformed_path_id_is_422_without_echo_and_with_a_null_tenant_audit(
    open_lab: OpenLab,
    *,
    bad: str,
    method: str,
    template: str,
    body: Any,
    action: str,
    resource_type: str,
) -> None:
    lab: Lab = await open_lab()
    before = lab.snapshot()
    response = await lab.request(
        method, template.format(x=BAD_IDS[bad]), headers=lab.bearer("alice"), json_body=body
    )
    assert_problem(response, status=422, code="request.invalid")
    assert BAD_IDS[bad] not in response.text, "the rejected identifier was echoed"
    after = assert_single_deny_audit(
        lab, before, response, actor=lab.fx.principal("alice").id, tenant=None,
        action=action, resource_type=resource_type, reason_code="request.invalid",
    )  # fmt: skip
    assert after.audit[-1]["resource_id"] is None, "an unparsed identifier must not be stored"


async def test_d11_the_member_route_validates_both_identifiers(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    tenant_a = lab.fx.tenant("A").id
    for path in (
        f"/v1/tenants/{tenant_a}/members/not-a-uuid",
        f"/v1/tenants/not-a-uuid/members/{lab.fx.principal('bob').id}",
    ):
        response = await lab.request(
            "PUT", path, headers=lab.bearer("alice"), json_body={"role": "viewer"}
        )
        assert_problem(response, status=422, code="request.invalid")


async def test_d11_authentication_and_principal_status_come_before_id_validation(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    anonymous = await lab.request("GET", "/v1/tenants/not-a-uuid/me")
    assert_problem(anonymous, status=401, code="auth.token_invalid")
    before = lab.snapshot()
    disabled = await lab.request("GET", "/v1/tenants/not-a-uuid/me", headers=lab.bearer("erin"))
    assert_problem(disabled, status=403, code="auth.principal_disabled")
    assert_single_deny_audit(
        lab, before, disabled, actor=lab.fx.principal("erin").id, tenant=None,
        action="tenant.context.read", resource_type="tenant",
        reason_code="auth.principal_disabled",
    )  # fmt: skip


# ======================================================== gate 8: the query string ====
async def test_gate8_repeated_and_unknown_query_parameters_are_422_with_a_tenant_audit(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    tenant_a = lab.fx.tenant("A").id
    path = f"/v1/tenants/{tenant_a}/projects"
    alice = lab.fx.principal("alice").id
    cases: list[Any] = [
        [("limit", "1"), ("limit", "2")],  # a repeated parameter is ambiguous
        [("page", "2")],  # offset-style paging is not part of the contract (D-14)
        [("offset", "0")],
        [("tenant_id", lab.fx.tenant("B").id)],
    ]
    for params in cases:
        before = lab.snapshot()
        response = await lab.client.request("GET", path, headers=lab.bearer("alice"), params=params)
        assert_problem(response, status=422, code="request.invalid")
        assert_single_deny_audit(
            lab, before, response, actor=alice, tenant=tenant_a, action="project.list",
            resource_type="tenant", reason_code="request.invalid",
        )  # fmt: skip


async def test_gate8_an_allowed_query_parameter_passes_the_gates(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    response = await lab.request(
        "GET",
        f"/v1/tenants/{lab.fx.tenant('A').id}/projects",
        headers=lab.bearer("alice"),
        params={"limit": "5"},
    )
    assert response.status_code in PASSED_THE_GATES


async def test_gate8_a_blank_valued_unknown_parameter_is_still_unknown(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    response = await lab.client.request("GET", _me(lab) + "?x", headers=lab.bearer("alice"))
    assert_problem(response, status=422, code="request.invalid")


# ============================================ positive controls: every GET route passes ====
async def test_an_authorized_actor_passes_the_gates_of_every_get_route(open_lab: OpenLab) -> None:
    """Anti-vacuity for all the denials above: a deny-everything pipeline would satisfy them.

    Ordinary reads write nothing (D-10). The one exception is the private-contact read, which is
    audited (D-10, D-37; since M2 the route has a real handler): exactly one `allow` row."""
    lab: Lab = await open_lab()
    ids = _ids(lab)
    ordinary = (
        f"/v1/tenants/{ids['A']}/me",
        f"/v1/tenants/{ids['A']}/projects",
        f"/v1/tenants/{ids['A']}/audit",
        f"/v1/projects/{ids['PA1']}",
        f"/v1/invoices/{ids['IA1']}",
        f"/v1/projects/{ids['PA1']}/invoices/{ids['IA1']}",
    )
    before = lab.snapshot()
    for path in ordinary:
        response = await lab.request("GET", path, headers=lab.bearer("alice"))
        assert response.status_code in PASSED_THE_GATES, (path, response.status_code, response.text)
    assert lab.snapshot() == before, "ordinary reads must not write (D-10)"

    contacts = await lab.request(
        "GET", f"/v1/projects/{ids['PA1']}/contacts", headers=lab.bearer("alice")
    )
    assert contacts.status_code in PASSED_THE_GATES, contacts.text
    after = lab.snapshot()
    assert after.business == before.business
    assert [(r["action"], r["decision"]) for r in after.new_audit_rows(before)] == [
        ("contact.private.read", "allow")
    ]


# ====================================================================== unknown routes ====
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/"),
        ("GET", "/docs"),
        ("GET", "/redoc"),
        ("GET", "/openapi.json"),
        ("GET", "/v1"),
        ("GET", "/v1/tenants"),
        ("GET", "/v1/tenants/{A}"),
        ("GET", "/v1/tenants/{A}/me/"),  # no redirect to the canonical form
        ("GET", "//v1/tenants/{A}/me"),
        ("DELETE", "/v1/projects/{PA1}"),
        ("POST", "/v1/tenants/{A}/me"),
        ("GET", "/v2/tenants/{A}/me"),
        ("GET", "/admin"),
    ],
)
async def test_unknown_paths_and_methods_are_one_generic_404(
    open_lab: OpenLab, method: str, path: str
) -> None:
    lab: Lab = await open_lab()
    ids = _ids(lab)
    bodies = []
    for headers in ({}, lab.bearer("alice")):
        response = await lab.request(method, path.format(**ids), headers=headers)
        problem = assert_problem(response, status=404, code="resource.not_found")
        assert "location" not in response.headers, "an unknown route must not redirect"
        assert "allow" not in response.headers
        bodies.append(body_sans_request_id(problem))
    assert bodies[0] == bodies[1]


# =================================================================== fail closed (503) ====
FAIL_CLOSED_CASES = [
    ("principals", "alice", "GET", "/v1/tenants/{A}/me", None),
    ("memberships", "alice", "GET", "/v1/tenants/{A}/me", None),
    ("tenants", "alice", "GET", "/v1/tenants/{A}/me", None),
    ("projects", "alice", "PATCH", "/v1/projects/{PA1}", PATCH_BODY),
    ("tenant_market_access", "alice", "GET", "/v1/projects/{PA1}", None),
    # the denial cannot be recorded, so the answer is 503 and not a silently unaudited 403
    ("audit_events", "bob", "PATCH", "/v1/projects/{PA1}", PATCH_BODY),
]


@pytest.mark.parametrize(
    ("table", "who", "method", "template", "body"),
    FAIL_CLOSED_CASES,
    ids=[c[0] for c in FAIL_CLOSED_CASES],
)
async def test_a_database_failure_fails_closed_with_503_and_leaks_nothing(
    open_lab: OpenLab, *, table: str, who: str, method: str, template: str, body: Any
) -> None:
    lab: Lab = await open_lab()
    path = template.format(**_ids(lab))
    lab.sql(f"DROP TABLE {table}")  # table comes from the constant list above
    response = await lab.request(method, path, headers=lab.bearer(who), json_body=body)
    assert_problem(response, status=503, code="service.unavailable")
    lowered = response.text.lower()
    for needle in (table, "sqlite", "select", "operationalerror", "traceback", "sqlalchemy"):
        assert needle not in lowered, f"{needle!r} leaked in a 503 body"


async def test_a_database_failure_is_logged_without_statement_or_parameters(
    open_lab: OpenLab, caplog: pytest.LogCaptureFixture
) -> None:
    lab: Lab = await open_lab()
    lab.sql("DROP TABLE memberships")
    with caplog.at_level(logging.INFO, logger="tenantlab"):
        response = await lab.request("GET", _me(lab), headers=lab.bearer("alice"))
    records = [r for r in caplog.records if getattr(r, "event", None) == "db.unavailable"]
    assert len(records) == 1
    assert records[0].__dict__["error"] == "OperationalError"
    assert records[0].__dict__["request_id"] == response.headers["x-request-id"]
    flat = " ".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records)
    assert "memberships" not in flat
    assert "SELECT" not in flat
    assert lab.fx.principal("alice").email not in flat


async def test_migrations_never_run_as_a_side_effect_of_starting_the_app(
    tmp_path: Path, trusted_keys: KeyPair
) -> None:
    db_file = tmp_path / "never-migrated.sqlite"
    url = f"sqlite+pysqlite:///{db_file}"
    app = create_app(
        Settings(
            database_url=url,  # type: ignore[arg-type]
            jwt_issuer=ISSUER,
            jwt_audience=AUDIENCE,
            jwt_public_key_pem=trusted_keys.public_pem,
        )
    )
    from tests.harness import TokenMint, generate_keypair  # noqa: PLC0415

    mint = TokenMint(trusted_keys, generate_keypair())
    token = mint.mint("10000000-0000-4000-8000-000000000001")
    async with app.router.lifespan_context(app):  # start-up, then shut-down on exit
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(
                "/v1/tenants/20000000-0000-4000-8000-000000000001/me",
                headers={"Authorization": f"Bearer {token}"},
            )
    assert_problem(response, status=503, code="service.unavailable")
    engine = create_engine(url)
    assert inspect(engine).get_table_names() == []
    engine.dispose()


# ============================================================================== logging ====
def _flat(caplog: pytest.LogCaptureFixture) -> str:
    return " ".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records)


async def test_a_pre_authentication_failure_is_a_log_line_without_the_token(
    open_lab: OpenLab, caplog: pytest.LogCaptureFixture
) -> None:
    lab: Lab = await open_lab()
    token = lab.mint.signed_by_attacker(lab.fx.principal("alice").id)
    with caplog.at_level(logging.INFO, logger="tenantlab"):
        response = await lab.request("GET", _me(lab), headers={"Authorization": f"Bearer {token}"})
    records = [r for r in caplog.records if getattr(r, "event", None) == "auth.rejected"]
    assert len(records) == 1
    record = records[0].__dict__
    assert record["reason"] == "bad_signature"
    assert record["request_id"] == response.headers["x-request-id"]
    assert record["route"] == "GET /v1/tenants/{tenant_id}/me"
    flat = _flat(caplog)
    assert token not in flat
    assert token.split(".")[1] not in flat, "the token payload was logged"
    assert token.split(".")[2] not in flat, "the token signature was logged"


async def test_a_denial_is_logged_with_ids_and_reason_but_no_tenant_data(
    open_lab: OpenLab, caplog: pytest.LogCaptureFixture
) -> None:
    lab: Lab = await open_lab()
    pa1 = lab.fx.project("PA1").id
    with caplog.at_level(logging.INFO, logger="tenantlab"):
        response = await lab.request(
            "PATCH", f"/v1/projects/{pa1}", headers=lab.bearer("bob"), json_body=PATCH_BODY
        )
    records = [r for r in caplog.records if getattr(r, "event", None) == "authz.denied"]
    assert len(records) == 1
    assert records[0].__dict__["reason"] == "authz.forbidden"
    assert records[0].__dict__["request_id"] == response.headers["x-request-id"]
    flat = _flat(caplog)
    for secret in ("SENTINEL", "@tenantlab.invalid", "renamed"):
        assert secret not in flat


# ===================================================================== response headers ====
@pytest.mark.parametrize("outcome", ["200", "401", "404", "422"])
async def test_every_response_has_a_fresh_request_id_and_the_security_headers(
    open_lab: OpenLab, outcome: str
) -> None:
    lab: Lab = await open_lab()
    path, headers = {
        "200": (_me(lab), lab.bearer("alice")),
        "401": (_me(lab), {}),
        "404": (f"/v1/tenants/{lab.fx.tenant('B').id}/me", lab.bearer("alice")),
        "422": ("/v1/tenants/nope/me", lab.bearer("alice")),
    }[outcome]
    first = await lab.request("GET", path, headers=headers)
    second = await lab.request("GET", path, headers=headers)
    assert str(first.status_code) == outcome
    assert first.headers["x-request-id"] != second.headers["x-request-id"]
    for response in (first, second):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
    expected_type = "application/json" if outcome == "200" else "application/problem+json"
    assert first.headers["content-type"].split(";")[0] == expected_type


# ================================================================ audit row properties ====
async def test_a_denial_row_records_the_target_time_and_no_secrets(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    ids = _ids(lab)
    token = lab.token("bob")
    before = lab.snapshot()
    forbidden = await lab.request(
        "PATCH",
        f"/v1/projects/{ids['PA1']}",
        headers={"Authorization": f"Bearer {token}"},
        json_body={**PATCH_BODY, "title": "SENTINEL-BODY-TEXT"},
    )
    hidden = await lab.request(
        "GET", f"/v1/tenants/{ids['B']}/me", headers={"Authorization": f"Bearer {token}"}
    )
    rows = lab.snapshot().new_audit_rows(before)
    assert [(r["action"], r["decision"]) for r in rows] == [
        ("project.write", "deny"),
        ("tenant.context.read", "deny"),
    ]
    assert norm_uuid(rows[0]["resource_id"]) == ids["PA1"]
    assert norm_uuid(rows[1]["resource_id"]) == ids["B"]  # the id the caller asked for
    assert norm_uuid(rows[0]["correlation_id"]) == forbidden.json()["request_id"]
    assert norm_uuid(rows[1]["correlation_id"]) == hidden.json()["request_id"]
    flat = str(rows)
    for secret in (token, "SENTINEL", "@tenantlab.invalid", "renamed"):
        assert secret not in flat
    for row in rows:
        stamp = datetime.fromisoformat(str(row["timestamp"])).replace(tzinfo=UTC)
        assert abs((datetime.now(UTC) - stamp).total_seconds()) < 120


# ================================================================== concurrency (threads) ====
async def test_concurrent_requests_stay_isolated_and_every_denial_is_audited_exactly_once(
    open_lab: OpenLab,
) -> None:
    """The gates run in a thread pool with one session per request: no shared state may bleed
    between concurrent callers (a leaked principal or tenant would show up as a wrong role)."""
    lab: Lab = await open_lab()
    tenant_a, pa1 = lab.fx.tenant("A").id, lab.fx.project("PA1").id
    before = lab.snapshot()
    plan: list[tuple[str, Any]] = []
    for _ in range(12):
        plan.append(("ok", lab.request("GET", _me(lab), headers=lab.bearer("alice"))))
        plan.append(("viewer", lab.request("GET", _me(lab), headers=lab.bearer("bob"))))
        plan.append(
            (
                "forbidden",
                lab.request(
                    "PATCH", f"/v1/projects/{pa1}", headers=lab.bearer("bob"), json_body=PATCH_BODY
                ),
            )
        )
        plan.append(("hidden", lab.request("GET", _me(lab), headers=lab.bearer("frank"))))
    results = await asyncio.gather(*(coroutine for _, coroutine in plan))
    denials: list[str] = []
    for (label, _), response in zip(plan, results, strict=True):
        if label == "ok":
            assert response.status_code == 200
            assert response.json()["role"] == "owner"
        elif label == "viewer":
            assert response.status_code == 200
            assert response.json() == {
                "principal_id": lab.fx.principal("bob").id,
                "tenant_id": tenant_a,
                "role": "viewer",
            }
        else:
            expected = {
                "forbidden": (403, "authz.forbidden"),
                "hidden": (404, "resource.not_found"),
            }
            status, code = expected[label]
            assert_problem(response, status=status, code=code)
            denials.append(response.json()["request_id"])
    after = lab.snapshot()
    assert after.business == before.business
    rows = after.new_audit_rows(before)
    assert len(rows) == len(denials) == 24
    assert {norm_uuid(r["correlation_id"]) for r in rows} == set(denials)
    assert len(set(denials)) == len(denials), "request ids must be unique per request"
