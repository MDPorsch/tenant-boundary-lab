"""Deny by default is STRUCTURAL: the app mounts exactly the routes in the registry, each wrapped in
the gate pipeline, and the registry equals the contract the owner approved.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
from fastapi.routing import APIRoute

from tenantlab.api.app import create_app
from tenantlab.api.routes import ROUTES, RouteSpec, Scope
from tenantlab.config import Settings
from tenantlab.lab.fixtures.loader import load_fixtures
from tenantlab.oracle.matrix import load_capabilities
from tenantlab.schemas.errors import PROBLEM_MEDIA_TYPE
from tests.harness import AUDIENCE, BASE_URL, ISSUER, KeyPair, assert_problem

DOCS = Path(__file__).resolve().parents[2] / "docs"
FX = load_fixtures()
ALL_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")
PLACEHOLDERS = {
    "tenant_id": FX.tenant("A").id,
    "project_id": FX.project("PA1").id,
    "invoice_id": FX.invoice("IA1").id,
    "principal_id": FX.principal("alice").id,
}


def _fill(path: str) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: PLACEHOLDERS[m.group(1)], path)


def _contract_rows() -> dict[tuple[str, str], tuple[str, str]]:
    """(method, path) -> (operation, handler milestone) from the table in api-contract.md s2."""
    rows: dict[tuple[str, str], tuple[str, str]] = {}
    for line in (DOCS / "api-contract.md").read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\| `(GET|POST|PUT|PATCH|DELETE) (/v1/[^`]+)` \| `([a-z.]+)` \|", line)
        if match:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            rows[(match.group(1), match.group(2))] = (match.group(3), cells[-1])
    return rows


@pytest.fixture
def app(tmp_path: Path, trusted_keys: KeyPair):  # type: ignore[no-untyped-def]
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'unmigrated.sqlite'}",  # type: ignore[arg-type]
        jwt_issuer=ISSUER,
        jwt_audience=AUDIENCE,
        jwt_public_key_pem=trusted_keys.public_pem,
    )
    return create_app(settings)


def test_the_registry_equals_the_route_table_in_the_api_contract() -> None:
    contract = _contract_rows()
    registry = {(r.method, r.path): r for r in ROUTES}
    assert set(registry) == set(contract)
    for key, (operation, milestone) in contract.items():
        assert registry[key].operation == operation, key
        assert registry[key].implemented == (milestone == "M1"), key


def test_every_oracle_operation_has_a_route_and_every_route_has_an_oracle_operation() -> None:
    oracle_operations = {rule.operation for rule in load_capabilities().rules}
    assert {r.operation for r in ROUTES} == oracle_operations


def test_registry_entries_are_internally_consistent() -> None:
    seen: set[tuple[str, str]] = set()
    for spec in ROUTES:
        assert (spec.method, spec.path) not in seen, "duplicate route"
        seen.add((spec.method, spec.path))
        in_path = tuple(re.findall(r"\{(\w+)\}", spec.path))
        assert spec.path_params == in_path, spec
        assert spec.target_param in spec.path_params, spec
        assert spec.path.startswith("/v1/")
        expected_params = {
            Scope.TENANT: {"tenant_id"},
            Scope.PROJECT: {"project_id"},
            Scope.INVOICE: {"invoice_id"},
            Scope.PROJECT_INVOICE: {"project_id", "invoice_id"},
        }[spec.scope]
        assert expected_params <= set(spec.path_params), spec
        assert spec.method in {"GET", "POST", "PUT", "PATCH", "DELETE"}


def test_only_the_context_probe_is_implemented_in_m1() -> None:
    assert [r.operation for r in ROUTES if r.implemented] == ["tenant.context.read"]


def _mounted(app: object) -> set[tuple[str, str]]:
    return {
        (method, route.path)
        for route in app.routes  # type: ignore[attr-defined]
        if isinstance(route, APIRoute)
        for method in route.methods
    }


def test_the_app_mounts_exactly_the_registered_routes_and_nothing_else(app: object) -> None:
    assert _mounted(app) == {(r.method, r.path) for r in ROUTES}
    assert all(
        isinstance(route, APIRoute)
        for route in app.routes  # type: ignore[attr-defined]
    ), "a non-API route (docs, openapi, static mount) was added"
    assert app.openapi_url is None  # type: ignore[attr-defined]
    assert app.docs_url is None  # type: ignore[attr-defined]
    assert app.redoc_url is None  # type: ignore[attr-defined]


def test_no_endpoint_lets_the_framework_parse_input_before_the_gates(app: object) -> None:
    """D-18 regression guard: the endpoint wrapper takes only the raw Request. Any declared body,
    query, path, header or cookie parameter would make FastAPI parse and validate it BEFORE the
    gates (anonymous + malformed JSON would become 422, not 401)."""
    for route in app.routes:  # type: ignore[attr-defined]
        assert isinstance(route, APIRoute)
        dependant = route.dependant
        assert route.body_field is None, route.path
        assert not dependant.body_params, route.path
        assert not dependant.query_params, route.path
        assert not dependant.path_params, route.path
        assert not dependant.header_params, route.path
        assert not dependant.cookie_params, route.path
        assert not dependant.dependencies, route.path


async def test_an_anonymous_request_to_every_registered_route_is_401_with_no_database(
    app: object, tmp_path: Path
) -> None:
    """Deny by default, and authentication needs no database: the DB file does not even exist."""
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url=BASE_URL) as client:
        for spec in ROUTES:
            response = await client.request(spec.method, _fill(spec.path))
            assert_problem(response, status=401, code="auth.token_invalid")
            assert response.headers["www-authenticate"] == "Bearer", spec
    assert not (tmp_path / "unmigrated.sqlite").exists() or not any(
        (tmp_path / "unmigrated.sqlite").read_bytes()
    ), "an anonymous request touched the database"


async def test_every_unregistered_method_on_a_registered_path_is_a_404_not_a_405(
    app: object,
) -> None:
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url=BASE_URL) as client:
        by_path: dict[str, set[str]] = {}
        for spec in ROUTES:
            by_path.setdefault(spec.path, set()).add(spec.method)
        probes = 0
        for path, methods in by_path.items():
            for method in ALL_METHODS:
                if method in methods or (method == "HEAD" and "GET" in methods):
                    continue
                response = await client.request(method, _fill(path))
                if method == "HEAD":  # a HEAD response has no body by definition
                    assert response.status_code == 404
                    assert response.headers["content-type"].startswith(PROBLEM_MEDIA_TYPE)
                else:
                    assert_problem(response, status=404, code="resource.not_found")
                assert "allow" not in response.headers
                probes += 1
        assert probes > 20


def test_registry_is_immutable_data() -> None:
    assert isinstance(ROUTES, tuple)
    spec: RouteSpec = ROUTES[0]
    with pytest.raises(AttributeError):
        spec.operation = "x"  # type: ignore[misc]
