"""Application factory.

`create_app(settings)` mounts exactly the routes in `tenantlab.api.routes.ROUTES`, each wrapped in
the gate pipeline. OpenAPI/Swagger/ReDoc endpoints are disabled: the contract lives in
docs/api-contract.md, and an extra unauthenticated route would be an extra surface (a test pins
the set of routes). Unknown paths and methods answer one generic 404 problem.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import sessionmaker
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import Response

from tenantlab.api.gates import Deps, run_gates
from tenantlab.api.handlers import HANDLERS, Context, Handler, not_implemented
from tenantlab.api.middleware import RequestContextMiddleware
from tenantlab.api.problems import ApiProblem, problem_response
from tenantlab.api.routes import ROUTES, RouteSpec
from tenantlab.auth.tokens import TokenVerifier, load_public_key
from tenantlab.config import Settings
from tenantlab.db.engine import make_engine
from tenantlab.schemas.errors import ErrorCode


def _mount(app: FastAPI, spec: RouteSpec, deps: Deps) -> None:
    handler: Handler = HANDLERS.get(spec.operation, not_implemented)
    if not spec.implemented:
        handler = not_implemented

    async def endpoint(request: Request) -> Response:
        # `request` is the only parameter on purpose: FastAPI parses a JSON body BEFORE running
        # the endpoint if the signature declares one, which would turn "anonymous + malformed
        # JSON" into a 422 (decision D-18). The body is read below, AFTER the gates.
        # The gates and the handler do blocking database calls: both run in the thread pool.
        allowed = await run_in_threadpool(run_gates, request, spec, deps)
        body = await request.body() if spec.has_body else b""
        return await run_in_threadpool(handler, Context(allowed, deps, request, body))

    app.add_api_route(
        spec.path,
        endpoint,
        methods=[spec.method],
        response_model=None,
        include_in_schema=False,
        name=f"{spec.method} {spec.path}",
    )


def _request_id(request: Request) -> UUID:
    request_id: UUID = request.state.request_id  # set by RequestContextMiddleware
    return request_id


def create_app(settings: Settings) -> FastAPI:
    engine = make_engine(settings.database_url.get_secret_value())
    verifier = TokenVerifier(
        load_public_key(settings.jwt_public_key_pem), settings.jwt_issuer, settings.jwt_audience
    )
    deps = Deps(session_factory=sessionmaker(engine, expire_on_commit=False), verifier=verifier)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(
        title="Tenant Boundary Lab",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        redirect_slashes=False,  # a redirect would reveal routes and change method semantics
        lifespan=lifespan,
    )
    app.add_middleware(RequestContextMiddleware)

    async def not_found(request: Request, exc: Exception) -> Response:
        # Unknown path, or a known path with the wrong method: one shape, no Allow header.
        return problem_response(_request_id(request), ApiProblem(ErrorCode.RESOURCE_NOT_FOUND))

    async def unprocessable(request: Request, exc: Exception) -> Response:
        # Fail-safe: no route declares typed parameters, but if one ever does its message must
        # not echo the offending input.
        return problem_response(_request_id(request), ApiProblem(ErrorCode.REQUEST_INVALID))

    async def other_http_error(request: Request, exc: Exception) -> Response:
        return problem_response(_request_id(request), ApiProblem(ErrorCode.INTERNAL_ERROR))

    app.add_exception_handler(StarletteHTTPException, other_http_error)
    app.add_exception_handler(RequestValidationError, unprocessable)
    app.add_exception_handler(404, not_found)
    app.add_exception_handler(405, not_found)

    for spec in ROUTES:
        _mount(app, spec, deps)
    return app
