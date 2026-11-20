"""Factory for the vulnerable lab. Every guard in `guard.py` runs HERE, before anything is built;
if one fails the call raises and no application object exists (decision D-41: no fallback)."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator, Callable, Iterable, Mapping
from contextlib import asynccontextmanager
from typing import Any, Final
from uuid import UUID

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import sessionmaker
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tenantlab.api.middleware import RequestContextMiddleware
from tenantlab.api.problems import ApiProblem, problem_response
from tenantlab.auth.tokens import TokenVerifier, load_public_key
from tenantlab.config import Settings
from tenantlab.db.engine import make_engine
from tenantlab.lab.vulnerable import handlers
from tenantlab.lab.vulnerable.flaws import ALL_FLAWS, Flaw
from tenantlab.lab.vulnerable.guard import (
    LoopbackOnlyMiddleware,
    require_lab_environment,
    require_loopback_bind,
    require_sqlite_file,
    require_synthetic_data,
)
from tenantlab.schemas.errors import ErrorCode

logger = logging.getLogger("tenantlab.lab.vulnerable")

MARKER_HEADER: Final = "X-Tenantlab-Vulnerable"

Handler = Callable[[handlers.Ctx, Request, handlers.Ids, bytes], Response]
#: method, path, handler, path parameters, reads a body
ROUTES: Final[tuple[tuple[str, str, Handler, tuple[str, ...], bool], ...]] = (
    ("GET", "/v1/tenants/{tenant_id}/me", handlers.me, ("tenant_id",), False),
    ("GET", "/v1/tenants/{tenant_id}/projects", handlers.list_projects, ("tenant_id",), False),
    ("GET", "/v1/projects/{project_id}", handlers.read_project, ("project_id",), False),
    ("PATCH", "/v1/projects/{project_id}", handlers.patch_project, ("project_id",), True),
    ("GET", "/v1/projects/{project_id}/contacts", handlers.read_contacts, ("project_id",), False),
    ("GET", "/v1/invoices/{invoice_id}", handlers.read_invoice, ("invoice_id",), False),
)


class MarkingMiddleware:
    """Every response says what it came from (decision D-47), even a refusal or an error."""

    def __init__(self, app: ASGIApp, value: str) -> None:
        self.app = app
        self.value = value

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def marked(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)[MARKER_HEADER] = self.value
            await send(message)

        await self.app(scope, receive, marked)


def _request_id(request: Request) -> UUID:
    request_id: UUID = request.state.request_id
    return request_id


def create_vulnerable_app(
    settings: Settings,
    *,
    flaws: Iterable[Flaw] | None = None,
    environ: Mapping[str, str] | None = None,
    bind_host: str | None = None,
) -> FastAPI:
    """Build the vulnerable app, or raise `LabIsolationError`. `bind_host` is where the caller
    intends to listen (None: a Unix socket or an in-process transport)."""
    env = os.environ if environ is None else environ
    require_lab_environment(env)
    if bind_host is not None:
        require_loopback_bind(bind_host)
    database_url = settings.database_url.get_secret_value()
    require_sqlite_file(database_url)
    engine = make_engine(database_url)
    try:
        require_synthetic_data(engine)
    except Exception:
        engine.dispose()
        raise

    enabled = ALL_FLAWS if flaws is None else frozenset(flaws)
    names = ",".join(sorted(f.name for f in enabled)) or "none"
    logger.warning(
        "DELIBERATELY VULNERABLE LAB: local only, synthetic data, never deploy. flaws=%s", names
    )
    verifier = TokenVerifier(
        load_public_key(settings.jwt_public_key_pem), settings.jwt_issuer, settings.jwt_audience
    )
    sessions = sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(
        title="Tenant Boundary Lab: DELIBERATELY VULNERABLE (local only)",
        docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False, lifespan=lifespan,
    )  # fmt: skip
    # last added is outermost: marking -> request context -> loopback guard -> routes
    app.add_middleware(LoopbackOnlyMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(MarkingMiddleware, value=f"deliberately-broken-lab; flaws={names}")

    def mount(
        method: str, path: str, handler: Handler, id_names: tuple[str, ...], has_body: bool
    ) -> None:
        def run(request: Request, body: bytes) -> Response:
            with sessions() as db:
                principal, status = handlers.authenticate(request, verifier, db)
                if status != "active":
                    raise ApiProblem(ErrorCode.AUTH_PRINCIPAL_DISABLED)
                ids = handlers.parse_ids(id_names, request)
                return handler(handlers.Ctx(db, enabled, principal), request, ids, body)

        async def endpoint(request: Request) -> Response:
            body: Any = await request.body() if has_body else b""
            return await run_in_threadpool(run, request, body)

        app.add_api_route(
            path, endpoint, methods=[method], response_model=None, include_in_schema=False,
            name=f"{method} {path}",
        )  # fmt: skip

    for route in ROUTES:
        mount(*route)

    async def not_found(request: Request, exc: Exception) -> Response:
        return problem_response(_request_id(request), ApiProblem(ErrorCode.RESOURCE_NOT_FOUND))

    async def unprocessable(request: Request, exc: Exception) -> Response:
        return problem_response(_request_id(request), ApiProblem(ErrorCode.REQUEST_INVALID))

    async def other_http_error(request: Request, exc: Exception) -> Response:
        return problem_response(_request_id(request), ApiProblem(ErrorCode.INTERNAL_ERROR))

    app.add_exception_handler(StarletteHTTPException, other_http_error)
    app.add_exception_handler(RequestValidationError, unprocessable)
    app.add_exception_handler(404, not_found)
    app.add_exception_handler(405, not_found)
    return app
