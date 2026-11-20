"""Isolation guards for the vulnerable lab (docs/vulnerable-lab.md s1, decisions D-41, D-44, D-45).

Everything here FAILS CLOSED and raises `LabIsolationError`: there is no fallback to the patched
app and no way to turn a guard off. The environment flags are guardrails; the container is the
network boundary.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any, Final

from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from starlette.types import ASGIApp, Receive, Scope, Send

from tenantlab.api.problems import ApiProblem
from tenantlab.schemas.errors import ErrorCode

SYNTHETIC_EMAIL_SUFFIX: Final = "@tenantlab.invalid"
ALLOWED_ENVIRONMENTS: Final = ("lab", "test")


class LabIsolationError(RuntimeError):
    """The vulnerable lab refuses to run here. Never caught and downgraded."""


def _is_loopback(value: str) -> bool:
    """A LITERAL loopback IP (v4, v6 or IPv4-mapped). Names, ports and brackets are not IPs."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    return address.is_loopback or (mapped is not None and mapped.is_loopback)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def require_lab_environment(environ: Mapping[str, str]) -> None:
    if environ.get("LAB_MODE") != "1":
        raise LabIsolationError("LAB_MODE must be exactly '1': the vulnerable lab is opt-in")
    if environ.get("TENANTLAB_ENV") not in ALLOWED_ENVIRONMENTS:
        raise LabIsolationError(
            "TENANTLAB_ENV must be exactly 'lab' or 'test': never production, never unset"
        )


def require_loopback_bind(host: str) -> None:
    if not _is_loopback(host):
        raise LabIsolationError(
            "bind address must be a literal loopback IP (127.0.0.0/8 or ::1), "
            "not a name, a port or a network address"
        )


def require_sqlite_file(database_url: str) -> None:
    try:
        url = make_url(database_url)
    except Exception:  # the message of a URL parse error can contain a password
        raise LabIsolationError(
            "the database URL is not valid; a SQLite file is required"
        ) from None
    if url.get_backend_name() != "sqlite" or url.database in (None, "", ":memory:"):
        raise LabIsolationError(
            "the database must be a SQLite file: never a networked or in-memory database"
        )


def require_synthetic_data(engine: Engine) -> None:
    """D-44: every principal must carry a synthetic e-mail, and there must be at least one, so the
    check cannot pass because there was nothing to check."""
    try:
        with engine.connect() as connection:
            emails = [row[0] for row in connection.execute(text("SELECT email FROM principals"))]
    except SQLAlchemyError:
        raise LabIsolationError(
            "cannot verify that the database holds only synthetic data (is it migrated and seeded?)"
        ) from None
    if not emails:
        raise LabIsolationError(
            "no synthetic principals found: refusing to start on an empty database"
        )
    real = [e for e in emails if not str(e).lower().endswith(SYNTHETIC_EMAIL_SUFFIX)]
    if real:
        raise LabIsolationError(
            f"{len(real)} principal(s) are not synthetic "
            f"(e-mail must end {SYNTHETIC_EMAIL_SUFFIX}); "
            "the vulnerable lab never runs on real data"
        )


def peer_is_local(scope: Mapping[str, Any]) -> bool:
    """The request guard (D-45). A Unix-socket peer has no IP and is local. A TCP peer must be a
    loopback IP. A local server address that is an IP literal must be loopback too (a hostname
    there is what the in-process test transport supplies)."""
    client = scope.get("client")
    if client is not None and client[0] != "" and not _is_loopback(str(client[0])):
        return False
    server = scope.get("server")
    return not (server is not None and _is_ip(str(server[0])) and not _is_loopback(str(server[0])))


class LoopbackOnlyMiddleware:
    """Refuses every request from a non-local peer, however the process was started."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and not peer_is_local(scope):
            raise ApiProblem(ErrorCode.AUTHZ_FORBIDDEN)  # rendered by RequestContextMiddleware
        await self.app(scope, receive, send)
