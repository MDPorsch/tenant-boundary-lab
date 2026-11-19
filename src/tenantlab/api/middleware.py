"""Outermost ASGI layer: request id, security headers, gate 0 and last-resort error mapping.

* The server generates the request id (UUIDv4). A client-supplied X-Request-ID is never read, so it
  cannot be echoed or used for log injection (TL-18).
* Gate 0 (transport limits) runs before authentication and is identity-independent: a declared
  Content-Length above the cap is refused with 413. A body without a declared length (chunked) is
  counted as it is read; because bodies are read only after the gates (D-18), such a request from
  an unauthenticated caller gets 401 first and its body is never read (see LIMITATIONS).
* Any unexpected exception becomes a generic problem response. A database failure is 503: the
  service FAILS CLOSED and never allows a request because a lookup failed.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Final

from sqlalchemy.exc import SQLAlchemyError
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tenantlab.api.problems import ApiProblem, problem_response
from tenantlab.schemas.errors import ErrorCode

logger = logging.getLogger("tenantlab.api")

MAX_BODY_BYTES: Final = 65_536

_SECURITY_HEADERS: Final = (
    ("Cache-Control", "no-store"),  # tenant data must not be cached by intermediaries
    ("X-Content-Type-Options", "nosniff"),
)


class BodyTooLarge(Exception):  # internal signal, converted to a 413 below
    """The request body exceeded MAX_BODY_BYTES while being read."""


def _declared_length(scope: Scope) -> int | None:
    values = [value for name, value in scope["headers"] if name == b"content-length"]
    if not values:
        return None
    if len(values) != 1 or not values[0].isdigit():
        raise ApiProblem(ErrorCode.REQUEST_INVALID)
    return int(values[0])


def _limit_body(receive: Receive, limit: int) -> Receive:
    seen = 0

    async def limited() -> Message:
        nonlocal seen
        message = await receive()
        if message["type"] == "http.request":
            seen += len(message.get("body", b""))
            if seen > limit:
                raise BodyTooLarge
        return message

    return limited


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp, max_body_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4()
        scope.setdefault("state", {})["request_id"] = request_id
        started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = str(request_id)
                for name, value in _SECURITY_HEADERS:
                    headers[name] = value
            await send(message)

        try:
            length = _declared_length(scope)
            if length is not None and length > self.max_body_bytes:
                raise ApiProblem(ErrorCode.REQUEST_TOO_LARGE)
            await self.app(scope, _limit_body(receive, self.max_body_bytes), send_with_headers)
        except Exception as exc:  # last-resort mapper: nothing may escape as a raw error
            if started:
                raise
            problem = self._to_problem(exc, request_id)
            response = problem_response(request_id, problem)
            await response(scope, receive, send_with_headers)

    @staticmethod
    def _to_problem(exc: Exception, request_id: uuid.UUID) -> ApiProblem:
        if isinstance(exc, ApiProblem):
            return exc
        if isinstance(exc, BodyTooLarge):
            return ApiProblem(ErrorCode.REQUEST_TOO_LARGE)
        extra: dict[str, Any] = {"request_id": str(request_id), "error": type(exc).__name__}
        if isinstance(exc, SQLAlchemyError):
            # Class name only: a statement or its parameters may hold tenant data.
            logger.error("database unavailable", extra={"event": "db.unavailable", **extra})
            return ApiProblem(ErrorCode.SERVICE_UNAVAILABLE)
        logger.error("unhandled error", extra={"event": "internal.error", **extra})
        return ApiProblem(ErrorCode.INTERNAL_ERROR)
