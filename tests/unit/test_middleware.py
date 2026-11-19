"""The outermost ASGI layer in isolation: request id, body cap, and last-resort error mapping.

An inner app that reads or raises stands in for the routes, so the cases that cannot be reached
through the real routes in M1 (streamed bodies, a crash after the response started) are still
proven. The 413-for-chunked path matters from M2 on, when handlers start reading bodies.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy.exc import OperationalError
from starlette.types import Message, Receive, Scope, Send

from tenantlab.api.app import create_app
from tenantlab.api.middleware import MAX_BODY_BYTES, RequestContextMiddleware
from tenantlab.api.problems import ApiProblem
from tenantlab.config import Settings
from tenantlab.schemas.errors import ErrorCode
from tests.harness import AUDIENCE, BASE_URL, ISSUER, KeyPair, assert_problem

CAP = 100
App = Callable[[Scope, Receive, Send], Awaitable[None]]


class Spy:
    """An inner ASGI app that optionally reads the whole body, then answers 200."""

    def __init__(self, *, read_body: bool = True) -> None:
        self.read_body = read_body
        self.calls = 0
        self.body_seen = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.calls += 1
        if scope["type"] == "http" and self.read_body:
            while True:
                message = await receive()
                self.body_seen += len(message.get("body", b""))
                if not message.get("more_body", False):
                    break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})


def _client(app: App) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)


async def _chunks(*sizes: int) -> AsyncIterator[bytes]:
    for size in sizes:
        yield b"x" * size


# ------------------------------------------------------------------------- body cap ----


@pytest.mark.parametrize(
    ("sizes", "status"), [((100,), 200), ((101,), 413), ((40, 40, 20), 200), ((40, 40, 21), 413)]
)
async def test_a_streamed_body_without_a_length_is_counted_as_it_is_read(
    sizes: tuple[int, ...], status: int
) -> None:
    inner = Spy()
    async with _client(RequestContextMiddleware(inner, max_body_bytes=CAP)) as client:
        response = await client.post("/x", content=_chunks(*sizes))  # chunked: no Content-Length
    assert response.status_code == status
    if status == 413:
        assert_problem(response, status=413, code="request.too_large")
        assert response.headers["x-request-id"]


async def test_a_declared_oversize_length_never_reaches_the_inner_app() -> None:
    inner = Spy()
    async with _client(RequestContextMiddleware(inner, max_body_bytes=CAP)) as client:
        response = await client.post("/x", content=b"x" * (CAP + 1))
    assert_problem(response, status=413, code="request.too_large")
    assert inner.calls == 0


async def test_a_disconnect_message_passes_through_the_limiter_untouched() -> None:
    seen: list[Message] = []

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(await receive())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    scope: Scope = {"type": "http", "headers": [], "method": "GET", "path": "/x"}

    async def receive() -> Message:
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        return None

    await RequestContextMiddleware(inner)(scope, receive, send)
    assert seen == [{"type": "http.disconnect"}]


async def test_the_default_cap_is_65536() -> None:
    assert MAX_BODY_BYTES == 65_536


async def _raw_call(
    app: App, *, headers: list[tuple[bytes, bytes]], scope_type: str = "http"
) -> list[Message]:
    scope: Scope = {
        "type": scope_type,
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/x",
        "raw_path": b"/x",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 1),
        "server": ("test", 80),
    }
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive, send)
    return sent


async def test_two_content_length_headers_are_a_422() -> None:
    inner = Spy()
    sent = await _raw_call(
        RequestContextMiddleware(inner),
        headers=[(b"content-length", b"1"), (b"content-length", b"1")],
    )
    assert sent[0]["status"] == 422
    assert inner.calls == 0


async def test_a_non_http_scope_passes_straight_through() -> None:
    inner = Spy(read_body=False)
    scopes: list[Scope] = []

    async def recording(scope: Scope, receive: Receive, send: Send) -> None:
        scopes.append(scope)

    await RequestContextMiddleware(recording)(
        {"type": "lifespan", "asgi": {"version": "3.0"}}, _never, _discard
    )
    assert len(scopes) == 1
    assert "state" not in scopes[0], "no request id is created for a lifespan scope"
    assert inner.calls == 0


async def _never() -> Message:
    raise AssertionError("receive must not be called")


async def _discard(message: Message) -> None:
    raise AssertionError("send must not be called")


# ------------------------------------------------------------------- error mapping ----


class Crash:
    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        raise self.exc


async def test_an_unexpected_exception_is_a_generic_500_that_leaks_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "secret-detail-xyz /etc/passwd Traceback"
    async with _client(RequestContextMiddleware(Crash(RuntimeError(secret)))) as client:
        with caplog.at_level(logging.INFO, logger="tenantlab"):
            response = await client.get("/x")
    assert_problem(response, status=500, code="internal.error")
    assert "secret-detail" not in response.text
    flat = " ".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records)
    assert "secret-detail" not in flat, "an exception message may carry data: log the class only"
    records = [r for r in caplog.records if getattr(r, "event", None) == "internal.error"]
    assert records[0].__dict__["error"] == "RuntimeError"
    assert records[0].__dict__["request_id"] == response.headers["x-request-id"]


async def test_a_database_error_is_503_and_never_an_allow() -> None:
    boom = OperationalError("SELECT secret FROM t WHERE x = ?", ("param-value",), Exception("db"))
    async with _client(RequestContextMiddleware(Crash(boom))) as client:
        response = await client.get("/x")
    assert_problem(response, status=503, code="service.unavailable")
    assert "secret" not in response.text
    assert "param-value" not in response.text


async def test_an_api_problem_is_rendered_with_its_headers() -> None:
    problem = ApiProblem(ErrorCode.AUTH_TOKEN_INVALID, headers={"WWW-Authenticate": "Bearer"})
    async with _client(RequestContextMiddleware(Crash(problem))) as client:
        response = await client.get("/x")
    assert_problem(response, status=401, code="auth.token_invalid")
    assert response.headers["www-authenticate"] == "Bearer"


async def test_a_crash_after_the_response_started_is_re_raised_not_masked() -> None:
    """Headers are already on the wire: a second response is impossible, so the error must
    propagate to the server (which closes the connection) rather than be swallowed."""

    async def half_then_crash(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        raise ValueError("late failure")

    with pytest.raises(ValueError, match="late failure"):
        await _raw_call(RequestContextMiddleware(half_then_crash), headers=[])


async def test_the_request_id_header_is_added_even_to_the_applications_own_response() -> None:
    sent = await _raw_call(RequestContextMiddleware(Spy()), headers=[])
    headers = {k.lower(): v for k, v in sent[0]["headers"]}
    assert len(headers[b"x-request-id"]) == 36
    assert headers[b"cache-control"] == b"no-store"
    assert headers[b"x-content-type-options"] == b"nosniff"


async def test_a_client_supplied_request_id_is_ignored() -> None:
    sent = await _raw_call(
        RequestContextMiddleware(Spy()), headers=[(b"x-request-id", b"attacker-chosen")]
    )
    headers = {k.lower(): v for k, v in sent[0]["headers"]}
    assert headers[b"x-request-id"] != b"attacker-chosen"


# ---------------------------------------------- the real app's framework-level handlers ----


def _app(tmp_path: Path, keys: KeyPair) -> Any:
    return create_app(
        Settings(
            database_url=f"sqlite+pysqlite:///{tmp_path / 'x.sqlite'}",  # type: ignore[arg-type]
            jwt_issuer=ISSUER,
            jwt_audience=AUDIENCE,
            jwt_public_key_pem=keys.public_pem,
        )
    )


async def test_a_framework_validation_error_never_echoes_the_input(
    tmp_path: Path, trusted_keys: KeyPair
) -> None:
    """Fail-safe: no registered route declares typed parameters, but if one ever does its 422
    must still be the generic problem and not FastAPI's default body (which echoes the value)."""
    app = _app(tmp_path, trusted_keys)

    @app.get("/__probe/{number}")
    def probe(number: int) -> dict[str, int]:  # a test-only route with a typed parameter
        return {"number": number}

    async with _client(app) as client:
        response = await client.get("/__probe/echo-me-please")
    assert_problem(response, status=422, code="request.invalid")
    assert "echo-me-please" not in response.text
    assert "detail" in response.json()
    assert response.json()["errors"] == []


async def test_an_unexpected_http_exception_is_a_generic_500(
    tmp_path: Path, trusted_keys: KeyPair
) -> None:
    """Every deliberate denial uses ApiProblem. A stray HTTPException (a coding mistake) must not
    produce FastAPI's default body, which could carry free text."""
    app = _app(tmp_path, trusted_keys)

    @app.get("/__teapot")
    def teapot() -> None:
        raise HTTPException(status_code=418, detail="free text that must not leak")

    async with _client(app) as client:
        response = await client.get("/__teapot")
    assert_problem(response, status=500, code="internal.error")
    assert "free text" not in response.text


def test_the_json_helpers_used_here_are_available() -> None:
    assert json.dumps({}) == "{}"
