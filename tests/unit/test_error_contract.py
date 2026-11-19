"""RFC 9457 problem+json contract (docs/api-contract.md s3)."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from tenantlab.schemas.errors import (
    MAX_FIELD_ERRORS,
    PROBLEM_MEDIA_TYPE,
    ErrorCode,
    FieldError,
    ProblemDetail,
)


def _problem(**over: object) -> ProblemDetail:
    base: dict[str, object] = {
        "type": ProblemDetail.type_for(ErrorCode.RESOURCE_NOT_FOUND),
        "title": "Not found",
        "status": 404,
        "code": ErrorCode.RESOURCE_NOT_FOUND,
        "detail": "The requested resource was not found.",
        "request_id": uuid4(),
    }
    return ProblemDetail(**{**base, **over})  # type: ignore[arg-type]


def test_media_type_is_problem_json() -> None:
    assert PROBLEM_MEDIA_TYPE == "application/problem+json"


def test_serialised_shape_has_the_documented_members() -> None:
    body = json.loads(_problem().model_dump_json())
    assert set(body) == {"type", "title", "status", "code", "detail", "request_id", "errors"}
    assert body["code"] == "resource.not_found"
    assert body["type"] == "urn:tenantlab:error:resource.not_found"


def test_every_error_code_has_a_valid_type_uri() -> None:
    for code in ErrorCode:
        assert _problem(type=ProblemDetail.type_for(code), code=code).type.endswith(code.value)


def test_unknown_code_and_unknown_members_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _problem(code="auth.invented")
    with pytest.raises(ValidationError):
        _problem(echo="<script>")  # extra members (e.g. an echoed input) are forbidden


def test_status_must_be_an_error_status() -> None:
    for bad in (200, 302, 399, 600):
        with pytest.raises(ValidationError):
            _problem(status=bad)


def test_request_id_must_be_a_uuid_not_free_text() -> None:
    """Log-injection guard: a client-supplied header value can never become request_id."""
    with pytest.raises(ValidationError):
        _problem(request_id="evil\r\nX-Injected: 1")


def test_field_errors_carry_location_and_code_only_never_the_input() -> None:
    assert set(FieldError.model_fields) == {"loc", "code"}
    FieldError(loc=("body", "title"), code="string_too_long")
    with pytest.raises(ValidationError):
        FieldError(loc=("body", "title"), code="x", input="hunter2")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        FieldError(loc=("body",), code="Has Spaces/Symbols!")


def test_field_error_list_is_bounded() -> None:
    errors = tuple(FieldError(loc=("body", i), code="invalid") for i in range(MAX_FIELD_ERRORS + 1))
    with pytest.raises(ValidationError):
        _problem(errors=errors)


def test_problem_is_immutable() -> None:
    problem = _problem()
    with pytest.raises(ValidationError):
        problem.status = 500  # type: ignore[misc]
