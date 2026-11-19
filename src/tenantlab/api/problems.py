"""RFC 9457 problem responses: one fixed title/detail/status per error code.

`detail` is a constant per code and NEVER contains user input. The request id comes from the server.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final
from uuid import UUID

from starlette.responses import JSONResponse

from tenantlab.schemas.errors import PROBLEM_MEDIA_TYPE, ErrorCode, FieldError, ProblemDetail


@dataclass(frozen=True, slots=True)
class ProblemText:
    status: int
    title: str
    detail: str


# Statuses are the contract in docs/api-contract.md s3 / oracle gates.csv (a test compares them).
PROBLEMS: Final[Mapping[ErrorCode, ProblemText]] = MappingProxyType(
    {
        ErrorCode.AUTH_TOKEN_INVALID: ProblemText(
            401, "Unauthorized", "Authentication is required."
        ),
        ErrorCode.AUTH_PRINCIPAL_DISABLED: ProblemText(
            403, "Forbidden", "This account is disabled."
        ),
        ErrorCode.RESOURCE_NOT_FOUND: ProblemText(
            404, "Not found", "The requested resource was not found."
        ),
        ErrorCode.TENANT_SUSPENDED: ProblemText(403, "Forbidden", "This tenant is suspended."),
        ErrorCode.AUTHZ_FORBIDDEN: ProblemText(
            403, "Forbidden", "You do not have permission to perform this action."
        ),
        ErrorCode.AUTHZ_MARKET_DENIED: ProblemText(
            403, "Forbidden", "This tenant may not use the requested market."
        ),
        ErrorCode.REQUEST_INVALID: ProblemText(
            422, "Unprocessable request", "The request is invalid."
        ),
        ErrorCode.REQUEST_TOO_LARGE: ProblemText(
            413, "Payload too large", "The request body is too large."
        ),
        ErrorCode.CONFLICT_STALE_REVISION: ProblemText(
            409, "Conflict", "The resource was changed by someone else."
        ),
        ErrorCode.CONFLICT_LAST_OWNER: ProblemText(
            409, "Conflict", "A tenant must keep at least one active owner."
        ),
        ErrorCode.QUOTA_EXCEEDED: ProblemText(429, "Too many requests", "A quota was exceeded."),
        ErrorCode.SERVICE_UNAVAILABLE: ProblemText(
            503, "Service unavailable", "The service is temporarily unavailable."
        ),
        ErrorCode.INTERNAL_ERROR: ProblemText(
            500, "Internal error", "An unexpected error occurred."
        ),
    }
)

NOT_IMPLEMENTED_STATUS: Final = 501
NOT_IMPLEMENTED_DETAIL: Final = "This operation is not implemented in this milestone."


class ApiProblem(Exception):
    """Raise to end the request with a problem response. Carries no user input."""

    def __init__(
        self,
        code: ErrorCode,
        *,
        status: int | None = None,
        detail: str | None = None,
        headers: Mapping[str, str] | None = None,
        errors: Sequence[FieldError] = (),
    ) -> None:
        super().__init__(code.value)
        self.code = code
        self.status = status if status is not None else PROBLEMS[code].status
        self.detail = detail if detail is not None else PROBLEMS[code].detail
        self.headers = dict(headers or {})
        self.errors = tuple(errors)


def problem_response(request_id: UUID, problem: ApiProblem) -> JSONResponse:
    text = PROBLEMS[problem.code]
    body = ProblemDetail(
        type=ProblemDetail.type_for(problem.code),
        title=text.title,
        status=problem.status,
        code=problem.code,
        detail=problem.detail,
        request_id=request_id,
        errors=problem.errors,
    ).model_dump(mode="json")
    return JSONResponse(
        body,
        status_code=problem.status,
        media_type=PROBLEM_MEDIA_TYPE,
        headers=problem.headers,
    )
