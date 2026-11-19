"""The problem+json table: one fixed status/title/detail per code, as the contract says."""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

import pytest

from tenantlab.api.problems import (
    NOT_IMPLEMENTED_DETAIL,
    PROBLEMS,
    ApiProblem,
    problem_response,
)
from tenantlab.oracle.matrix import load_gates
from tenantlab.schemas.errors import PROBLEM_MEDIA_TYPE, ErrorCode, ProblemDetail

DOCS = Path(__file__).resolve().parents[2] / "docs"
RID = uuid.UUID("5e1b0e0e-3b0a-4b86-8a3e-0f4d1e1d2c3b")


def test_every_error_code_has_exactly_one_entry() -> None:
    assert set(PROBLEMS) == set(ErrorCode)


def test_statuses_equal_the_oracle_gate_table() -> None:
    for gate in load_gates():
        assert PROBLEMS[gate.problem_code].status == gate.http_status, gate.gate


def test_statuses_equal_the_table_in_the_api_contract() -> None:
    documented = {}
    for line in (DOCS / "api-contract.md").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\| `([a-z]+\.[a-z_]+)` \| (\d{3}) \|", line)
        if m:
            documented[m.group(1)] = int(m.group(2))
    assert documented == {code.value: PROBLEMS[code].status for code in ErrorCode}


@pytest.mark.parametrize("code", list(ErrorCode))
def test_the_detail_is_a_constant_that_cannot_carry_user_input(code: ErrorCode) -> None:
    text = PROBLEMS[code]
    for value in (text.title, text.detail):
        assert value
        assert len(value) < 120
        assert not re.search(r"[{}%$<>]", value), "templating characters in a fixed message"
    assert text.detail.endswith(".")


@pytest.mark.parametrize("code", list(ErrorCode))
def test_the_response_validates_against_the_strict_schema(code: ErrorCode) -> None:
    response = problem_response(RID, ApiProblem(code))
    assert response.media_type == PROBLEM_MEDIA_TYPE
    assert response.status_code == PROBLEMS[code].status
    body = json.loads(bytes(response.body))
    parsed = ProblemDetail.model_validate(body)
    assert parsed.request_id == RID
    assert parsed.code is code
    assert body["errors"] == []
    assert set(body) == {"type", "title", "status", "code", "detail", "request_id", "errors"}


def test_the_not_implemented_override_keeps_the_schema() -> None:
    problem = ApiProblem(ErrorCode.INTERNAL_ERROR, status=501, detail=NOT_IMPLEMENTED_DETAIL)
    body = json.loads(bytes(problem_response(RID, problem).body))
    ProblemDetail.model_validate(body)
    assert body["status"] == 501
    assert body["detail"] == NOT_IMPLEMENTED_DETAIL


def test_headers_are_carried_through() -> None:
    problem = ApiProblem(ErrorCode.AUTH_TOKEN_INVALID, headers={"WWW-Authenticate": "Bearer"})
    assert problem_response(RID, problem).headers["www-authenticate"] == "Bearer"


def test_a_problem_never_contains_anything_but_its_code() -> None:
    assert str(ApiProblem(ErrorCode.RESOURCE_NOT_FOUND)) == "resource.not_found"
