"""A malformed oracle or fixture must raise, never degrade into 'allow' or partial data."""

from __future__ import annotations

import pytest

from tenantlab.oracle import matrix
from tenantlab.oracle.matrix import OracleDataError

HEADER = "operation,capability,owner,admin,editor,viewer,spec_ref\n"


def _patch(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    monkeypatch.setattr(matrix, "_read_text", lambda name: text)


@pytest.mark.parametrize(
    "body",
    [
        "",  # empty file
        "wrong,header\nx,y\n",  # unexpected header
        HEADER,  # header only: no rules
        HEADER + "project.read,projects:read,Y,Y,Y\n",  # too few cells
        HEADER + "project.read,projects:read,Y,Y,Y,Y,ref,extra\n",  # too many cells
        HEADER
        + "project.read,projects:read,Y,Y,Y,,ref\n",  # BLANK cell must not mean deny-or-allow
        HEADER + "project.read,projects:read,Y,Y,Y,y,ref\n",  # lowercase is not Y
        HEADER + "project.read,projects:read,Y,Y,Y,yes,ref\n",
        HEADER + "project.read,projects:read,Y,Y,Y,Y,ref\nproject.read,x,N,N,N,N,ref\n",  # dup
        HEADER + ",projects:read,Y,Y,Y,Y,ref\n",  # empty operation
    ],
)
def test_malformed_capabilities_raise(monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    _patch(monkeypatch, body)
    with pytest.raises(OracleDataError):
        matrix.load_capabilities()


GATES_HEADER = "order,gate,applies_to,deny_condition,http_status,problem_code,audit,standard_ref\n"


@pytest.mark.parametrize(
    "row",
    [
        "x,authenticate,all,c,401,auth.token_invalid,none,s\n",  # non-numeric order
        "1,authenticate,all,c,abc,auth.token_invalid,none,s\n",  # non-numeric status
        "1,authenticate,all,c,401,auth.made_up,none,s\n",  # unknown error code
        "1,authenticate,all,c,401,auth.token_invalid,sometimes,s\n",  # unknown audit policy
    ],
)
def test_malformed_gates_raise(monkeypatch: pytest.MonkeyPatch, row: str) -> None:
    _patch(monkeypatch, GATES_HEADER + row)
    with pytest.raises(OracleDataError):
        matrix.load_gates()


FIELD_HEADER = "resource,field,read_min_role,surfaces,on_create,on_update,notes\n"


@pytest.mark.parametrize(
    "row",
    [
        "r,f,superuser,s,server,server,\n",  # unknown role
        "r,f,never,project.detail,server,server,\n",  # 'never' field listing a surface
        "r,f,viewer,,server,server,\n",  # readable field with no surface
        "r,f,viewer,s,maybe,server,\n",  # unknown write mode
        "r,f,viewer,s,server,server,\nr,f,viewer,s,server,server,\n",  # duplicate
    ],
)
def test_malformed_field_policy_raises(monkeypatch: pytest.MonkeyPatch, row: str) -> None:
    _patch(monkeypatch, FIELD_HEADER + row)
    with pytest.raises(OracleDataError):
        matrix.load_field_policy()
