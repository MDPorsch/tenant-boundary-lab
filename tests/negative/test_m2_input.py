"""TL-10 and TL-15 (milestone M2): hostile pagination, identifiers and request bodies.

STATUS: written RED-FIRST for M2 (see test_m2_authorization.py). Every rejection must be
`422 request.invalid` with a body that never echoes the input, exactly one tenant-scoped audit row
and no change to any business table. Body above 65 536 bytes: `413` before authentication.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

import pytest

from tests.harness import Lab, assert_problem, assert_single_deny_audit
from tests.support_m2 import (
    SIXTY_FIVE_KIB,
    body_routes,
    count_statements,
    insert_audit_rows,
    insert_contacts,
    insert_projects,
)

pytestmark = pytest.mark.milestone("M2")

OpenLab = Callable[..., Any]
CODE_RE = re.compile(r"^[a-z0-9_.]+$")


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()


def _list_routes(lab: Lab) -> dict[str, tuple[str, str, str]]:
    """name -> (path, audit action, audit resource_type)"""
    return {
        "projects": (f"/v1/tenants/{lab.fx.tenant('A').id}/projects", "project.list", "tenant"),
        "contacts": (
            f"/v1/projects/{lab.fx.project('PA1').id}/contacts", "contact.private.read", "contact",
        ),
        "audit": (f"/v1/tenants/{lab.fx.tenant('A').id}/audit", "audit.read", "audit"),
    }  # fmt: skip


async def _assert_422_audited(lab: Lab, route: str, query: str) -> None:
    path, action, resource_type = _list_routes(lab)[route]
    before = lab.snapshot()
    response = await lab.request("GET", f"{path}{query}", headers=lab.bearer("alice"))
    problem = assert_problem(response, status=422, code="request.invalid")
    assert len(problem["errors"]) <= 20
    assert_single_deny_audit(
        lab, before, response, actor=lab.fx.principal("alice").id, tenant=lab.fx.tenant("A").id,
        action=action, resource_type=resource_type, reason_code="request.invalid",
    )  # fmt: skip


# ---------------------------------------------------------------------------- TL-10 ----
BAD_LIMITS = ["0", "-1", "101", "1000", "abc", "1.5", "+5", "05", "1e1", "", "٣", "5 ", " 5", "0x5"]


@pytest.mark.parametrize("route", ["projects", "contacts", "audit"])
@pytest.mark.parametrize("limit", BAD_LIMITS)
async def test_tl10_a_bad_limit_is_422(open_lab: OpenLab, route: str, limit: str) -> None:
    lab: Lab = await open_lab()
    await _assert_422_audited(lab, route, "?" + urlencode({"limit": limit}))


@pytest.mark.parametrize("route", ["projects", "contacts", "audit"])
@pytest.mark.parametrize("limit", ["1", "25", "100"])
async def test_tl10_a_good_limit_is_accepted(open_lab: OpenLab, route: str, limit: str) -> None:
    """Anti-vacuity: the 422s above are about the value, not about the parameter."""
    lab: Lab = await open_lab()
    path, _, _ = _list_routes(lab)[route]
    response = await lab.request("GET", f"{path}?limit={limit}", headers=lab.bearer("alice"))
    assert response.status_code == 200, response.text


async def test_tl10_an_invalid_utf8_query_value_is_422(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    await _assert_422_audited(lab, "projects", "?limit=%FF%FE")


async def test_tl10_the_rejected_value_is_never_echoed(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    path, _, _ = _list_routes(lab)["projects"]
    for query in ("?limit=ECHOMARKER9", "?cursor=ECHOMARKER9!!", "?ECHOMARKER9=1"):
        response = await lab.request("GET", path + query, headers=lab.bearer("alice"))
        assert_problem(response, status=422, code="request.invalid")
        assert "ECHOMARKER9" not in response.text


BAD_CURSORS = {
    "oversized": "A" * 257,
    "not_base64url": "not base64!!",
    "padding_chars": "aGVsbG8=",
    "plus_slash": "a+b/c",
    "decodes_to_text": _b64("hello"),
    "decodes_to_nothing_useful": "A" * 256,
    "decodes_to_an_integer_on_a_uuid_route": _b64("42"),
    "decodes_to_non_ascii_bytes": "__4",  # base64url of 0xFF 0xFE
    "decodes_to_a_non_canonical_uuid": _b64("ABCDEF00-0000-4000-8000-000000000001"),
    "empty_value": "",
}


@pytest.mark.parametrize("name", sorted(BAD_CURSORS))
async def test_tl10_a_bad_cursor_is_422(open_lab: OpenLab, name: str) -> None:
    lab: Lab = await open_lab()
    await _assert_422_audited(lab, "projects", "?" + urlencode({"cursor": BAD_CURSORS[name]}))


async def test_tl10_a_non_canonical_cursor_encoding_is_422(open_lab: OpenLab) -> None:
    """'NDI' is the canonical base64url of '42'; 'NDJ' decodes to the same bytes (the spare bits
    differ) but is a second spelling of one cursor. Exactly one spelling is accepted."""
    lab: Lab = await open_lab()
    path, _, _ = _list_routes(lab)["audit"]
    insert_audit_rows(lab, tenant="A", count=3)
    good = await lab.request("GET", f"{path}?cursor=NDI", headers=lab.bearer("alice"))
    assert good.status_code == 200, good.text
    await _assert_422_audited(lab, "audit", "?cursor=NDJ")


async def test_tl10_a_cursor_of_the_wrong_kind_is_422(open_lab: OpenLab) -> None:
    """Project/contact cursors are UUIDs, audit cursors are integers: not interchangeable."""
    lab: Lab = await open_lab()
    a_uuid = _b64(lab.fx.project("PA1").id)
    await _assert_422_audited(lab, "audit", "?" + urlencode({"cursor": a_uuid}))
    await _assert_422_audited(lab, "projects", "?" + urlencode({"cursor": _b64("7")}))


async def test_tl10_a_cursor_naming_a_foreign_object_reveals_nothing(open_lab: OpenLab) -> None:
    """The cursor only moves the start point inside the caller's own readable set (D-33)."""
    lab: Lab = await open_lab()
    path, _, _ = _list_routes(lab)["projects"]
    for foreign in (
        lab.fx.project("PB1").id,
        lab.fx.project("PA2").id,
        lab.fx.never_seeded["project"],
    ):
        response = await lab.request(
            "GET", f"{path}?cursor={_b64(foreign)}", headers=lab.bearer("alice")
        )
        assert response.status_code == 200, response.text
        assert "SENTINEL-TENANT-B" not in response.text
        assert "US pilot" not in response.text


@pytest.mark.parametrize(
    "query", ["?page=-1", "?page=2", "?offset=0", "?limit=1&limit=2", "?sort=id"]
)
async def test_tl10_unknown_or_repeated_parameters_are_422(open_lab: OpenLab, query: str) -> None:
    lab: Lab = await open_lab()
    await _assert_422_audited(lab, "projects", query)


@pytest.mark.parametrize(
    "template",
    [
        "/v1/projects/not-a-uuid/contacts",
        "/v1/tenants/not-a-uuid/audit",
        "/v1/tenants/not-a-uuid/projects",
    ],
)
async def test_tl10_an_invalid_path_id_is_422_without_echo(
    open_lab: OpenLab, template: str
) -> None:
    lab: Lab = await open_lab()
    before = lab.snapshot()
    response = await lab.request("GET", template, headers=lab.bearer("alice"))
    assert_problem(response, status=422, code="request.invalid")
    assert "not-a-uuid" not in response.text
    assert lab.snapshot().business == before.business


async def test_tl10_cursor_pages_are_complete_ordered_and_disjoint(open_lab: OpenLab) -> None:
    lab: Lab = await open_lab()
    extra = insert_projects(lab, tenant="A", market="UK", count=7)
    expected = sorted([lab.fx.project("PA1").id, *extra])
    path, _, _ = _list_routes(lab)["projects"]
    pages, cursor = [], None
    while True:
        query = "?limit=3" + (f"&cursor={cursor}" if cursor else "")
        body = (await lab.request("GET", path + query, headers=lab.bearer("alice"))).json()
        pages.append([item["id"] for item in body["items"]])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert [len(p) for p in pages] == [3, 3, 2]
    assert [i for page in pages for i in page] == expected


CEILING = 14


async def _statements(lab: Lab, path: str) -> int:
    with count_statements() as seen:
        response = await lab.request("GET", path, headers=lab.bearer("alice"))
    assert response.status_code == 200, response.text
    return len(seen)


async def test_tl10_work_is_bounded_by_a_statement_ceiling_not_by_the_data(
    open_lab: OpenLab,
) -> None:
    """No N+1: the number of SQL statements per request does not grow with the rows involved."""
    lab: Lab = await open_lab()
    ids = {"A": lab.fx.tenant("A").id, "PA1": lab.fx.project("PA1").id}
    paths = {
        "list": f"/v1/tenants/{ids['A']}/projects?limit=100",
        "detail": f"/v1/projects/{ids['PA1']}",
        "contacts": f"/v1/projects/{ids['PA1']}/contacts?limit=100",
        "audit": f"/v1/tenants/{ids['A']}/audit?limit=100",
    }
    insert_audit_rows(lab, tenant="A", count=1)
    small = {name: await _statements(lab, path) for name, path in paths.items()}
    insert_projects(lab, tenant="A", market="UK", count=150)
    insert_contacts(lab, project="PA1", count=60)
    insert_audit_rows(lab, tenant="A", count=200)
    large = {name: await _statements(lab, path) for name, path in paths.items()}
    assert small == large, f"statement count grows with the data: {small} -> {large}"
    assert max(large.values()) <= CEILING, large


# ---------------------------------------------------------------------------- TL-15 ----
ROUTES = ["create", "patch", "put"]
NUMERIC_TEMPLATE = {  # the one field whose TYPE is attacked, per route
    "create": '{"title": "T", "market": %s}',
    "patch": '{"title": "T", "row_version": %s}',
    "put": '{"role": "viewer", "status": "active", "version": %s}',
}
BAD_NUMBERS = {
    "create": ["NaN", "1", "1.0", "true", "null", '["UK"]', '{"a": 1}', "Infinity"],
    "patch": ["NaN", "Infinity", '"1"', "1.0", "true", "null", "[1]", '{"a": 1}', "0", "-1",
              "2147483648", "99999999999999999999999", "1e2", '""'],
    "put": ["NaN", "Infinity", '"1"', "1.0", "true", "null", "[1]", '{"a": 1}', "0", "-1",
            "2147483648", "99999999999999999999999", "1e2", '""'],
}  # fmt: skip
JSON = "application/json"


async def _send(lab: Lab, route: str, raw: bytes, content_type: str | None = JSON) -> Any:
    method, path, _, _, _ = body_routes(lab)[route]
    headers = dict(lab.bearer("alice"))
    if content_type is not None:
        headers["Content-Type"] = content_type
    return await lab.request(method, path, headers=headers, content=raw)


async def _assert_body_rejected(
    lab: Lab, route: str, raw: bytes, content_type: str | None = JSON, *, marker: str | None = None
) -> None:
    _, _, action, resource_type, _ = body_routes(lab)[route]
    before = lab.snapshot()
    response = await _send(lab, route, raw, content_type)
    problem = assert_problem(response, status=422, code="request.invalid")
    assert len(problem["errors"]) <= 20
    for error in problem["errors"]:
        assert set(error) == {"loc", "code"}
        assert CODE_RE.match(error["code"])
    if marker:
        assert marker not in response.text, "the rejected input was echoed"
    assert_single_deny_audit(
        lab, before, response, actor=lab.fx.principal("alice").id, tenant=lab.fx.tenant("A").id,
        action=action, resource_type=resource_type, reason_code="request.invalid",
    )  # fmt: skip


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    "raw",
    [
        b"", b"   ", b"[]", b"null", b'"x"', b"1", b"true", b"{}", b'{"title": ', b"{'title': 'x'}",
        b"\xff\xfe", b'{"x": "\xff"}', b'{"x": "\xc0\xaf"}', b"\xef\xbb\xbf{}",
        b"[" * 60_000, b'{"a":' * 13_000, b'{"title": "a", "title": "b"}',
    ],
    ids=["empty", "blank", "array", "null", "string", "number", "true", "empty_object",
         "truncated", "single_quotes", "bad_utf8_a", "bad_utf8_b", "overlong_utf8", "bom",
         "depth_bomb_array", "depth_bomb_object", "duplicate_key"],
)  # fmt: skip
async def test_tl15_a_malformed_or_non_object_body_is_422(
    open_lab: OpenLab, route: str, raw: bytes
) -> None:
    lab: Lab = await open_lab()
    await _assert_body_rejected(lab, route, raw)


@pytest.mark.parametrize("route", ROUTES)
async def test_tl15_duplicate_keys_are_refused_even_when_the_last_value_is_valid(
    open_lab: OpenLab, route: str
) -> None:
    lab: Lab = await open_lab()
    valid = json.dumps(body_routes(lab)[route][4])
    first_key = next(iter(body_routes(lab)[route][4]))
    duplicated = valid[:-1] + f', "{first_key}": "ECHO9X"' + "}"
    await _assert_body_rejected(lab, route, duplicated.encode(), marker="ECHO9X")


@pytest.mark.parametrize(
    ("route", "value"),
    [(route, value) for route in ROUTES for value in BAD_NUMBERS[route]],
)
async def test_tl15_a_wrongly_typed_or_out_of_range_scalar_is_422(
    open_lab: OpenLab, route: str, value: str
) -> None:
    lab: Lab = await open_lab()
    await _assert_body_rejected(lab, route, (NUMERIC_TEMPLATE[route] % value).encode())


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
async def test_tl15_non_finite_numbers_are_invalid_json_not_merely_a_wrong_type(
    open_lab: OpenLab, route: str, constant: str
) -> None:
    """D-30: NaN and Infinity are not JSON. They are refused by the PARSER (`invalid_json`), so the
    rejection does not depend on which field happens to be typed as a number."""
    lab: Lab = await open_lab()
    raw = (NUMERIC_TEMPLATE[route] % constant).encode()
    response = await _send(lab, route, raw)
    problem = assert_problem(response, status=422, code="request.invalid")
    assert problem["errors"] == [{"loc": ["body"], "code": "invalid_json"}]


BAD_TITLES = {
    "overlong_121": "ECHO9X" + "x" * 115,
    "empty": "",
    "nul": "ECHO9X\u0000x",
    "newline": "ECHO9X\nx",
    "tab": "ECHO9X\tx",
    "next_line_c1": "ECHO9X\u0085x",
    "bidi_override": "ECHO9X\u202ex",
    "bidi_isolate": "ECHO9X\u2066x",
    "lone_surrogate": "ECHO9X\ud800x",
}


@pytest.mark.parametrize("route", ["create", "patch"])
@pytest.mark.parametrize("name", sorted(BAD_TITLES))
async def test_tl15_a_bad_title_is_422_without_echo(
    open_lab: OpenLab, route: str, name: str
) -> None:
    lab: Lab = await open_lab()
    body = {**body_routes(lab)[route][4], "title": BAD_TITLES[name]}
    raw = json.dumps(body, ensure_ascii=True).encode()  # \u escapes: lone surrogates survive
    await _assert_body_rejected(lab, route, raw, marker="ECHO9X")


@pytest.mark.parametrize("route", ["create", "patch"])
@pytest.mark.parametrize("value", ['{"a": 1}', '["x"]', "5", "null", "true", "1.5"])
async def test_tl15_a_non_string_title_is_422(open_lab: OpenLab, route: str, value: str) -> None:
    lab: Lab = await open_lab()
    template = {
        "create": '{"title": %s, "market": "UK"}',
        "patch": '{"title": %s, "row_version": 1}',
    }[route]
    await _assert_body_rejected(lab, route, (template % value).encode())


@pytest.mark.parametrize(
    ("route", "raw"),
    [
        ("create", b'{"market": "UK"}'),
        ("create", b'{"title": "T"}'),
        ("patch", b'{"row_version": 1}'),
        ("patch", b'{"title": "T"}'),
        ("patch", b'{"status": "deleted", "row_version": 1}'),
        ("patch", b'{"status": "ACTIVE", "row_version": 1}'),
        ("patch", b'{"status": 1, "row_version": 1}'),
        ("put", b'{"role": "viewer", "status": "active"}'),
        ("put", b'{"role": "root", "status": "active", "version": 1}'),
        ("put", b'{"role": "Owner", "status": "active", "version": 1}'),
        ("put", b'{"role": "viewer", "status": "pending", "version": 1}'),
        ("put", b'{"role": ["viewer"], "status": "active", "version": 1}'),
    ],
)
async def test_tl15_missing_or_unlisted_values_are_422(
    open_lab: OpenLab, route: str, raw: bytes
) -> None:
    lab: Lab = await open_lab()
    await _assert_body_rejected(lab, route, raw)


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    "content_type",
    [None, "text/plain", "application/x-www-form-urlencoded", "application/jsonx",
     "application/json; charset=utf-16", "multipart/form-data", "application/xml"],
)  # fmt: skip
async def test_tl15_the_wrong_media_type_is_422_even_for_a_valid_body(
    open_lab: OpenLab, route: str, content_type: str | None
) -> None:
    lab: Lab = await open_lab()
    raw = json.dumps(body_routes(lab)[route][4]).encode()
    await _assert_body_rejected(lab, route, raw, content_type)


@pytest.mark.parametrize(
    "content_type", ["application/json", "application/json; charset=utf-8", "APPLICATION/JSON"]
)
async def test_tl15_the_json_media_type_with_utf8_is_accepted(
    open_lab: OpenLab, content_type: str
) -> None:
    lab: Lab = await open_lab()
    response = await _send(
        lab, "create", json.dumps(body_routes(lab)["create"][4]).encode(), content_type
    )
    assert response.status_code == 201, response.text


@pytest.mark.parametrize(
    ("title", "ok"),
    [
        ("x" * 120, True),
        ("x" * 121, False),
        ("日本語プロジェクト", True),
        ("😀" * 120, True),  # 120 code points = 480 bytes: the limit counts characters
        ("😀" * 121, False),
        ("é" * 60, True),  # combining marks are characters too
        ("  padded  ", True),
        ('Zoë\'s <b>project</b> & "co"', True),
    ],
)
async def test_tl15_multibyte_titles_are_counted_in_characters_and_stored_exactly(
    open_lab: OpenLab, title: str, ok: bool
) -> None:
    lab: Lab = await open_lab()
    raw = json.dumps({"title": title, "market": "UK"}, ensure_ascii=False).encode("utf-8")
    if not ok:
        await _assert_body_rejected(lab, "create", raw)
        return
    response = await _send(lab, "create", raw)
    assert response.status_code == 201, response.text
    assert response.json()["title"] == title
    fetched = await lab.request(
        "GET", f"/v1/projects/{response.json()['id']}", headers=lab.bearer("alice")
    )
    assert fetched.json()["title"] == title


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("who", ["anonymous", "alice", "bob", "garbage_token"])
async def test_tl15_a_body_above_65536_bytes_is_413_before_authentication(
    open_lab: OpenLab, route: str, who: str
) -> None:
    lab: Lab = await open_lab()
    method, path, _, _, _ = body_routes(lab)[route]
    headers = {
        "anonymous": {},
        "alice": lab.bearer("alice"),
        "bob": lab.bearer("bob"),
        "garbage_token": {"Authorization": "Bearer nope"},
    }[who]
    before = lab.snapshot()
    response = await lab.request(
        method, path, headers={**headers, "Content-Type": JSON}, content=b"x" * (SIXTY_FIVE_KIB + 1)
    )
    assert_problem(response, status=413, code="request.too_large")
    assert lab.snapshot() == before


async def test_tl15_an_anonymous_streamed_oversize_body_is_401_and_is_never_read(
    open_lab: OpenLab,
) -> None:
    """D-23 / L-15: without a declared length the body is counted only when read, and it is read
    only AFTER the gates, so an anonymous caller is refused first."""
    lab: Lab = await open_lab()
    method, path, _, _, _ = body_routes(lab)["patch"]

    async def chunks() -> Any:
        for _ in range(9):
            yield b"x" * 8192

    before = lab.snapshot()
    response = await lab.client.request(
        method, path, headers={"Content-Type": JSON}, content=chunks()
    )
    assert_problem(response, status=401, code="auth.token_invalid")
    assert lab.snapshot() == before


async def test_tl15_a_streamed_body_above_the_cap_is_413_after_authentication(
    open_lab: OpenLab,
) -> None:
    """No Content-Length (chunked): the body is counted as the handler reads it (D-23, L-15)."""
    lab: Lab = await open_lab()
    method, path, _, _, _ = body_routes(lab)["patch"]

    async def chunks() -> Any:
        for _ in range(9):
            yield b"x" * 8192

    before = lab.snapshot()
    response = await lab.client.request(
        method, path, headers={**lab.bearer("alice"), "Content-Type": JSON}, content=chunks()
    )
    assert_problem(response, status=413, code="request.too_large")
    assert lab.snapshot() == before
