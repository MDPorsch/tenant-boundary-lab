"""In-process tests for the parts of the vulnerable lab that the subprocess and container tests
exercise but coverage cannot see (a subprocess is not measured), and for its defensive branches.

Written after the implementation, when coverage fell from 99% to 94%: the launcher showed 0%,
`parse_flaws` 33%, and several 422/409/404 branches of the handlers were untested. Nothing here
changes behaviour; it makes the claim "the launcher refuses X" something a unit test says directly,
and it gives the mutation tool more to kill.
"""

from __future__ import annotations

import json
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, text

from tenantlab.config import Settings
from tenantlab.lab.vulnerable import (
    ALL_FLAWS,
    Flaw,
    LabIsolationError,
    create_vulnerable_app,
    parse_flaws,
)
from tenantlab.lab.vulnerable import __main__ as launcher
from tenantlab.lab.vulnerable.app import MarkingMiddleware
from tenantlab.lab.vulnerable.guard import require_sqlite_file, require_synthetic_data
from tests.harness import AUDIENCE, BASE_URL, ISSUER, KeyPair, Lab, assert_problem
from tests.support_m3 import LAB_ENV, prepare_database

OpenVuln = Callable[..., Any]


# -------------------------------------------------------------------------- parse_flaws ----
@pytest.mark.parametrize("text_", ["all", "ALL", " all ", "All"])
def test_all_means_every_flaw(text_: str) -> None:
    assert parse_flaws(text_) == ALL_FLAWS
    assert len(ALL_FLAWS) == 4


@pytest.mark.parametrize("text_", ["none", "NONE", "", "   "])
def test_none_and_blank_mean_no_flaw(text_: str) -> None:
    assert parse_flaws(text_) == frozenset()


@pytest.mark.parametrize(
    ("text_", "expected"),
    [
        ("role_check_missing", {Flaw.ROLE_CHECK_MISSING}),
        ("ROLE_CHECK_MISSING", {Flaw.ROLE_CHECK_MISSING}),
        (
            "market_boundary_omitted, tenant_predicate_omitted",
            {Flaw.MARKET_BOUNDARY_OMITTED, Flaw.TENANT_PREDICATE_OMITTED},
        ),
        ("role_check_missing,role_check_missing", {Flaw.ROLE_CHECK_MISSING}),
    ],
)
def test_names_select_exactly_those_flaws(text_: str, expected: set[Flaw]) -> None:
    assert parse_flaws(text_) == frozenset(expected)


@pytest.mark.parametrize(
    "bad", ["role_check", "everything", "role_check_missing,", ",", "role-check-missing", "1"]
)
def test_a_typo_is_an_error_never_a_silently_different_lab(bad: str) -> None:
    with pytest.raises(ValueError, match="unknown flaw"):
        parse_flaws(bad)


# ---------------------------------------------------------------------------- launcher ----
@pytest.fixture
def lab_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, trusted_keys: KeyPair
) -> dict[str, Any]:
    url = prepare_database(tmp_path / "launcher.sqlite")
    values = {
        "LAB_MODE": "1",
        "TENANTLAB_ENV": "test",
        "TENANTLAB_DATABASE_URL": url,
        "TENANTLAB_JWT_ISSUER": ISSUER,
        "TENANTLAB_JWT_AUDIENCE": AUDIENCE,
        "TENANTLAB_JWT_PUBLIC_KEY_PEM": trusted_keys.public_pem,
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return {"url": url, "dir": _private_dir(tmp_path)}


def _private_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "sock"
    directory.mkdir()
    directory.chmod(0o700)
    return directory


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    """Replace the server start: record what the launcher WOULD have served."""
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(
        launcher, "_serve", lambda app, uds, host, port: calls.append((app, uds, host, port))
    )
    return calls


def test_the_launcher_serves_a_unix_socket_by_default(
    lab_env: dict[str, Any], served: list[tuple[Any, ...]]
) -> None:
    socket_path = lab_env["dir"] / "s"
    assert launcher.main(["--uds", str(socket_path), "--flaws", "role_check_missing"]) == 0
    assert len(served) == 1
    _, uds, host, _ = served[0]
    assert uds == socket_path
    assert host is None


def test_the_launcher_serves_a_loopback_address_when_asked(
    lab_env: dict[str, Any], served: list[tuple[Any, ...]]
) -> None:
    assert launcher.main(["--host", "127.0.0.1", "--port", "18099", "--flaws", "none"]) == 0
    _, uds, host, port = served[0]
    assert (uds, host, port) == (None, "127.0.0.1", 18099)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.5", "localhost", "example.com"])
def test_the_launcher_refuses_a_non_loopback_host_without_serving(
    lab_env: dict[str, Any],
    served: list[tuple[Any, ...]],
    host: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert launcher.main(["--host", host]) == 2
    assert "loopback" in capsys.readouterr().err.lower()
    assert served == []


def test_the_launcher_refuses_an_unknown_flaw_name(
    lab_env: dict[str, Any], served: list[tuple[Any, ...]], capsys: pytest.CaptureFixture[str]
) -> None:
    assert launcher.main(["--uds", str(lab_env["dir"] / "s"), "--flaws", "role_check"]) == 2
    assert "unknown flaw" in capsys.readouterr().err
    assert served == []


@pytest.mark.parametrize(
    "missing",
    ["LAB_MODE", "TENANTLAB_ENV", "TENANTLAB_DATABASE_URL", "TENANTLAB_JWT_PUBLIC_KEY_PEM"],
)
def test_the_launcher_refuses_when_a_required_setting_is_missing(
    lab_env: dict[str, Any],
    served: list[tuple[Any, ...]],
    monkeypatch: pytest.MonkeyPatch,
    missing: str,
) -> None:
    monkeypatch.delenv(missing)
    assert launcher.main(["--uds", str(lab_env["dir"] / "s")]) == 2
    assert served == []


def test_the_launcher_refuses_a_database_with_real_data(
    lab_env: dict[str, Any], served: list[tuple[Any, ...]], capsys: pytest.CaptureFixture[str]
) -> None:
    engine = create_engine(lab_env["url"])
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO principals (id, email, status, auth_version, created_at) VALUES "
            "('99999999999940009999999999999999', 'real@company.example', 'active', 1, "
            "'2026-01-01 00:00:00')"
        ))  # fmt: skip
    engine.dispose()
    assert launcher.main(["--uds", str(lab_env["dir"] / "s")]) == 2
    assert "synthetic" in capsys.readouterr().err
    assert served == []


@pytest.mark.parametrize("mode", [0o755, 0o770, 0o707, 0o750])
def test_the_launcher_refuses_a_socket_directory_open_to_group_or_others(
    lab_env: dict[str, Any],
    served: list[tuple[Any, ...]],
    mode: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lab_env["dir"].chmod(mode)
    assert launcher.main(["--uds", str(lab_env["dir"] / "s")]) == 2
    assert "directory" in capsys.readouterr().err
    assert served == []
    lab_env["dir"].chmod(0o700)  # ... and the same path is accepted once it is owner-only
    assert launcher.main(["--uds", str(lab_env["dir"] / "s")]) == 0


def test_the_launcher_refuses_a_missing_socket_directory(
    lab_env: dict[str, Any],
    served: list[tuple[Any, ...]],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert launcher.main(["--uds", str(tmp_path / "nope" / "s")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_the_launcher_can_create_its_own_synthetic_database(
    lab_env: dict[str, Any],
    served: list[tuple[Any, ...]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TENANTLAB_DATABASE_URL")
    fresh = tmp_path / "fresh.sqlite"
    assert (
        launcher.main(["--uds", str(lab_env["dir"] / "s"), "--init-synthetic-db", str(fresh)]) == 0
    )
    engine = create_engine(f"sqlite+pysqlite:///{fresh}")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM principals")).scalar() == 7
    engine.dispose()


def test_the_launcher_never_touches_an_existing_database_file(
    lab_env: dict[str, Any],
    served: list[tuple[Any, ...]],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    existing = tmp_path / "existing.sqlite"
    existing.write_bytes(b"do not overwrite me")
    result = launcher.main(
        ["--uds", str(lab_env["dir"] / "s"), "--init-synthetic-db", str(existing)]
    )
    assert result == 2
    assert "existing file" in capsys.readouterr().err
    assert existing.read_bytes() == b"do not overwrite me"


def test_the_launcher_says_so_when_uvicorn_is_not_installed(
    lab_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "uvicorn", None)  # makes `import uvicorn` raise ImportError
    assert launcher.main(["--uds", str(lab_env["dir"] / "s")]) == 2
    assert "uvicorn" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [[], ["--uds", "/tmp/a", "--host", "127.0.0.1"]])  # noqa: S108
def test_the_launcher_needs_exactly_one_of_uds_and_host(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        launcher.main(argv)
    assert caught.value.code == 2


def test_the_private_directory_check_reports_the_mode(tmp_path: Path) -> None:
    open_dir = tmp_path / "open"
    open_dir.mkdir()
    open_dir.chmod(0o755)
    with pytest.raises(LabIsolationError, match="0o755"):
        launcher._require_private_directory(open_dir / "s")
    assert stat.S_IMODE(open_dir.stat().st_mode) == 0o755  # the check does not change anything


# ------------------------------------------------------------------------- the guards ----
def test_an_unparsable_database_url_is_refused_without_echoing_it() -> None:
    with pytest.raises(LabIsolationError) as caught:
        require_sqlite_file("this is :: not a url with hunter2")
    assert "hunter2" not in str(caught.value)


def test_an_unmigrated_database_cannot_be_verified_so_it_is_refused(tmp_path: Path) -> None:
    from tenantlab.db.engine import make_engine  # noqa: PLC0415

    engine = make_engine(f"sqlite+pysqlite:///{tmp_path / 'bare.sqlite'}")
    with pytest.raises(LabIsolationError, match="cannot verify"):
        require_synthetic_data(engine)
    engine.dispose()


# ------------------------------------------------------------------------------ the app ----
async def test_the_marking_layer_leaves_non_http_traffic_alone() -> None:
    seen: list[str] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    async def never(*_: Any) -> None:
        raise AssertionError("not used")

    await MarkingMiddleware(inner, "x")({"type": "lifespan"}, never, never)
    assert seen == ["lifespan"]


async def test_the_database_connection_is_released_when_the_app_shuts_down(
    tmp_path: Path, trusted_keys: KeyPair
) -> None:
    url = prepare_database(tmp_path / "life.sqlite")
    settings = Settings(
        database_url=url, jwt_issuer=ISSUER, jwt_audience=AUDIENCE,  # type: ignore[arg-type]
        jwt_public_key_pem=trusted_keys.public_pem,
    )  # fmt: skip
    app = create_vulnerable_app(settings, flaws=frozenset(), environ=LAB_ENV)
    async with app.router.lifespan_context(app):
        pass  # start-up and shut-down must both run without error


async def test_framework_errors_are_generic_problems_that_never_echo_input(
    tmp_path: Path, trusted_keys: KeyPair
) -> None:
    url = prepare_database(tmp_path / "errs.sqlite")
    settings = Settings(
        database_url=url, jwt_issuer=ISSUER, jwt_audience=AUDIENCE,  # type: ignore[arg-type]
        jwt_public_key_pem=trusted_keys.public_pem,
    )  # fmt: skip
    app = create_vulnerable_app(settings, flaws=frozenset(), environ=LAB_ENV)

    @app.get("/__probe/{number}")
    def probe(number: int) -> dict[str, int]:
        return {"number": number}

    @app.get("/__teapot")
    def teapot() -> None:
        raise HTTPException(status_code=418, detail="free text that must not leak")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE_URL
    ) as client:
        invalid = await client.get("/__probe/echo-me-please")
        stray = await client.get("/__teapot")
    assert_problem(invalid, status=422, code="request.invalid")
    assert "echo-me-please" not in invalid.text
    assert_problem(stray, status=500, code="internal.error")
    assert "free text" not in stray.text


# -------------------------------------------------------------- the handlers' branches ----
async def _patch(
    lab: Lab, body: Any, *, raw: bytes | None = None, who: str = "alice"
) -> httpx.Response:
    path = f"/v1/projects/{lab.fx.project('PA1').id}"
    if raw is not None:
        return await lab.request(
            "PATCH",
            path,
            headers={**lab.bearer(who), "Content-Type": "application/json"},
            content=raw,
        )
    return await lab.request("PATCH", path, headers=lab.bearer(who), json_body=body)


@pytest.mark.parametrize(
    "body",
    [
        {"title": 5, "row_version": 1},
        {"title": "", "row_version": 1},
        {"title": "x" * 121, "row_version": 1},
        {"status": "deleted", "row_version": 1},
        {"title": "ok", "row_version": "1"},
        {"title": "ok", "row_version": True},
        {"title": "ok", "row_version": 0},
        {"title": "ok", "row_version": 2**31},
        {"title": "ok"},
        {"row_version": 1},
        {"title": "ok", "row_version": 1, "tenant_id": "x"},
        ["not", "an", "object"],
    ],
)
async def test_an_invalid_patch_body_is_422_and_changes_nothing(
    open_vuln: OpenVuln, body: Any
) -> None:
    lab: Lab = await open_vuln(())
    before = lab.snapshot()
    assert_problem(await _patch(lab, body), status=422, code="request.invalid")
    assert lab.snapshot().business == before.business


@pytest.mark.parametrize("raw", [b"", b"{", b"\xff\xfe", b"[" * 5000])
async def test_an_unparsable_patch_body_is_422(open_vuln: OpenVuln, raw: bytes) -> None:
    lab: Lab = await open_vuln(())
    assert_problem(await _patch(lab, None, raw=raw), status=422, code="request.invalid")


async def test_a_stale_patch_is_409_and_a_title_or_status_alone_is_enough(
    open_vuln: OpenVuln,
) -> None:
    lab: Lab = await open_vuln(())
    only_status = await _patch(lab, {"status": "archived", "row_version": 1})
    assert only_status.status_code == 200, only_status.text
    assert only_status.json()["status"] == "archived"
    assert only_status.json()["title"] == lab.fx.project("PA1").title  # untouched
    only_title = await _patch(lab, {"title": "renamed", "row_version": 2})
    assert only_title.status_code == 200, only_title.text
    assert only_title.json()["status"] == "archived"  # untouched
    stale = await _patch(lab, {"title": "late", "row_version": 1})
    assert_problem(stale, status=409, code="conflict.stale_revision")


async def test_a_token_for_a_principal_that_does_not_exist_is_a_plain_401(
    open_vuln: OpenVuln,
) -> None:
    lab: Lab = await open_vuln(())
    ghost = lab.mint.mint(lab.fx.never_seeded["principal"])
    response = await lab.request(
        "GET",
        f"/v1/tenants/{lab.fx.tenant('A').id}/me",
        headers={"Authorization": f"Bearer {ghost}"},
    )
    assert_problem(response, status=401, code="auth.token_invalid")
    assert response.headers["www-authenticate"] == "Bearer"


async def test_a_malformed_path_id_is_422(open_vuln: OpenVuln) -> None:
    lab: Lab = await open_vuln(())
    response = await lab.request("GET", "/v1/projects/not-a-uuid", headers=lab.bearer("alice"))
    assert_problem(response, status=422, code="request.invalid")
    assert json.loads(response.text)["errors"] == []  # the simplified detail (D-42)


async def test_an_invoice_whose_tenant_differs_from_its_projects_is_not_served(
    open_vuln: OpenVuln,
) -> None:
    lab: Lab = await open_vuln(())
    invoice = f"/v1/invoices/{lab.fx.invoice('IA1').id}"
    assert (await lab.request("GET", invoice, headers=lab.bearer("alice"))).status_code == 200
    lab.sql(
        "UPDATE invoices SET tenant_id = (SELECT id FROM tenants WHERE slug = 'tenant-b') "
        "WHERE amount_minor = 125000"
    )
    assert_problem(
        await lab.request("GET", invoice, headers=lab.bearer("alice")),
        status=404,
        code="resource.not_found",
    )
