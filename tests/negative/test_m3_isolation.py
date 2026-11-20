"""TL-16 (milestone M3): the vulnerable lab cannot start, be reached or ship outside the lab.

STATUS: written RED-FIRST. Expected outcomes: docs/vulnerable-lab.md s1 (eight layers) and
decisions D-41..D-47. Each layer is tested on its own; a guard that is never shown to REFUSE
something would pass vacuously, so every refusal sits next to an acceptance.

The container layer (7) is in tests/docker/ and needs a Docker daemon.
"""

from __future__ import annotations

import ast
import json
import logging
import subprocess
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from sqlalchemy import create_engine, text

import tenantlab
from tests.harness import AUDIENCE, BASE_URL, ISSUER, KeyPair, assert_problem
from tests.support_m3 import LAB_ENV, NOT_IMPLEMENTED, prepare_database

pytestmark = pytest.mark.milestone("M3")

OpenVuln = Callable[..., Any]
REPO = Path(__file__).resolve().parents[2]
PACKAGE = Path(next(iter(tenantlab.__path__)))
VULN_DIR = PACKAGE / "lab" / "vulnerable"


def _create(tmp_path: Path, trusted: KeyPair, **kwargs: Any) -> Any:
    """Call create_vulnerable_app with a freshly seeded database unless told otherwise."""
    try:
        from tenantlab.lab.vulnerable import create_vulnerable_app  # noqa: PLC0415

        from tenantlab.config import Settings  # noqa: PLC0415
    except ImportError as exc:
        pytest.fail(NOT_IMPLEMENTED.format(exc=exc), pytrace=False)
    url = kwargs.pop("database_url", None) or prepare_database(tmp_path / "guard.sqlite")
    settings = Settings(
        database_url=url,
        jwt_issuer=ISSUER,
        jwt_audience=AUDIENCE,
        jwt_public_key_pem=trusted.public_pem,
    )
    kwargs.setdefault("environ", LAB_ENV)
    kwargs.setdefault("flaws", frozenset())
    return create_vulnerable_app(settings, **kwargs)


def _isolation_error() -> type[Exception]:
    try:
        from tenantlab.lab.vulnerable import LabIsolationError  # noqa: PLC0415
    except ImportError as exc:
        pytest.fail(NOT_IMPLEMENTED.format(exc=exc), pytrace=False)
    return LabIsolationError  # type: ignore[no-any-return]


# ------------------------------------------------ layer 4: the start-up guard (hard failure) ----
@pytest.mark.parametrize(
    "environ",
    [
        {},
        {"TENANTLAB_ENV": "lab"},
        {"LAB_MODE": "", "TENANTLAB_ENV": "lab"},
        {"LAB_MODE": "0", "TENANTLAB_ENV": "lab"},
        {"LAB_MODE": "true", "TENANTLAB_ENV": "lab"},
        {"LAB_MODE": "yes", "TENANTLAB_ENV": "lab"},
        {"LAB_MODE": "11", "TENANTLAB_ENV": "lab"},
        {"LAB_MODE": " 1", "TENANTLAB_ENV": "lab"},
        {"LAB_MODE": "1 ", "TENANTLAB_ENV": "lab"},
    ],
    ids=[
        "nothing",
        "no_lab_mode",
        "empty",
        "zero",
        "true",
        "yes",
        "eleven",
        "leading_space",
        "trailing_space",
    ],
)
def test_tl16_refuses_to_start_unless_lab_mode_is_exactly_1(
    tmp_path: Path, trusted_keys: KeyPair, environ: dict[str, str]
) -> None:
    with pytest.raises(_isolation_error(), match="LAB_MODE"):
        _create(tmp_path, trusted_keys, environ=environ)


@pytest.mark.parametrize(
    "tenantlab_env",
    [
        None,
        "",
        "production",
        "prod",
        "PRODUCTION",
        "staging",
        "development",
        "dev",
        "LAB",
        "lab ",
        "labs",
    ],
)
def test_tl16_refuses_to_start_outside_the_lab_or_test_environment(
    tmp_path: Path, trusted_keys: KeyPair, tenantlab_env: str | None
) -> None:
    environ = {"LAB_MODE": "1"} | (
        {} if tenantlab_env is None else {"TENANTLAB_ENV": tenantlab_env}
    )
    with pytest.raises(_isolation_error(), match="TENANTLAB_ENV"):
        _create(tmp_path, trusted_keys, environ=environ)


@pytest.mark.parametrize("tenantlab_env", ["lab", "test"])
def test_tl16_starts_in_exactly_the_lab_and_test_environments(
    tmp_path: Path, trusted_keys: KeyPair, tenantlab_env: str
) -> None:
    """The acceptance that gives the refusals above their meaning."""
    app = _create(tmp_path, trusted_keys, environ={"LAB_MODE": "1", "TENANTLAB_ENV": tenantlab_env})
    assert app is not None


@pytest.mark.parametrize(
    "host",
    ["0.0.0.0", "::", "192.168.1.10", "10.0.0.5", "172.16.0.1", "8.8.8.8", "169.254.169.254",
     "localhost", "example.com", "", "127.0.0.1:8000", "[::1]", "0", "::ffff:10.0.0.5"],
)  # fmt: skip
def test_tl16_refuses_a_bind_address_that_is_not_a_literal_loopback_ip(
    tmp_path: Path, trusted_keys: KeyPair, host: str
) -> None:
    with pytest.raises(_isolation_error(), match="loopback"):
        _create(tmp_path, trusted_keys, bind_host=host)


@pytest.mark.parametrize("host", [None, "127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"])
def test_tl16_accepts_a_loopback_bind_address_or_none_for_a_socket(
    tmp_path: Path, trusted_keys: KeyPair, host: str | None
) -> None:
    assert _create(tmp_path, trusted_keys, bind_host=host) is not None


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://lab:pw@db.internal/lab",
        "postgresql://localhost/lab",
        "mysql+pymysql://root@10.0.0.2/lab",
        "sqlite://",
        "sqlite+pysqlite:///:memory:",
    ],
)
def test_tl16_refuses_a_database_that_is_not_a_sqlite_file(
    tmp_path: Path, trusted_keys: KeyPair, url: str
) -> None:
    with pytest.raises(_isolation_error(), match="SQLite"):
        _create(tmp_path, trusted_keys, database_url=url)


def test_tl16_refuses_a_database_holding_a_principal_that_is_not_synthetic(
    tmp_path: Path, trusted_keys: KeyPair
) -> None:
    """D-44: a broken app must not be pointed at real data. One real-looking e-mail is enough."""
    url = prepare_database(tmp_path / "mixed.sqlite")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO principals (id, email, status, auth_version, created_at) VALUES "
                "('99999999999940009999999999999999', 'someone@company.example', 'active', 1, "
                "'2026-01-01 00:00:00')"
            )
        )
    engine.dispose()
    with pytest.raises(_isolation_error(), match="synthetic"):
        _create(tmp_path, trusted_keys, database_url=url)


def test_tl16_refuses_an_empty_database_rather_than_passing_the_check_vacuously(
    tmp_path: Path, trusted_keys: KeyPair
) -> None:
    from tenantlab.db.migrate import upgrade_to_head  # noqa: PLC0415

    url = f"sqlite+pysqlite:///{tmp_path / 'empty.sqlite'}"
    upgrade_to_head(url)  # migrated, not seeded
    with pytest.raises(_isolation_error(), match="synthetic"):
        _create(tmp_path, trusted_keys, database_url=url)


def test_tl16_a_refusal_is_a_hard_failure_never_a_fallback_to_the_patched_app(
    tmp_path: Path, trusted_keys: KeyPair
) -> None:
    error = _isolation_error()
    result: Any = None
    with pytest.raises(error):
        result = _create(
            tmp_path, trusted_keys, environ={"LAB_MODE": "1", "TENANTLAB_ENV": "production"}
        )
    assert result is None
    assert issubclass(error, RuntimeError)


# ------------------------------------------------- layer 5: the request guard (any start-up) ----
def _scope(client: tuple[str, int] | None, server: tuple[str, int] | None) -> dict[str, Any]:
    return {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET",
        "scheme": "http", "path": "/v1/tenants/x/me", "raw_path": b"/v1/tenants/x/me",
        "query_string": b"", "headers": [], "client": client, "server": server,
    }  # fmt: skip


async def _status_for(
    app: Any, client: tuple[str, int] | None, server: tuple[str, int] | None
) -> int:
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(_scope(client, server), receive, send)
    return int(next(m["status"] for m in sent if m["type"] == "http.response.start"))


@pytest.mark.parametrize(
    "client",
    [("203.0.113.9", 4000), ("10.0.0.5", 4000), ("192.168.1.20", 1), ("8.8.8.8", 1),
     ("::ffff:203.0.113.9", 1), ("2001:db8::1", 1), ("fe80::1", 1)],
)  # fmt: skip
async def test_tl16_a_request_from_a_non_loopback_peer_is_refused_whatever_the_bind(
    tmp_path: Path, trusted_keys: KeyPair, client: tuple[str, int]
) -> None:
    """Even a process that was (mis)started on 0.0.0.0 refuses every non-loopback peer."""
    app = _create(tmp_path, trusted_keys)
    assert await _status_for(app, client, ("127.0.0.1", 8000)) == 403


@pytest.mark.parametrize(
    "client", [("127.0.0.1", 4000), ("127.0.0.2", 1), ("::1", 1), ("::ffff:127.0.0.1", 1), None]
)
async def test_tl16_loopback_and_unix_socket_peers_are_served(
    tmp_path: Path, trusted_keys: KeyPair, client: tuple[str, int] | None
) -> None:
    app = _create(tmp_path, trusted_keys)
    assert await _status_for(app, client, ("127.0.0.1", 8000)) == 401  # reached the app: no token


@pytest.mark.parametrize("server", [("192.168.1.5", 8000), ("10.1.2.3", 80), ("2001:db8::5", 8000)])
async def test_tl16_a_request_that_arrived_on_a_non_loopback_local_address_is_refused(
    tmp_path: Path, trusted_keys: KeyPair, server: tuple[str, int]
) -> None:
    app = _create(tmp_path, trusted_keys)
    assert await _status_for(app, ("127.0.0.1", 4000), server) == 403


async def test_tl16_a_refused_request_is_a_problem_and_touches_nothing(
    tmp_path: Path, trusted_keys: KeyPair, attacker_keys: KeyPair
) -> None:
    from tests.harness import TokenMint  # noqa: PLC0415

    app = _create(tmp_path, trusted_keys)
    token = TokenMint(trusted_keys, attacker_keys).mint("10000000-0000-4000-8000-000000000001")
    transport = httpx.ASGITransport(app=app, client=("203.0.113.9", 4000))
    async with httpx.AsyncClient(transport=transport, base_url=BASE_URL) as client:
        response = await client.get(
            "/v1/tenants/20000000-0000-4000-8000-000000000001/me",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert_problem(response, status=403, code="authz.forbidden")
    assert response.headers["x-tenantlab-vulnerable"]  # even the refusal is marked


# ------------------------------------------------------------------ layer 8: visible marking ----
async def test_tl16_every_response_is_marked_and_a_banner_is_logged(
    open_vuln: OpenVuln, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="tenantlab"):
        lab = await open_vuln(["ROLE_CHECK_MISSING"])
    assert any("DELIBERATELY VULNERABLE" in r.getMessage() for r in caplog.records)
    assert any("ROLE_CHECK_MISSING" in r.getMessage() for r in caplog.records)
    tenant_a = lab.fx.tenant("A").id
    for headers, path in (
        (lab.bearer("alice"), f"/v1/tenants/{tenant_a}/me"),  # 200
        ({}, f"/v1/tenants/{tenant_a}/me"),  # 401
        (lab.bearer("alice"), "/v1/nowhere"),  # 404
        (lab.bearer("bob"), f"/v1/tenants/{lab.fx.tenant('B').id}/me"),  # 404 (member of A only)
    ):
        response = await lab.request("GET", path, headers=headers)
        assert response.headers["x-tenantlab-vulnerable"].startswith("deliberately-broken-lab")


# ----------------------------------------------------------------- layer 6: the launcher ----
def _launch(args: list[str], env_extra: dict[str, str]) -> subprocess.CompletedProcess[str]:
    import os  # noqa: PLC0415

    env = {k: v for k, v in os.environ.items() if k not in ("LAB_MODE", "TENANTLAB_ENV")}
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "tenantlab.lab.vulnerable", *args],
        env={**env, **env_extra}, capture_output=True, text=True, timeout=30, check=False,
    )  # fmt: skip


@pytest.mark.parametrize(
    "host", ["0.0.0.0", "::", "192.168.1.5", "10.0.0.1", "localhost", "example.com", "8.8.8.8"]
)
def test_tl16_the_launcher_refuses_any_host_that_is_not_a_literal_loopback_ip(host: str) -> None:
    result = _launch(["--host", host, "--port", "8099"], LAB_ENV)
    assert result.returncode == 2, result.stderr[-300:]
    assert "loopback" in result.stderr.lower()


@pytest.mark.parametrize(
    "env_extra",
    [
        {},
        {"LAB_MODE": "1"},
        {"LAB_MODE": "1", "TENANTLAB_ENV": "production"},
        {"TENANTLAB_ENV": "lab"},
    ],
    ids=["nothing", "no_env", "production", "no_lab_mode"],
)
def test_tl16_the_launcher_refuses_to_run_outside_the_lab_environment(
    env_extra: dict[str, str],
) -> None:
    result = _launch(["--uds", "/tmp/never-created.sock"], env_extra)  # noqa: S108
    assert result.returncode == 2, result.stderr[-300:]
    assert "LAB_MODE" in result.stderr or "TENANTLAB_ENV" in result.stderr


# ------------------------------------------------ layers 1-3: the code never reaches the app ----
def _modules_after(statement: str) -> list[str]:
    """Run `statement` in a clean interpreter; return the vulnerable modules that got imported."""
    report = (
        "print(json.dumps(sorted(m for m in sys.modules "
        "if m.startswith('tenantlab.lab.vulnerable'))))"
    )
    code = f"import sys, json\n{statement}\n{report}"
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stderr[-500:]
    return list(json.loads(result.stdout.strip().splitlines()[-1]))


def test_tl16_importing_and_building_the_default_app_never_imports_the_vulnerable_lab() -> None:
    """In a CLEAN interpreter (-I): the whole default stack, then the default app is created."""
    statement = (
        "import tenantlab.api.app, tenantlab.api.handlers, tenantlab.api.gates, "
        "tenantlab.lab.patched.service, tenantlab.oracle.matrix, tenantlab.auth.tokens, "
        "tenantlab.db.models, tenantlab.config\n"
        "from cryptography.hazmat.primitives import serialization\n"
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n"
        "pem = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM, "
        "serialization.PublicFormat.SubjectPublicKeyInfo).decode()\n"
        "import tempfile, os\n"
        "d = tempfile.mkdtemp()\n"
        "url = 'sqlite+pysqlite:///' + os.path.join(d, 'x.sqlite')\n"
        "settings = tenantlab.config.Settings(database_url=url, jwt_issuer='i', "
        "jwt_audience='a', jwt_public_key_pem=pem)\n"
        "tenantlab.api.app.create_app(settings)\n"
    )
    assert _modules_after(statement) == []


def test_tl16_the_probe_can_see_a_leak_when_there_is_one() -> None:
    """Anti-vacuity: importing the vulnerable package DOES make it appear in sys.modules."""
    assert VULN_DIR.joinpath("__init__.py").is_file(), "the vulnerable package does not exist yet"
    assert "tenantlab.lab.vulnerable" in _modules_after("import tenantlab.lab.vulnerable")


def _imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise AssertionError(f"{path}: relative import hides the dependency graph")
            if node.module:
                found.add(node.module)
                found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def test_tl16_no_module_outside_the_vulnerable_package_imports_it() -> None:
    assert VULN_DIR.is_dir(), "the vulnerable package does not exist yet"
    offenders = []
    for module in sorted(PACKAGE.rglob("*.py")):
        if VULN_DIR in module.parents:
            continue
        if any(i.startswith("tenantlab.lab.vulnerable") for i in _imports(module)):
            offenders.append(str(module.relative_to(PACKAGE)))
    assert not offenders, f"imported from outside the lab: {offenders}"


ALLOWED_TENANTLAB_IMPORTS = (
    "tenantlab.schemas", "tenantlab.db", "tenantlab.auth", "tenantlab.ids", "tenantlab.config",
    "tenantlab.api.middleware", "tenantlab.api.problems", "tenantlab.lab.vulnerable",
)  # fmt: skip
FORBIDDEN_LIBRARIES = (
    "socket", "ssl", "http.client", "urllib.request", "urllib3", "requests", "httpx", "aiohttp",
    "websockets", "smtplib", "ftplib", "telnetlib", "subprocess", "ctypes", "multiprocessing",
)  # fmt: skip


def _violations(files: list[Path]) -> list[str]:
    bad = []
    for module in files:
        for imported in _imports(module):
            if imported.startswith("tenantlab.") and not imported.startswith(
                ALLOWED_TENANTLAB_IMPORTS
            ):
                bad.append(f"{module.name}: {imported} (not on the allow-list)")
            root = imported.split(".")[0]
            if imported in FORBIDDEN_LIBRARIES or root in FORBIDDEN_LIBRARIES:
                bad.append(f"{module.name}: {imported} (a network or process library)")
    return bad


def test_tl16_the_vulnerable_package_imports_only_the_allow_list_and_no_network_client() -> None:
    files = sorted(VULN_DIR.rglob("*.py"))
    assert files, "the vulnerable package does not exist yet"
    assert not _violations(files)


def test_tl16_the_import_scan_detects_a_violation(tmp_path: Path) -> None:
    """Guard the guard."""
    for source, expected in (
        ("from tenantlab.api.gates import run_gates\n", "allow-list"),
        ("import tenantlab.lab.patched.service\n", "allow-list"),
        ("from tenantlab.oracle.matrix import load_capabilities\n", "allow-list"),
        ("import socket\n", "network"),
        ("import httpx\n", "network"),
        ("from urllib.request import urlopen\n", "network"),
        ("import subprocess\n", "network"),
    ):
        bad = tmp_path / "bad.py"
        bad.write_text(source)
        assert any(expected in v for v in _violations([bad])), source


def test_tl16_the_built_wheel_does_not_contain_the_vulnerable_lab(tmp_path: Path) -> None:
    """D-43. Anti-vacuity: the package must exist in the SOURCE tree, and the wheel must still
    contain its patched sibling, so 'absent' cannot mean 'not built'."""
    assert VULN_DIR.joinpath("__init__.py").is_file(), "the vulnerable package does not exist yet"
    build = subprocess.run(  # noqa: S603
        ["uv", "build", "--wheel", "--out-dir", str(tmp_path), str(REPO)],  # noqa: S607
        capture_output=True, text=True, timeout=300, check=False,
    )  # fmt: skip
    assert build.returncode == 0, build.stderr[-500:]
    wheel = next(tmp_path.glob("*.whl"))
    names = zipfile.ZipFile(wheel).namelist()
    assert "tenantlab/lab/patched/service.py" in names
    assert [n for n in names if "lab/vulnerable" in n] == []


# --------------------------------------------------- layer 7 (static part): the compose file ----
def _compose() -> dict[str, Any]:
    path = REPO / "deploy" / "compose.vulnerable-lab.yaml"
    assert path.is_file(), "deploy/compose.vulnerable-lab.yaml does not exist yet"
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_tl16_the_compose_file_removes_the_network_and_every_privilege() -> None:
    compose = _compose()
    assert list(compose["services"]) == ["vulnerable-lab"]
    service = compose["services"]["vulnerable-lab"]
    assert service["network_mode"] == "none"
    assert "ports" not in service
    assert "expose" not in service
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert not service.get("cap_add")
    assert "no-new-privileges:true" in service["security_opt"]
    assert str(service["user"]).split(":")[0] not in ("0", "root", "")
    assert not service.get("privileged")
    assert service.get("tmpfs"), "state must live on tmpfs, not a host mount"
    assert "volumes" not in service, "no host path may be mounted into the lab"
    assert "networks" not in service
    assert "networks" not in compose
    environment = service.get("environment", {})
    flat = json.dumps(environment).lower()
    for word in ("private", "secret", "password"):
        assert word not in flat


def test_tl16_the_dockerfile_runs_as_a_non_root_user_and_exposes_nothing() -> None:
    path = REPO / "deploy" / "Dockerfile.vulnerable-lab"
    assert path.is_file(), "deploy/Dockerfile.vulnerable-lab does not exist yet"
    lines = [
        ln.strip() for ln in path.read_text().splitlines() if ln.strip() and not ln.startswith("#")
    ]
    users = [ln.split(None, 1)[1] for ln in lines if ln.upper().startswith("USER ")]
    assert users, "the image must switch to a non-root USER"
    assert users[-1].split(":")[0] not in ("0", "root"), users
    assert not [ln for ln in lines if ln.upper().startswith("EXPOSE")]
    assert not [ln for ln in lines if ln.upper().startswith("ADD ")], "ADD can fetch URLs"
    froms = [ln.split()[1] for ln in lines if ln.upper().startswith("FROM ")]
    assert froms
    for image in froms:
        assert ":" in image, f"unpinned base image {image}"
        assert not image.endswith(":latest"), f"unpinned base image {image}"
