"""Helpers for the M3 tests: build the vulnerable lab in process, run it as an isolated process
over a Unix socket, and the exploits that demonstrate each controlled flaw.

Independence rule (as elsewhere): the exploits judge by HTTP outcome and by sentinel strings from
the fixtures, never by calling application code. The only application imports are inside
`build_vulnerable_lab`, where a missing module fails the calling test explicitly (red phase).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from pathlib import Path
from typing import Any, Final

import httpx
import pytest
from sqlalchemy import create_engine

from tests.harness import (
    AUDIENCE,
    BASE_URL,
    ISSUER,
    KeyPair,
    Lab,
    TokenMint,
    generate_keypair,
)

LAB_ENV: Final = {"LAB_MODE": "1", "TENANTLAB_ENV": "test"}
ALL_FLAWS: Final = (
    "TENANT_PREDICATE_OMITTED",
    "ROLE_CHECK_MISSING",
    "PRIVATE_PROPERTY_SERIALIZED",
    "MARKET_BOUNDARY_OMITTED",
    "WRITE_BEFORE_AUTHORIZATION",
)
NOT_IMPLEMENTED: Final = (
    "NOT IMPLEMENTED (milestone M3): the vulnerable lab is missing: {exc}. This red test "
    "specifies behaviour the next step must provide; see docs/vulnerable-lab.md."
)


def _settings(url: str, trusted: KeyPair) -> Any:
    from tenantlab.config import Settings  # noqa: PLC0415

    return Settings(
        database_url=url,  # type: ignore[arg-type]
        jwt_issuer=ISSUER,
        jwt_audience=AUDIENCE,
        jwt_public_key_pem=trusted.public_pem,
    )


def prepare_database(db_file: Path) -> str:
    from tenantlab.db.migrate import upgrade_to_head  # noqa: PLC0415
    from tenantlab.db.seed import seed_fixtures  # noqa: PLC0415

    url = f"sqlite+pysqlite:///{db_file}"
    upgrade_to_head(url)
    seed_fixtures(url)
    return url


async def build_vulnerable_lab(
    db_file: Path,
    trusted: KeyPair,
    attacker: KeyPair,
    flaws: Iterable[str],
    *,
    environ: Mapping[str, str] | None = None,
    bind_host: str | None = None,
) -> Lab:
    """A migrated, seeded vulnerable app served in process. Fails the calling test explicitly
    while it does not exist."""
    try:
        from tenantlab.lab.fixtures.loader import load_fixtures  # noqa: PLC0415
        from tenantlab.lab.vulnerable import Flaw, create_vulnerable_app  # noqa: PLC0415
    except ImportError as exc:
        pytest.fail(NOT_IMPLEMENTED.format(exc=exc), pytrace=False)
    url = prepare_database(db_file)
    app = create_vulnerable_app(
        _settings(url, trusted),
        flaws=frozenset(Flaw[name] for name in flaws),
        environ=LAB_ENV if environ is None else environ,
        bind_host=bind_host,
    )
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)
    return Lab(client, create_engine(url), TokenMint(trusted, attacker), load_fixtures())


# --------------------------------------------------------------- an isolated process ----
class IsolatedLab:
    """The vulnerable lab as a SEPARATE process that listens on a Unix socket only (no TCP)."""

    def __init__(self, tmp_path: Path, trusted: KeyPair, flaws: Iterable[str]) -> None:
        # macOS limits a Unix socket path to ~104 characters: pytest's tmp_path is longer
        self.socket_dir = Path(tempfile.mkdtemp(prefix="tl-", dir="/tmp"))
        self.socket = self.socket_dir / "s"
        self.db_file = tmp_path / "lab.sqlite"
        self.trusted = trusted
        self.flaws = ",".join(flaws) or "none"
        self.process: subprocess.Popen[str] | None = None
        self.stderr_path = tmp_path / "lab.stderr"

    def start(self) -> None:
        url = prepare_database(self.db_file)
        env = {
            **os.environ,
            **LAB_ENV,
            "TENANTLAB_DATABASE_URL": url,
            "TENANTLAB_JWT_ISSUER": ISSUER,
            "TENANTLAB_JWT_AUDIENCE": AUDIENCE,
            "TENANTLAB_JWT_PUBLIC_KEY_PEM": self.trusted.public_pem,
        }
        with self.stderr_path.open("w") as stderr:
            self.process = subprocess.Popen(  # noqa: S603
                [sys.executable, "-m", "tenantlab.lab.vulnerable", "--uds", str(self.socket),
                 "--flaws", self.flaws],
                env=env, stdout=subprocess.DEVNULL, stderr=stderr, text=True,
            )  # fmt: skip
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            if self.socket.exists():
                return
            time.sleep(0.1)
        pytest.fail(f"the isolated lab did not start: {self.stderr_text()[-800:]}", pytrace=False)

    def stderr_text(self) -> str:
        return self.stderr_path.read_text() if self.stderr_path.exists() else ""

    def lab(self, attacker: KeyPair | None = None) -> Lab:
        """A `Lab` whose HTTP client talks to the process over the socket."""
        from tenantlab.lab.fixtures.loader import load_fixtures  # noqa: PLC0415

        transport = httpx.AsyncHTTPTransport(uds=str(self.socket))
        client = httpx.AsyncClient(transport=transport, base_url=BASE_URL)
        engine = create_engine(f"sqlite+pysqlite:///{self.db_file}")
        mint = TokenMint(self.trusted, attacker or generate_keypair())
        return Lab(client, engine, mint, load_fixtures())

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        shutil.rmtree(self.socket_dir, ignore_errors=True)


# ------------------------------------------------------------------------- the exploits ----
Exploit = Callable[[Lab], Awaitable[bool]]


async def _get(lab: Lab, who: str, path: str) -> httpx.Response:
    return await lab.request("GET", path, headers=lab.bearer(who))


async def _patch(lab: Lab, who: str, project: str, title: str) -> httpx.Response:
    return await lab.request(
        "PATCH",
        f"/v1/projects/{lab.fx.project(project).id}",
        headers=lab.bearer(who),
        json_body={"title": title, "row_version": 1},
    )


async def e1_cross_tenant_read(lab: Lab) -> bool:
    r = await _get(lab, "bob", f"/v1/projects/{lab.fx.project('PB1').id}")
    return r.status_code == 200 and "SENTINEL-TENANT-B" in r.text


async def e1_cross_tenant_list(lab: Lab) -> bool:
    r = await _get(lab, "bob", f"/v1/tenants/{lab.fx.tenant('B').id}/projects")
    return r.status_code == 200 and lab.fx.project("PB1").id in r.text


async def e1_cross_tenant_invoice(lab: Lab) -> bool:
    r = await _get(lab, "bob", f"/v1/invoices/{lab.fx.invoice('IB1').id}")
    return r.status_code == 200 and "98000" in r.text


async def e1_cross_tenant_write(lab: Lab) -> bool:
    """alice owns A and is NOT a member of B: only an unscoped membership lookup lets her write
    B's project (dave, a viewer of B, would also be let in by a missing role check)."""
    r = await _patch(lab, "alice", "PB1", "pwned-by-alice")
    return r.status_code == 200 and r.json().get("title") == "pwned-by-alice"


async def e2_viewer_writes(lab: Lab) -> bool:
    r = await _patch(lab, "bob", "PA1", "pwned-by-bob")
    return r.status_code == 200 and r.json().get("title") == "pwned-by-bob"


async def e2_viewer_reads_private_contacts(lab: Lab) -> bool:
    r = await _get(lab, "bob", f"/v1/projects/{lab.fx.project('PA1').id}/contacts")
    return r.status_code == 200 and lab.fx.private_sentinel in r.text


async def e3_private_in_general_json(lab: Lab) -> bool:
    r = await _get(lab, "bob", f"/v1/projects/{lab.fx.project('PA1').id}")
    return r.status_code == 200 and lab.fx.private_sentinel in r.text


async def e4_hidden_project(lab: Lab) -> bool:
    r = await _get(lab, "alice", f"/v1/projects/{lab.fx.project('PA2').id}")
    return r.status_code == 200 and "US pilot" in r.text


async def e4_hidden_invoice(lab: Lab) -> bool:
    r = await _get(lab, "alice", f"/v1/invoices/{lab.fx.invoice('IA2').id}")
    return r.status_code == 200 and "USD" in r.text


async def e4_hidden_contacts(lab: Lab) -> bool:
    r = await _get(lab, "alice", f"/v1/projects/{lab.fx.project('PA2').id}/contacts")
    return r.status_code == 200 and "SENTINEL-PRIV-EMAIL-CA2" in r.text


async def e4_hidden_in_list(lab: Lab) -> bool:
    r = await _get(lab, "alice", f"/v1/tenants/{lab.fx.tenant('A').id}/projects")
    return r.status_code == 200 and r.json().get("total") == 2


async def e5_refused_write_persists(lab: Lab) -> bool:
    """gina owns the SUSPENDED tenant C: every correct app refuses her write (403), whatever other
    control is missing. If the row changed anyway, the write ran BEFORE the authorization check.
    Judged by a raw-SQL snapshot, never by the response, which is a perfectly normal 403."""
    before = lab.snapshot()
    response = await _patch(lab, "gina", "PC1", "written-then-refused")
    return response.status_code == 403 and lab.snapshot().business != before.business


EXPLOITS: Final[dict[str, tuple[str, Exploit]]] = {
    "e1_cross_tenant_read": ("TENANT_PREDICATE_OMITTED", e1_cross_tenant_read),
    "e1_cross_tenant_list": ("TENANT_PREDICATE_OMITTED", e1_cross_tenant_list),
    "e1_cross_tenant_invoice": ("TENANT_PREDICATE_OMITTED", e1_cross_tenant_invoice),
    "e1_cross_tenant_write": ("TENANT_PREDICATE_OMITTED", e1_cross_tenant_write),
    "e2_viewer_writes": ("ROLE_CHECK_MISSING", e2_viewer_writes),
    "e2_viewer_reads_private_contacts": ("ROLE_CHECK_MISSING", e2_viewer_reads_private_contacts),
    "e3_private_in_general_json": ("PRIVATE_PROPERTY_SERIALIZED", e3_private_in_general_json),
    "e4_hidden_project": ("MARKET_BOUNDARY_OMITTED", e4_hidden_project),
    "e4_hidden_invoice": ("MARKET_BOUNDARY_OMITTED", e4_hidden_invoice),
    "e4_hidden_contacts": ("MARKET_BOUNDARY_OMITTED", e4_hidden_contacts),
    "e4_hidden_in_list": ("MARKET_BOUNDARY_OMITTED", e4_hidden_in_list),
    "e5_refused_write_persists": ("WRITE_BEFORE_AUTHORIZATION", e5_refused_write_persists),
}
