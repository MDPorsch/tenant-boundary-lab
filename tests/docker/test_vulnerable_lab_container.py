"""TL-16, layer 7 (milestone M3): the container is the real network boundary.

Needs a running Docker daemon (decision D-46). Without one these tests FAIL with the exact command
that deselects them; they are never skipped, so a missing daemon cannot look like a pass.

The self-check (`deploy/container_selfcheck.py`) runs INSIDE the container and reports what it
observes: who it runs as, which interfaces exist, whether outbound TCP and DNS work, whether the
root filesystem is writable, which capabilities it holds, and whether the four exploits work there.
A CONTROL run without `--network none` must report that egress is NOT blocked: otherwise the check
could be reporting 'blocked' for any reason at all.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.milestone("M3"), pytest.mark.docker]

REPO = Path(__file__).resolve().parents[2]
IMAGE = "tenantlab-vulnerable-lab:test"
HARDENED = [
    "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=64m", "--cap-drop", "ALL",  # noqa: S108
    "--security-opt", "no-new-privileges", "--user", "10001:10001",
]  # fmt: skip


def _docker(*args: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["docker", *args],  # noqa: S607
        capture_output=True, text=True, timeout=timeout, check=False,
    )  # fmt: skip


@pytest.fixture(scope="module")
def image() -> str:
    try:
        info = _docker("info", "--format", "{{.ServerVersion}}", timeout=30)
    except FileNotFoundError:
        info = subprocess.CompletedProcess([], 1, "", "docker: command not found")
    if info.returncode != 0:
        pytest.fail(
            "NO DOCKER DAEMON: the container-isolation tests cannot run, and that is a failure, "
            "not a pass (D-46). Start Docker (for example `colima start`), or deselect these "
            f'tests explicitly with `pytest -m "not docker"`. ({info.stderr.strip()[:200]})',
            pytrace=False,
        )
    build = _docker(
        "build", "-f", "deploy/Dockerfile.vulnerable-lab", "-t", IMAGE, str(REPO), timeout=1200
    )
    assert build.returncode == 0, (
        f"image build failed:\n{build.stdout[-1500:]}\n{build.stderr[-1500:]}"
    )
    return IMAGE


def _selfcheck(image: str, *run_args: str) -> dict[str, object]:
    result = _docker(
        "run", "--rm", *run_args, image, "python", "/app/deploy/container_selfcheck.py", timeout=300
    )
    assert result.returncode == 0, (
        f"self-check failed:\n{result.stdout[-800:]}\n{result.stderr[-800:]}"
    )
    return dict(json.loads(result.stdout.strip().splitlines()[-1]))


def test_tl16_inside_the_isolated_container_nothing_can_leave_and_nothing_is_privileged(
    image: str,
) -> None:
    report = _selfcheck(image, "--network", "none", *HARDENED)
    assert report["uid"] == 10001, "must not run as root"
    assert report["interfaces"] == ["lo"], "only the loopback interface may exist"
    assert report["egress_tcp_blocked"] is True
    assert report["dns_blocked"] is True
    assert report["root_filesystem_read_only"] is True
    assert report["effective_capabilities"] == "0000000000000000"
    assert report["no_new_privileges"] is True


def test_tl16_the_flaws_are_exploitable_inside_the_container(image: str) -> None:
    """The lab still does its job once isolated: all four exploits work there."""
    exploits = _selfcheck(image, "--network", "none", *HARDENED)["exploits"]
    assert exploits == {
        "TENANT_PREDICATE_OMITTED": True,
        "ROLE_CHECK_MISSING": True,
        "PRIVATE_PROPERTY_SERIALIZED": True,
        "MARKET_BOUNDARY_OMITTED": True,
    }


def test_tl16_control_without_network_isolation_the_selfcheck_reports_egress_possible(
    image: str,
) -> None:
    """Anti-vacuity: the same image on the default network must be seen to reach out, by BOTH
    probes, or 'blocked' in the test above would prove nothing for the probe that stayed silent."""
    report = _selfcheck(image, *HARDENED)
    assert report["egress_tcp_blocked"] is False, "the TCP probe cannot see a reachable network"
    assert report["dns_blocked"] is False, "the DNS probe cannot see a working resolver"
    assert report["interfaces"] != ["lo"]


def test_tl16_the_container_does_not_loosen_the_guards(image: str) -> None:
    result = _docker(
        "run", "--rm", "--network", "none", *HARDENED,
        "-e", "LAB_MODE=1", "-e", "TENANTLAB_ENV=lab",
        image, "python", "-m", "tenantlab.lab.vulnerable", "--host", "0.0.0.0", "--port", "8099",
    )  # fmt: skip
    assert result.returncode == 2
    assert "loopback" in result.stderr.lower()


def test_tl16_the_image_declares_no_ports_and_a_non_root_user(image: str) -> None:
    inspect = json.loads(_docker("image", "inspect", image).stdout)[0]["Config"]
    assert not inspect.get("ExposedPorts")
    assert str(inspect["User"]).split(":")[0] not in ("", "0", "root")
