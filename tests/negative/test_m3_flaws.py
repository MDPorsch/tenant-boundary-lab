"""M3: the four controlled flaws are real, attributable, switchable and confined.

STATUS: written RED-FIRST (the vulnerable lab does not exist yet; tests fail with
"NOT IMPLEMENTED (milestone M3)"). Never skipped or xfailed.

What these tests establish, in order:
1. every exploit succeeds with ALL flaws on, and fails with NONE on (the flaws are the only cause);
2. ATTRIBUTION: with exactly one flaw on, only that flaw's exploits succeed (no cross-talk);
3. the PATCHED app denies every exploit (no exposure in the default router);
4. PARITY: with no flaw on, the vulnerable app answers like the patched app (status and body) to
   a matrix of authorization-relevant requests, so the flaws are the ONLY differences;
5. the exploits work against a SEPARATE PROCESS that listens on a Unix socket, and only there.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from collections.abc import Callable
from typing import Any

import pytest

from tests.harness import Lab, body_sans_request_id
from tests.support_m3 import ALL_FLAWS, EXPLOITS, IsolatedLab

pytestmark = pytest.mark.milestone("M3")

OpenLab = Callable[..., Any]
OpenVuln = Callable[..., Any]
ExploitName = str


# ---------------------------------------------------------------------- 1 and 2: causality ----
@pytest.mark.parametrize("name", sorted(EXPLOITS))
async def test_every_exploit_succeeds_with_all_flaws_on(open_vuln: OpenVuln, name: str) -> None:
    lab: Lab = await open_vuln(ALL_FLAWS)
    assert await EXPLOITS[name][1](lab), f"{name} did not work with every flaw enabled"


@pytest.mark.parametrize("name", sorted(EXPLOITS))
async def test_no_exploit_succeeds_with_no_flaw_on(open_vuln: OpenVuln, name: str) -> None:
    """The control: without the flaws the vulnerable app is not exploitable by these requests."""
    lab: Lab = await open_vuln(())
    assert not await EXPLOITS[name][1](lab), f"{name} worked although no flaw was enabled"


@pytest.mark.parametrize("flaw", ALL_FLAWS)
@pytest.mark.parametrize("name", sorted(EXPLOITS))
async def test_with_exactly_one_flaw_only_that_flaws_exploits_succeed(
    open_vuln: OpenVuln, flaw: str, name: str
) -> None:
    lab: Lab = await open_vuln([flaw])
    owner = EXPLOITS[name][0]
    worked = await EXPLOITS[name][1](lab)
    assert worked is (owner == flaw), (
        f"{name} belongs to {owner}; with only {flaw} on it {'worked' if worked else 'failed'}"
    )


# ------------------------------------------------------------- 3: the patched app is clean ----
@pytest.mark.parametrize("name", sorted(EXPLOITS))
async def test_the_patched_app_denies_every_exploit(open_lab: OpenLab, name: str) -> None:
    lab: Lab = await open_lab()
    assert not await EXPLOITS[name][1](lab), f"{name} works against the PATCHED app"


# ----------------------------------------------------------------------------- 4: parity ----
def _matrix(lab: Lab) -> list[tuple[str | None, str, str, Any]]:
    """(principal or None, method, path, json body): authorization outcomes and success bodies."""
    ids = {
        "A": lab.fx.tenant("A").id,
        "B": lab.fx.tenant("B").id,
        "C": lab.fx.tenant("C").id,
        "GT": lab.fx.never_seeded["tenant"],
        "PA1": lab.fx.project("PA1").id,
        "PA2": lab.fx.project("PA2").id,
        "PB1": lab.fx.project("PB1").id,
        "PC1": lab.fx.project("PC1").id,
        "GP": lab.fx.never_seeded["project"],
        "IA1": lab.fx.invoice("IA1").id,
        "IA2": lab.fx.invoice("IA2").id,
        "IB1": lab.fx.invoice("IB1").id,
        "GI": lab.fx.never_seeded["invoice"],
    }
    paths = [
        *(f"/v1/tenants/{ids[t]}/me" for t in ("A", "B", "C", "GT")),
        *(f"/v1/tenants/{ids[t]}/projects" for t in ("A", "B", "C", "GT")),
        *(f"/v1/projects/{ids[p]}" for p in ("PA1", "PA2", "PB1", "PC1", "GP")),
        *(f"/v1/projects/{ids[p]}/contacts" for p in ("PA1", "PA2", "PB1", "PC1", "GP")),
        *(f"/v1/invoices/{ids[i]}" for i in ("IA1", "IA2", "IB1", "GI")),
    ]
    people: list[str | None] = [*(p.key for p in lab.fx.principals), None, "garbage"]
    rows: list[tuple[str | None, str, str, Any]] = [
        (who, "GET", path, None) for who in people for path in paths
    ]
    # writes, in one fixed order so both apps pass through identical states
    for who in ("bob", "alice", "dave", "carla", "erin", "frank", "gina"):
        for project in ("PA1", "PA2", "PB1", "PC1", "GP"):
            body = {"title": f"parity-{who}-{project}", "row_version": 1}
            rows.append((who, "PATCH", f"/v1/projects/{ids[project]}", body))
    rows.append(
        ("alice", "PATCH", f"/v1/projects/{ids['PA1']}", {"title": "stale", "row_version": 1})
    )
    rows.append(
        ("alice", "PATCH", f"/v1/projects/{ids['PA1']}", {"title": "fresh", "row_version": 2})
    )
    return rows


async def _answer(lab: Lab, who: str | None, method: str, path: str, body: Any) -> tuple[Any, ...]:
    if who is None:
        headers: dict[str, str] = {}
    elif who == "garbage":
        headers = {"Authorization": "Bearer not-a-jwt"}
    else:
        headers = lab.bearer(who)
    response = await lab.request(method, path, headers=headers, json_body=body)
    payload = response.json()
    return (
        response.status_code,
        response.headers["content-type"].split(";")[0],
        body_sans_request_id(payload) if isinstance(payload, dict) else payload,
    )


async def test_with_no_flaw_enabled_the_vulnerable_app_answers_exactly_like_the_patched_one(
    open_lab: OpenLab, open_vuln: OpenVuln
) -> None:
    """Status, media type and body (minus the request id) for every request in the matrix: the
    flaws are the ONLY differences. Request-validation error detail is out of scope (D-42)."""
    patched: Lab = await open_lab()
    vulnerable: Lab = await open_vuln(())
    rows = _matrix(patched)
    assert len(rows) > 250
    differences = []
    for who, method, path, body in rows:
        expected = await _answer(patched, who, method, path, body)
        observed = await _answer(vulnerable, who, method, path, body)
        if expected != observed:
            differences.append((who, method, path.split("/v1/")[1], expected[0], observed[0]))
    assert not differences, f"{len(differences)} differences, first: {differences[:5]}"


async def test_the_matrix_has_teeth_it_does_detect_a_flaw(
    open_lab: OpenLab, open_vuln: OpenVuln
) -> None:
    """Anti-vacuity for the parity test: with one flaw on, the same comparison must NOT be clean."""
    patched: Lab = await open_lab()
    vulnerable: Lab = await open_vuln(["MARKET_BOUNDARY_OMITTED"])
    seen = 0
    for who, method, path, body in _matrix(patched):
        if method != "GET":
            continue
        if await _answer(patched, who, method, path, body) != await _answer(
            vulnerable, who, method, path, body
        ):
            seen += 1
    assert seen > 0


# --------------------------------------------------------- 5: a separate, socket-only process ----
async def test_the_exploits_work_against_a_separate_process_serving_a_unix_socket_only(
    isolated_lab: Callable[..., IsolatedLab],
) -> None:
    process = isolated_lab(ALL_FLAWS)
    lab = process.lab()
    try:
        for name, (_, exploit) in sorted(EXPLOITS.items()):
            assert await exploit(lab), f"{name} failed against the isolated process"
    finally:
        await lab.aclose()
    # the process opened no network socket of any kind: nothing for another machine to reach
    lsof = shutil.which("lsof")
    assert lsof, "lsof is required to prove the isolated process holds no network socket"
    pid = str(process.process.pid)  # type: ignore[union-attr]
    listing = await asyncio.to_thread(
        subprocess.run, [lsof, "-nP", "-a", "-p", pid, "-i"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert listing.stdout.strip() == "", f"the lab holds a network socket:\n{listing.stdout}"


async def test_a_separate_process_with_no_flaws_resists_the_same_exploits(
    isolated_lab: Callable[..., IsolatedLab],
) -> None:
    process = isolated_lab(())
    lab = process.lab()
    try:
        results = {name: await exploit(lab) for name, (_, exploit) in sorted(EXPLOITS.items())}
    finally:
        await lab.aclose()
    assert not any(results.values()), results


async def test_the_process_announces_what_it_is_and_which_flaws_are_on(
    isolated_lab: Callable[..., IsolatedLab],
) -> None:
    process = isolated_lab(["MARKET_BOUNDARY_OMITTED", "ROLE_CHECK_MISSING"])
    log = process.stderr_text()
    assert "DELIBERATELY VULNERABLE" in log
    assert "MARKET_BOUNDARY_OMITTED" in log
    assert "ROLE_CHECK_MISSING" in log
    assert "TENANT_PREDICATE_OMITTED" not in log
