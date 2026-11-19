"""TL-19, timing part: a hidden object must be indistinguishable from a missing one by the WORK the
server does and by the TIME it takes.

STATUS: written RED-FIRST (this is the hardening that replaced the first, coarse timing test).

Two layers, from strongest to weakest:

1. STRUCTURE (deterministic, no clock): every "not visible" outcome of a route runs the identical
   SQL statement sequence. If the sequences are equal there is no data-dependent branch for a clock
   to find, and the test cannot flake.
2. STATISTICS (a clock): interleaved samples, a permutation test and an effect-size floor, which
   must trigger in every one of two independent rounds before the test fails. It only claims to
   detect differences of at least 15%; it does NOT claim constant-time behaviour (LIMITATIONS
   L-07, L-24).

A third test proves the statistical detector can actually see a difference, so layer 2 cannot pass
simply because it is blind.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from tests.harness import Lab
from tests.support_m2 import count_statements
from tests.timing import (
    EFFECT_THRESHOLD,
    ROUNDS,
    SAMPLES_PER_CLASS,
    flagged,
    interleaved_samples,
    relative_difference,
)

pytestmark = pytest.mark.milestone("M2")

OpenLab = Callable[..., Any]
Request = tuple[str, str, str, Any]  # (who, method, path, json body)
PATCH_BODY = {"title": "renamed", "row_version": 1}


def _groups(lab: Lab) -> dict[str, dict[str, Request]]:
    """Per route family: every class of 'not visible' request, all of which must answer 404."""
    ids = {
        "A": lab.fx.tenant("A").id,
        "B": lab.fx.tenant("B").id,
        "PA1": lab.fx.project("PA1").id,
        "PA2": lab.fx.project("PA2").id,
        "PB1": lab.fx.project("PB1").id,
        "IA2": lab.fx.invoice("IA2").id,
        "IB1": lab.fx.invoice("IB1").id,
        "GT": lab.fx.never_seeded["tenant"],
        "GP": lab.fx.never_seeded["project"],
        "GI": lab.fx.never_seeded["invoice"],
        "CARLA": lab.fx.principal("carla").id,
    }
    return {
        "project read": {
            "hidden market": ("alice", "GET", f"/v1/projects/{ids['PA2']}", None),
            "foreign tenant": ("bob", "GET", f"/v1/projects/{ids['PB1']}", None),
            "revoked member": ("frank", "GET", f"/v1/projects/{ids['PA1']}", None),
            "missing": ("alice", "GET", f"/v1/projects/{ids['GP']}", None),
        },
        "project write": {
            "hidden market": ("alice", "PATCH", f"/v1/projects/{ids['PA2']}", PATCH_BODY),
            "foreign tenant": ("bob", "PATCH", f"/v1/projects/{ids['PB1']}", PATCH_BODY),
            "revoked member": ("frank", "PATCH", f"/v1/projects/{ids['PA1']}", PATCH_BODY),
            "missing": ("alice", "PATCH", f"/v1/projects/{ids['GP']}", PATCH_BODY),
        },
        "project contacts": {
            "hidden market": ("alice", "GET", f"/v1/projects/{ids['PA2']}/contacts", None),
            "foreign tenant": ("bob", "GET", f"/v1/projects/{ids['PB1']}/contacts", None),
            "missing": ("alice", "GET", f"/v1/projects/{ids['GP']}/contacts", None),
        },
        "invoice": {
            "hidden market": ("alice", "GET", f"/v1/invoices/{ids['IA2']}", None),
            "foreign tenant": ("alice", "GET", f"/v1/invoices/{ids['IB1']}", None),
            "missing": ("alice", "GET", f"/v1/invoices/{ids['GI']}", None),
            "nested, wrong project": (
                "alice", "GET", f"/v1/projects/{ids['PA1']}/invoices/{ids['IB1']}", None,
            ),
            "nested, missing project": (
                "alice", "GET", f"/v1/projects/{ids['GP']}/invoices/{ids['IB1']}", None,
            ),
            "nested, missing invoice": (
                "alice", "GET", f"/v1/projects/{ids['PA1']}/invoices/{ids['GI']}", None,
            ),
        },
        "tenant": {
            "foreign tenant": ("bob", "GET", f"/v1/tenants/{ids['B']}/me", None),
            "revoked member": ("frank", "GET", f"/v1/tenants/{ids['A']}/me", None),
            "missing": ("bob", "GET", f"/v1/tenants/{ids['GT']}/me", None),
            "list, foreign": ("bob", "GET", f"/v1/tenants/{ids['B']}/projects", None),
            "list, missing": ("bob", "GET", f"/v1/tenants/{ids['GT']}/projects", None),
        },
        "membership": {
            "foreign tenant": (
                "alice", "PUT", f"/v1/tenants/{ids['B']}/members/{ids['CARLA']}",
                {"role": "owner", "status": "active", "version": 1},
            ),
            "missing tenant": (
                "alice", "PUT", f"/v1/tenants/{ids['GT']}/members/{ids['CARLA']}",
                {"role": "owner", "status": "active", "version": 1},
            ),
        },
    }  # fmt: skip


async def _statements(lab: Lab, request: Request) -> list[str]:
    who, method, path, body = request
    with count_statements() as seen:
        response = await lab.request(method, path, headers=lab.bearer(who), json_body=body)
    assert response.status_code == 404, (path, response.status_code, response.text)
    return [" ".join(statement.split()) for statement in seen]


# ---------------------------------------------------------------------- layer 1: structure ----
@pytest.mark.parametrize(
    "family",
    ["project read", "project write", "project contacts", "invoice", "tenant", "membership"],
)
async def test_tl19_every_not_visible_outcome_runs_the_same_sql(
    open_lab: OpenLab, family: str
) -> None:
    """A hidden, a foreign, a revoked and a missing target are one case to an observer; if the
    server also does the same database work for each, there is nothing for a clock to find."""
    lab: Lab = await open_lab()
    sequences = {
        name: await _statements(lab, request) for name, request in _groups(lab)[family].items()
    }
    distinct = {tuple(seq) for seq in sequences.values()}
    counts = {name: len(seq) for name, seq in sequences.items()}
    assert len(distinct) == 1, (
        f"{family}: different SQL work per outcome (statement counts {counts})"
    )


async def test_tl19_an_incoherent_invoice_runs_the_same_sql_as_a_missing_one(
    open_lab: OpenLab,
) -> None:
    lab: Lab = await open_lab()
    lab.sql(
        "UPDATE invoices SET tenant_id = (SELECT id FROM tenants WHERE slug = 'tenant-b') "
        "WHERE amount_minor = 125000"
    )  # IA1 now claims tenant B although its project is tenant A's
    incoherent = ("alice", "GET", f"/v1/invoices/{lab.fx.invoice('IA1').id}", None)
    missing = ("alice", "GET", f"/v1/invoices/{lab.fx.never_seeded['invoice']}", None)
    assert await _statements(lab, incoherent) == await _statements(lab, missing)


# -------------------------------------------------------------------- layer 2: statistics ----
def _requests(lab: Lab, group: dict[str, Request]) -> dict[str, Callable[[], Any]]:
    headers = {who: lab.bearer(who) for who, *_ in group.values()}

    def make(request: Request) -> Callable[[], Any]:
        who, method, path, body = request

        async def call() -> Any:
            return await lab.request(method, path, headers=headers[who], json_body=body)

        return call

    return {name: make(request) for name, request in group.items()}


async def test_tl19_no_timing_difference_of_15_percent_is_detectable_between_hidden_and_missing(
    open_lab: OpenLab,
) -> None:
    """Interleaved, randomised order; the claim is only 'no difference of at least 15%, in both of
    two independent rounds'. Constant-time behaviour is NOT claimed (L-07, L-24)."""
    lab: Lab = await open_lab()
    group = _groups(lab)["project read"]
    calls = _requests(lab, group)
    others = [name for name in calls if name != "missing"]
    hits = dict.fromkeys(others, 0)
    last: dict[str, float] = {}
    for round_number in range(ROUNDS):
        samples = await interleaved_samples(calls, SAMPLES_PER_CLASS, seed=round_number)
        for name in others:
            last[name] = relative_difference(samples[name], samples["missing"])
            if flagged(samples[name], samples["missing"]):
                hits[name] += 1
    consistently = {name: hits[name] for name in others if hits[name] == ROUNDS}
    assert not consistently, (
        f"detectable and repeatable timing difference vs a missing project: "
        f"{ {n: f'{last[n]:+.0%}' for n in consistently} } (threshold {EFFECT_THRESHOLD:.0%})"
    )


async def test_tl19_the_timing_detector_can_see_a_real_difference(open_lab: OpenLab) -> None:
    """Anti-vacuity: a successful project read does clearly more work than a 404. The detector
    must flag that in both rounds, or layer 2 above could be passing because it is blind."""
    lab: Lab = await open_lab()
    pa1, ghost = lab.fx.project("PA1").id, lab.fx.never_seeded["project"]
    headers = lab.bearer("alice")

    async def visible() -> Any:
        return await lab.request("GET", f"/v1/projects/{pa1}", headers=headers)

    async def missing() -> Any:
        return await lab.request("GET", f"/v1/projects/{ghost}", headers=headers)

    seen = 0
    for round_number in range(ROUNDS):
        samples = await interleaved_samples(
            {"visible": visible, "missing": missing}, SAMPLES_PER_CLASS, seed=100 + round_number
        )
        seen += flagged(samples["visible"], samples["missing"])
    assert seen == ROUNDS, "the detector failed to see a response that does ~2x the work"
