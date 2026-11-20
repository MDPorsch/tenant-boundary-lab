"""M5: Hypothesis properties over random actors, resources and request bodies.

Where tests/negative/test_m5_sweep.py walks every combination once, these let Hypothesis choose
sequences: several requests in a row on the SAME lab, so a write that succeeds changes what the next
request sees. Every response of every example is judged by the one independent checker
(tests/support_properties.py): no server error, a well-formed problem, no foreign or private data, the
authorization matrix's answer, and an unchanged database unless an authorised write succeeded.

Deterministic by default (derandomize), so a CI failure reproduces; set TENANTLAB_EXPLORE=1 for a
long random search (it shrinks any counter-example Hypothesis finds).
"""

from __future__ import annotations

import asyncio
import os
import string
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from tests.harness import KeyPair
from tests.support_properties import (
    BAD_TOKENS,
    CREDENTIALS,
    ROUTES,
    TENANTS,
    WRITES,
    Probe,
    build_probe,
    build_template,
    check,
    headers_for,
    lab_from_template,
    send_and_check,
    targets_around,
    targets_for,
)

pytestmark = pytest.mark.milestone("M5")

EXPLORE = os.environ.get("TENANTLAB_EXPLORE") == "1"
CONFIG = settings(
    max_examples=1500 if EXPLORE else 150,
    deadline=None,
    derandomize=not EXPLORE,
    database=None,
    suppress_health_check=list(HealthCheck),
)
ROUTE_NAMES = [r[0] for r in ROUTES]


@pytest.fixture(scope="module")
def template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("m5-props") / "template.sqlite"
    build_template(path)
    return path


PAIRS = [(credential, tenant) for credential in CREDENTIALS for tenant in TENANTS]


def covering(test: Any) -> Any:
    """Add one EXPLICIT example per (caller, tenant) pair, each walking every route.

    Hypothesis is a search, not a coverage tool: it mutates earlier examples and drew a member of the
    suspended tenant meeting that tenant ZERO times in 561 requests, so the M5 mutation check found a
    survivor. These examples make the pairing certain; the random part still explores sequences."""
    for credential, tenant in PAIRS:
        steps = [(credential, r, targets_around(r, tenant)[0]) for r in ROUTE_NAMES]
        test = example(steps=steps)(test)
    return test


@st.composite
def requests(draw: st.DrawFn) -> tuple[str, str, dict[str, str]]:
    """(caller, route, target), with the caller and the tenant the target is about drawn TOGETHER."""
    credential, tenant = draw(st.sampled_from(PAIRS))
    route = draw(st.sampled_from(ROUTE_NAMES))
    return credential, route, draw(st.sampled_from(targets_around(route, tenant)))


JSON = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(-5, 2**40)
    | st.floats(allow_nan=False)
    | st.text(max_size=24),
    lambda inner: (
        st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=10), inner, max_size=3)
    ),
    max_leaves=8,
)
HEADER_VALUE = st.text(alphabet=string.ascii_letters + string.digits + " .-_=+/:;,", max_size=120)


async def _run(
    template: Path, tmp_path: Path, trusted: KeyPair, attacker: KeyPair, steps: list[Any]
) -> None:
    lab = await lab_from_template(template, tmp_path / "lab.sqlite", trusted, attacker)
    try:
        for credential, route, target in steps:
            await send_and_check(lab, credential, build_probe(lab, route, target))
    finally:
        await lab.aclose()


@covering
@CONFIG
@given(steps=st.lists(requests(), min_size=1, max_size=8))
def test_a_sequence_of_arbitrary_requests_never_breaks_a_rule(
    template: Path, tmp_path: Path, trusted_keys: KeyPair, attacker_keys: KeyPair, steps: list[Any]
) -> None:
    asyncio.run(_run(template, tmp_path, trusted_keys, attacker_keys, steps))


@CONFIG
@given(step=requests(), body=JSON)
def test_an_arbitrary_body_is_never_a_server_error_and_a_refusal_never_writes(
    template: Path,
    tmp_path: Path,
    trusted_keys: KeyPair,
    attacker_keys: KeyPair,
    step: tuple[str, str, dict[str, str]],
    body: Any,
) -> None:
    credential, route, target = step

    async def go() -> None:
        lab = await lab_from_template(
            template, tmp_path / "lab.sqlite", trusted_keys, attacker_keys
        )
        try:
            probe = build_probe(lab, route, target)
            junk = Probe(**{**probe.__dict__, "body": body if route in WRITES else None})
            before = lab.snapshot()
            response = await lab.request(
                junk.method, junk.path, headers=headers_for(lab, credential), json_body=junk.body
            )
            after = lab.snapshot()
            if response.status_code < 400 and route in WRITES:
                # a body that happened to be valid and authorised: only the state rule applies
                assert response.status_code in {200, 201}
            else:
                check(lab, credential, junk, response, before=before, after=after)
        finally:
            await lab.aclose()

    asyncio.run(go())


@CONFIG
@given(
    route=st.sampled_from(ROUTE_NAMES),
    header=HEADER_VALUE,
    scheme=st.sampled_from(["Bearer", "bearer", "Basic", "Token", ""]),
)
def test_a_malformed_authorization_header_is_a_plain_401(
    template: Path,
    tmp_path: Path,
    trusted_keys: KeyPair,
    attacker_keys: KeyPair,
    route: str,
    header: str,
    scheme: str,
) -> None:
    async def go() -> None:
        lab = await lab_from_template(
            template, tmp_path / "lab.sqlite", trusted_keys, attacker_keys
        )
        try:
            probe = build_probe(lab, route, targets_for(route)[0])
            before = lab.snapshot()
            response = await lab.request(
                probe.method,
                probe.path,
                headers={"Authorization": f"{scheme} {header}".strip()},
                json_body=probe.body,
            )
            assert response.status_code == 401, response.text[:200]
            check(lab, "garbage", probe, response, before=before, after=lab.snapshot())
        finally:
            await lab.aclose()

    asyncio.run(go())


@CONFIG
@given(credential=st.sampled_from([c for c in CREDENTIALS if c not in BAD_TOKENS]), data=st.data())
def test_a_hidden_object_answers_exactly_like_a_missing_one(
    template: Path,
    tmp_path: Path,
    trusted_keys: KeyPair,
    attacker_keys: KeyPair,
    credential: str,
    data: st.DataObject,
) -> None:
    """Concealment (TL-04/08/19): for a caller with no membership in an object's tenant, a real
    object of that tenant and an id that never existed are indistinguishable: same status, same
    body except the request id."""
    route = data.draw(st.sampled_from(["project", "contacts", "invoice"]))
    kind = "invoice" if route == "invoice" else "project"
    real = data.draw(
        st.sampled_from(
            ["PA1", "PA2", "PB1", "PC1"] if kind == "project" else ["IA1", "IA2", "IB1"]
        )
    )

    async def go() -> None:
        lab = await lab_from_template(
            template, tmp_path / "lab.sqlite", trusted_keys, attacker_keys
        )
        try:
            owner = (
                lab.fx.project(real).tenant if kind == "project" else lab.fx.invoice(real).tenant
            )
            member = any(
                m.principal == credential and m.tenant == owner and m.status == "active"
                for m in lab.fx.memberships
            )
            hidden_market = real in {"PA2", "IA2"}
            if member and not hidden_market:
                return  # a member legitimately sees her own tenant's objects
            if lab.fx.principal(credential).status != "active":
                return  # a disabled principal is refused before any object is looked at
            seen: list[Any] = []
            for name in (real, "ghost"):
                probe = build_probe(lab, route, {kind: name})
                response = await lab.request(
                    probe.method, probe.path, headers=headers_for(lab, credential)
                )
                body = response.json()
                body.pop("request_id", None)
                seen.append((response.status_code, response.headers["content-type"], body))
            assert seen[0] == seen[1], f"{credential} can tell {real} from a missing {kind}: {seen}"
        finally:
            await lab.aclose()

    asyncio.run(go())
