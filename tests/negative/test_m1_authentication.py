"""TL-01 and TL-02 (milestone M1): the authentication gate.

STATUS: RED by design in M0. These tests specify behaviour the M1 milestone must build. They fail
today with "NOT IMPLEMENTED (milestone M1)" and must never be skipped, xfailed or weakened to
turn green. Expected outcomes come from oracle/data/gates.csv (gate 1) and the case catalog.

What "pass" means here is stricter than a status code (spec s9, TL-17 caveat): the WHOLE database,
including audit_events, must be byte-identical before and after. Pre-authentication failures
write structured logs only.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from tests.harness import Lab, assert_no_leak, assert_problem

pytestmark = pytest.mark.milestone("M1")

Variant = Callable[[Lab], dict[str, str]]


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _alice(lab: Lab) -> str:
    return lab.fx.principal("alice").id


# --- TL-01: absent, malformed or forged credentials --------------------------------------------
BAD_CREDENTIALS: dict[str, Variant] = {
    "missing_header": lambda lab: {},
    "empty_bearer": lambda lab: {"Authorization": "Bearer "},
    "basic_scheme": lambda lab: {"Authorization": "Basic YWxpY2U6cGFzcw=="},
    "not_a_jwt": lambda lab: _bearer("not-a-jwt"),
    "two_segments": lambda lab: _bearer("abc.def"),
    "forged_wrong_key": lambda lab: _bearer(lab.mint.signed_by_attacker(_alice(lab))),
    "alg_none": lambda lab: _bearer(lab.mint.alg_none(_alice(lab))),
    "hs256_key_confusion": lambda lab: _bearer(lab.mint.hs256_key_confusion(_alice(lab))),
    "truncated_signature": lambda lab: _bearer(lab.mint.truncated_signature(_alice(lab))),
    "tampered_payload_bob_to_alice": lambda lab: _bearer(
        lab.mint.tampered_payload(lab.fx.principal("bob").id, _alice(lab))
    ),
}


def _routes(lab: Lab) -> dict[str, tuple[str, str, Any]]:
    tenant_a, pa1 = lab.fx.tenant("A").id, lab.fx.project("PA1").id
    return {
        # a read, and a mutating route: "no DB change" is only meaningful for the latter
        "context_read": ("GET", f"/v1/tenants/{tenant_a}/me", None),
        "project_patch": ("PATCH", f"/v1/projects/{pa1}", {"title": "pwned", "row_version": 1}),
    }


async def _assert_rejected_401(lab: Lab, variant: str, headers: dict[str, str], route: str) -> None:
    method, path, body = _routes(lab)[route]
    before = lab.snapshot()
    response = await lab.request(method, path, headers=headers, json_body=body)
    assert_problem(response, status=401, code="auth.token_invalid")
    assert response.headers["www-authenticate"].split()[0].lower() == "bearer"
    assert_no_leak(response.text, lab.fx, forbidden_tenants="ABC")
    token = headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if len(token) > 8:
        assert token not in response.text, f"{variant}: the token was echoed in the error body"
    assert lab.snapshot() == before, f"{variant}: the database changed on a 401"


@pytest.mark.parametrize("route", ["context_read", "project_patch"])
@pytest.mark.parametrize("variant", sorted(BAD_CREDENTIALS))
async def test_tl01_bad_or_missing_credentials_are_401_and_change_nothing(
    open_lab: Callable[..., Any], variant: str, route: str
) -> None:
    lab: Lab = await open_lab()
    await _assert_rejected_401(lab, variant, BAD_CREDENTIALS[variant](lab), route)


async def test_tl01_control_a_valid_token_is_accepted(open_lab: Callable[..., Any]) -> None:
    """Anti-vacuity: a deny-everything server would pass every negative test above."""
    lab: Lab = await open_lab()
    tenant_a = lab.fx.tenant("A").id
    response = await lab.request("GET", f"/v1/tenants/{tenant_a}/me", headers=lab.bearer("alice"))
    assert response.status_code == 200, response.text
    assert response.json() == {"principal_id": _alice(lab), "tenant_id": tenant_a, "role": "owner"}


async def test_tl01_a_token_in_the_query_string_is_not_a_credential(
    open_lab: Callable[..., Any],
) -> None:
    lab: Lab = await open_lab()
    tenant_a = lab.fx.tenant("A").id
    token = lab.token("alice")  # a perfectly valid token, supplied the wrong way
    before = lab.snapshot()
    response = await lab.request(
        "GET", f"/v1/tenants/{tenant_a}/me", params={"access_token": token}
    )
    assert_problem(response, status=401, code="auth.token_invalid")
    assert token not in response.text
    assert lab.snapshot() == before


async def test_tl01_authentication_precedes_body_parsing(open_lab: Callable[..., Any]) -> None:
    """An anonymous caller must not learn anything from body validation: malformed JSON on a
    mutating route is still 401, never 422 (shared standard s2 order)."""
    lab: Lab = await open_lab()
    pa1 = lab.fx.project("PA1").id
    before = lab.snapshot()
    response = await lab.request(
        "PATCH",
        f"/v1/projects/{pa1}",
        content=b'{"title": ',
        headers={"Content-Type": "application/json"},
    )
    assert_problem(response, status=401, code="auth.token_invalid")
    assert lab.snapshot() == before


# --- TL-02: well-signed tokens with bad claims -------------------------------------------------
CLAIM_VARIANTS: dict[str, dict[str, Any]] = {
    # Lifetime is 540 s (<= the 900 s cap) so EXPIRY is the only violated property; a
    # 3540 s lifetime would also trip the cap and mask a verifier that never checks `exp`.
    "expired": {"iat_offset": -600, "nbf_offset": -600, "exp_offset": -60},
    "not_yet_valid": {"nbf_offset": 300, "exp_offset": 600},
    "issued_in_the_future": {"iat_offset": 300, "exp_offset": 600},
    "wrong_issuer": {"iss": "https://evil.tenantlab.invalid"},
    "wrong_audience": {"aud": "some-other-api"},
    "missing_sub": {"omit": ["sub"]},
    "missing_jti": {"omit": ["jti"]},
    "missing_iss": {"omit": ["iss"]},
    "missing_aud": {"omit": ["aud"]},
    "missing_iat": {"omit": ["iat"]},
    "missing_nbf": {"omit": ["nbf"]},
    "missing_exp": {"omit": ["exp"]},
    "lifetime_901s": {"exp_offset": 901},  # one second above the 900 s maximum
    "lifetime_one_day": {"exp_offset": 86_400},
}


@pytest.mark.parametrize("route", ["context_read", "project_patch"])
@pytest.mark.parametrize("variant", sorted(CLAIM_VARIANTS))
async def test_tl02_bad_claims_are_401_and_change_nothing(
    open_lab: Callable[..., Any], variant: str, route: str
) -> None:
    lab: Lab = await open_lab()
    headers = lab.bearer("alice", **CLAIM_VARIANTS[variant])
    await _assert_rejected_401(lab, variant, headers, route)


async def test_tl02_sub_that_is_not_a_uuid_is_401(open_lab: Callable[..., Any]) -> None:
    lab: Lab = await open_lab()
    headers = _bearer(lab.mint.mint("alice"))  # an e-mail-ish name, not a principal UUID
    await _assert_rejected_401(lab, "sub_not_a_uuid", headers, "context_read")


async def test_tl02_valid_signature_for_an_unknown_principal_is_indistinguishable_from_invalid(
    open_lab: Callable[..., Any],
) -> None:
    """A properly signed token whose `sub` matches no principal must look exactly like any other
    invalid token (no account-existence oracle): 401 auth.token_invalid, nothing written."""
    lab: Lab = await open_lab()
    ghost = lab.fx.never_seeded["principal"]
    await _assert_rejected_401(
        lab, "unknown_principal", _bearer(lab.mint.mint(ghost)), "context_read"
    )
    bad_sig = lab.mint.signed_by_attacker(ghost)
    a = await lab.request(
        "GET", _routes(lab)["context_read"][1], headers=_bearer(lab.mint.mint(ghost))
    )
    b = await lab.request("GET", _routes(lab)["context_read"][1], headers=_bearer(bad_sig))
    for response in (a, b):
        assert_problem(response, status=401, code="auth.token_invalid")
    strip = lambda r: {k: v for k, v in r.json().items() if k != "request_id"}  # noqa: E731
    assert strip(a) == strip(b)


async def test_tl02_control_a_token_at_exactly_the_maximum_lifetime_is_accepted(
    open_lab: Callable[..., Any],
) -> None:
    """Boundary anti-vacuity: 900 s is allowed, 901 s (above) is not."""
    lab: Lab = await open_lab()
    tenant_a = lab.fx.tenant("A").id
    response = await lab.request(
        "GET", f"/v1/tenants/{tenant_a}/me", headers=lab.bearer("alice", exp_offset=900)
    )
    assert response.status_code == 200, response.text
