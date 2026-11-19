"""Unit tests of the token verifier (decision D-03) with an INDEPENDENT token mint.

The end-to-end tests (tests/negative) prove that a bad token yields 401. These prove WHY each token
is refused, so a verifier that rejects everything, or rejects for the wrong reason, is noticed. The
verifier's own reason codes are internal (logged, never sent to the client).
"""

from __future__ import annotations

import base64
import json
import string
import uuid
from typing import Any

import jwt
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tenantlab.auth.tokens import (
    MAX_TOKEN_CHARS,
    ConfigurationError,
    TokenError,
    TokenVerifier,
    VerifiedToken,
    load_public_key,
)
from tests.harness import AUDIENCE, ISSUER, KeyPair, TokenMint, generate_keypair

SUB = "10000000-0000-4000-8000-000000000001"
SUB_WITH_LETTERS = "a000000b-0000-4000-8000-00000000000c"  # upper-casing changes it


@pytest.fixture(scope="module")
def mint(trusted_keys: KeyPair, attacker_keys: KeyPair) -> TokenMint:
    return TokenMint(trusted_keys, attacker_keys)


@pytest.fixture(scope="module")
def verifier(trusted_keys: KeyPair) -> TokenVerifier:
    return TokenVerifier(load_public_key(trusted_keys.public_pem), ISSUER, AUDIENCE)


def _reason(verifier: TokenVerifier, token: str) -> str:
    with pytest.raises(TokenError) as caught:
        verifier.verify(token)
    return caught.value.reason


def test_a_valid_token_yields_exactly_the_verified_identity(
    verifier: TokenVerifier, mint: TokenMint
) -> None:
    verified = verifier.verify(mint.mint(SUB))
    assert isinstance(verified, VerifiedToken)
    assert verified.subject == uuid.UUID(SUB)
    assert verified.jti
    assert verified.expires_at - verified.issued_at == 300


def test_a_token_at_exactly_the_maximum_lifetime_is_accepted(
    verifier: TokenVerifier, mint: TokenMint
) -> None:
    assert verifier.verify(mint.mint(SUB, exp_offset=900)).subject == uuid.UUID(SUB)


CLAIM_REASONS: dict[str, tuple[dict[str, Any], str]] = {
    "expired": ({"iat_offset": -600, "nbf_offset": -600, "exp_offset": -60}, "expired"),
    "not_yet_valid": ({"nbf_offset": 300, "exp_offset": 600}, "not_yet_valid"),
    "issued_in_the_future": ({"iat_offset": 300, "exp_offset": 600}, "not_yet_valid"),
    "wrong_issuer": ({"iss": "https://evil.tenantlab.invalid"}, "bad_issuer"),
    "wrong_audience": ({"aud": "some-other-api"}, "bad_audience"),
    "missing_sub": ({"omit": ["sub"]}, "missing_claim"),
    "missing_jti": ({"omit": ["jti"]}, "missing_claim"),
    "missing_iss": ({"omit": ["iss"]}, "missing_claim"),
    "missing_aud": ({"omit": ["aud"]}, "missing_claim"),
    "missing_iat": ({"omit": ["iat"]}, "missing_claim"),
    "missing_nbf": ({"omit": ["nbf"]}, "missing_claim"),
    "missing_exp": ({"omit": ["exp"]}, "missing_claim"),
    "lifetime_901": ({"exp_offset": 901}, "lifetime"),
    "lifetime_one_day": ({"exp_offset": 86_400}, "lifetime"),
    "exp_equals_iat": ({"exp_offset": 0}, "expired"),
    "sub_not_a_uuid": ({"sub": "alice"}, "bad_subject"),
    "sub_upper_case": ({"sub": SUB_WITH_LETTERS.upper()}, "bad_subject"),
    "sub_without_hyphens": ({"sub": SUB.replace("-", "")}, "bad_subject"),
    "sub_a_number": ({"sub": 5}, "bad_subject"),
    "sub_nil_uuid": ({"sub": "00000000-0000-0000-0000-000000000000"}, "bad_subject"),
    "jti_empty": ({"extra": {"jti": ""}}, "bad_jti"),
    "jti_a_number": ({"extra": {"jti": 7}}, "bad_jti"),
    "jti_too_long": ({"extra": {"jti": "j" * 129}}, "bad_jti"),
    "aud_as_a_list_with_a_second_value": (
        {"aud": [AUDIENCE, "another-api"]},
        "bad_issuer_or_audience",
    ),
    "aud_as_a_one_element_list": ({"aud": [AUDIENCE]}, "bad_issuer_or_audience"),
    "exp_is_a_float": ({"extra": {"exp": 4_102_444_800.5}}, "bad_time_claim"),
    "nbf_is_a_boolean": ({"extra": {"nbf": True}}, "bad_time_claim"),
}


@pytest.mark.parametrize("variant", sorted(CLAIM_REASONS))
def test_each_bad_claim_is_refused_for_its_own_reason(
    verifier: TokenVerifier, mint: TokenMint, variant: str
) -> None:
    kwargs, expected = CLAIM_REASONS[variant]
    kwargs = dict(kwargs)
    sub = kwargs.pop("sub", SUB)
    assert _reason(verifier, mint.mint(sub, **kwargs)) == expected


def test_a_non_numeric_iat_is_refused(verifier: TokenVerifier, mint: TokenMint) -> None:
    assert _reason(verifier, mint.mint(SUB, extra={"iat": "not-a-number"})) == "bad_time_claim"


def test_a_header_that_is_not_json_is_malformed(verifier: TokenVerifier, mint: TokenMint) -> None:
    payload = _b64(json.dumps(mint.claims(SUB)).encode())
    assert _reason(verifier, f"{_b64(b'not json')}.{payload}.{_b64(b'x' * 64)}") == "malformed"


def test_a_validly_signed_payload_that_is_not_json_is_malformed(
    verifier: TokenVerifier, trusted_keys: KeyPair
) -> None:
    """Signature is checked first (garbage + bad signature would be 'bad_signature'); only a
    correctly signed but unparsable payload reaches the generic fallback."""
    token = jwt.api_jws.PyJWS().encode(b"not json", trusted_keys.private, algorithm="EdDSA")
    assert _reason(verifier, token) == "malformed"


def test_a_float_iat_is_refused(verifier: TokenVerifier, mint: TokenMint) -> None:
    now = mint.claims(SUB)["iat"]
    token = mint.mint(SUB, extra={"iat": now + 0.5})
    assert _reason(verifier, token) in {"bad_time_claim", "not_yet_valid"}


def test_forged_and_malformed_signatures_are_refused(
    verifier: TokenVerifier, mint: TokenMint
) -> None:
    assert _reason(verifier, mint.signed_by_attacker(SUB)) == "bad_signature"
    assert _reason(
        verifier, mint.tampered_payload(SUB, "10000000-0000-4000-8000-000000000002")
    ) == ("bad_signature")
    assert _reason(verifier, mint.truncated_signature(SUB)) in {"bad_signature", "malformed"}


def test_alg_none_and_key_confusion_are_refused_before_any_key_use(
    verifier: TokenVerifier, mint: TokenMint
) -> None:
    # An unsigned token has an empty third segment: it is not even a well-formed compact JWS.
    assert _reason(verifier, mint.alg_none(SUB)) == "malformed"
    assert _reason(verifier, mint.hs256_key_confusion(SUB)) == "alg_not_allowed"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.mark.parametrize(
    "alg", ["HS256", "HS512", "RS256", "ES256", "PS256", "none", "NONE", "eddsa"]
)
def test_the_header_alg_is_never_trusted(
    verifier: TokenVerifier, mint: TokenMint, alg: str
) -> None:
    """Whatever alg the token claims, only exactly 'EdDSA' reaches signature verification."""
    header = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = _b64(json.dumps(mint.claims(SUB)).encode())
    token = f"{header}.{payload}.{_b64(b'sig' * 20)}"
    assert _reason(verifier, token) == "alg_not_allowed"


def test_extra_claims_and_headers_are_ignored_and_grant_nothing(
    verifier: TokenVerifier, mint: TokenMint, trusted_keys: KeyPair
) -> None:
    claims = mint.claims(SUB, extra={"role": "owner", "tenant_id": "x", "scope": "admin:*"})
    token = jwt.encode(
        claims,
        trusted_keys.private,
        algorithm="EdDSA",
        headers={"kid": "k1", "jku": "http://127.0.0.1:1/jwks", "x5u": "http://127.0.0.1:1/x"},
    )
    verified = verifier.verify(
        token
    )  # no key is fetched from jku/x5u: the key is the configured one
    assert verified.subject == uuid.UUID(SUB)
    assert not hasattr(verified, "role")
    assert not hasattr(verified, "tenant_id")


@pytest.mark.parametrize(
    "junk",
    [
        "",
        "abc",
        "a.b",
        "a.b.c.d",
        "Bearer abc.def.ghi",
        "é.é.é",
        "a..c",
        ".b.c",
        "a.b.",
        "a b.c.d",
        "a.b.c\n",
        "x" * (MAX_TOKEN_CHARS + 1),
    ],
)
def test_malformed_strings_are_refused(verifier: TokenVerifier, junk: str) -> None:
    assert _reason(verifier, junk) == "malformed"


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=300))
def test_arbitrary_text_is_refused_with_a_token_error_and_nothing_else(text: str) -> None:
    """Fail closed: the verifier raises TokenError for junk, never another exception type."""
    local = TokenVerifier(load_public_key(_PROPERTY_KEYS.public_pem), ISSUER, AUDIENCE)
    with pytest.raises(TokenError):
        local.verify(text)


_B64URL = st.text(alphabet=string.ascii_letters + string.digits + "-_", min_size=1, max_size=80)


@settings(max_examples=300, deadline=None)
@given(_B64URL, _B64URL, _B64URL)
def test_arbitrary_three_segment_strings_are_refused(a: str, b: str, c: str) -> None:
    local = TokenVerifier(load_public_key(_PROPERTY_KEYS.public_pem), ISSUER, AUDIENCE)
    with pytest.raises(TokenError):
        local.verify(f"{a}.{b}.{c}")


_PROPERTY_KEYS = generate_keypair()


def test_a_verifier_without_issuer_or_audience_cannot_be_built(trusted_keys: KeyPair) -> None:
    key = load_public_key(trusted_keys.public_pem)
    with pytest.raises(ConfigurationError):
        TokenVerifier(key, "", AUDIENCE)
    with pytest.raises(ConfigurationError):
        TokenVerifier(key, ISSUER, "")


def test_two_tokens_for_the_same_subject_have_different_jti(
    verifier: TokenVerifier, mint: TokenMint
) -> None:
    assert verifier.verify(mint.mint(SUB)).jti != verifier.verify(mint.mint(SUB)).jti
