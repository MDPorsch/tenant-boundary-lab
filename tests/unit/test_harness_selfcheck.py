"""Guard the guards: prove the hostile tokens and the DB snapshot used by the red tests are
well-formed, so a future 'forged token is rejected' pass cannot be a false pass."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from pathlib import Path

import httpx
import jwt
import pytest
from sqlalchemy import create_engine, text

from tenantlab.lab.fixtures.loader import load_fixtures
from tenantlab.schemas.errors import ErrorCode, ProblemDetail
from tests.harness import (
    AUDIENCE,
    BUSINESS_TABLES,
    ISSUER,
    KeyPair,
    Lab,
    TokenMint,
    assert_problem,
    norm_uuid,
)

SUB = "10000000-0000-4000-8000-000000000001"


@pytest.fixture(scope="module")
def mint(trusted_keys: KeyPair, attacker_keys: KeyPair) -> TokenMint:
    return TokenMint(trusted_keys, attacker_keys)


def _strict_decode(token: str, public_pem: str) -> dict[str, object]:
    """A deliberately strict reference verifier (the contract in api-contract.md s4)."""
    return jwt.decode(
        token,
        public_pem,
        algorithms=["EdDSA"],
        audience=AUDIENCE,
        issuer=ISSUER,
        leeway=0,
        options={"require": ["sub", "jti", "iss", "aud", "iat", "nbf", "exp"]},
    )


def test_keypairs_are_distinct_and_ephemeral(trusted_keys: KeyPair, attacker_keys: KeyPair) -> None:
    assert trusted_keys.public_pem != attacker_keys.public_pem
    assert trusted_keys.public_pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert "PRIVATE" not in trusted_keys.public_pem


def test_default_token_verifies_under_the_strict_reference_verifier(
    mint: TokenMint, trusted_keys: KeyPair
) -> None:
    claims = _strict_decode(mint.mint(SUB), trusted_keys.public_pem)
    assert claims["sub"] == SUB
    assert claims["iss"] == ISSUER
    assert claims["aud"] == AUDIENCE


def test_max_lifetime_token_is_exactly_900_seconds(mint: TokenMint) -> None:
    claims = mint.claims(SUB, exp_offset=900)
    assert claims["exp"] - claims["iat"] == 900  # type: ignore[operator]


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"iat_offset": -600, "nbf_offset": -600, "exp_offset": -60}, jwt.ExpiredSignatureError),
        ({"nbf_offset": 300, "exp_offset": 600}, jwt.ImmatureSignatureError),
        ({"iss": "https://evil.tenantlab.invalid"}, jwt.InvalidIssuerError),
        ({"aud": "some-other-api"}, jwt.InvalidAudienceError),
        ({"omit": ["sub"]}, jwt.MissingRequiredClaimError),
        ({"omit": ["jti"]}, jwt.MissingRequiredClaimError),
        ({"omit": ["exp"]}, jwt.MissingRequiredClaimError),
        ({"omit": ["nbf"]}, jwt.MissingRequiredClaimError),
        ({"omit": ["iat"]}, jwt.MissingRequiredClaimError),
    ],
)
def test_claim_variants_are_each_rejected_by_the_strict_verifier_for_the_stated_reason(
    mint: TokenMint, trusted_keys: KeyPair, kwargs: dict[str, object], error: type[Exception]
) -> None:
    with pytest.raises(error):
        _strict_decode(mint.mint(SUB, **kwargs), trusted_keys.public_pem)  # type: ignore[arg-type]


def test_iat_in_the_future_is_rejected(mint: TokenMint, trusted_keys: KeyPair) -> None:
    with pytest.raises(jwt.ImmatureSignatureError):
        _strict_decode(mint.mint(SUB, iat_offset=300, exp_offset=600), trusted_keys.public_pem)


def test_forgery_signed_by_the_attacker_key_fails_signature_verification(
    mint: TokenMint, trusted_keys: KeyPair
) -> None:
    with pytest.raises(jwt.InvalidSignatureError):
        _strict_decode(mint.signed_by_attacker(SUB), trusted_keys.public_pem)


def test_alg_none_token_is_well_formed_and_refused_when_alg_is_pinned(
    mint: TokenMint, trusted_keys: KeyPair
) -> None:
    token = mint.alg_none(SUB)
    header_b64, payload_b64, signature = token.split(".")
    assert signature == ""  # unsigned
    pad = "=" * (-len(header_b64) % 4)
    assert json.loads(base64.urlsafe_b64decode(header_b64 + pad))["alg"] == "none"
    assert (
        json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))["sub"]
        == SUB
    )
    with pytest.raises(jwt.PyJWTError):
        _strict_decode(token, trusted_keys.public_pem)


def test_hs256_key_confusion_forgery_carries_a_CORRECT_mac_under_the_public_key(
    mint: TokenMint, trusted_keys: KeyPair
) -> None:
    """The forgery must be genuinely dangerous: a verifier that trusts the header's alg and
    uses the public key as an HMAC secret would ACCEPT it. Prove the MAC is right, then prove
    a verifier that pins EdDSA rejects it."""
    token = mint.hs256_key_confusion(SUB)
    signing_input, _, signature = token.rpartition(".")
    expected = hmac.new(
        trusted_keys.public_pem.encode("ascii"), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    got = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    assert hmac.compare_digest(got, expected)
    with pytest.raises(jwt.PyJWTError):
        _strict_decode(token, trusted_keys.public_pem)


def test_truncated_signature_and_tampered_payload_fail(
    mint: TokenMint, trusted_keys: KeyPair
) -> None:
    with pytest.raises(jwt.PyJWTError):
        _strict_decode(mint.truncated_signature(SUB), trusted_keys.public_pem)
    other = "10000000-0000-4000-8000-000000000002"
    tampered = mint.tampered_payload(SUB, other)
    with pytest.raises(jwt.InvalidSignatureError):
        _strict_decode(tampered, trusted_keys.public_pem)


def test_valid_token_claims_cannot_carry_extra_authority_unnoticed(mint: TokenMint) -> None:
    claims = mint.claims(SUB, extra={"role": "owner", "tenant_id": "x"})
    assert claims["role"] == "owner"  # the harness CAN craft them; the app must ignore them


def test_norm_uuid_accepts_both_storage_forms() -> None:
    assert norm_uuid(SUB) == norm_uuid(SUB.replace("-", "")) == SUB


def test_assert_problem_enforces_the_m0_error_contract() -> None:
    body = {
        "type": ProblemDetail.type_for(ErrorCode.AUTH_TOKEN_INVALID),
        "title": "Unauthorized",
        "status": 401,
        "code": "auth.token_invalid",
        "detail": "Authentication is required.",
        "request_id": "5e1b0e0e-3b0a-4b86-8a3e-0f4d1e1d2c3b",
        "errors": [],
    }
    ok = httpx.Response(401, json=body, headers={"content-type": "application/problem+json"})
    assert assert_problem(ok, status=401, code="auth.token_invalid")["code"] == "auth.token_invalid"
    wrong_type = httpx.Response(401, json=body, headers={"content-type": "application/json"})
    with pytest.raises(AssertionError):
        assert_problem(wrong_type, status=401, code="auth.token_invalid")
    with pytest.raises(AssertionError):
        assert_problem(ok, status=403, code="auth.token_invalid")
    leaky = httpx.Response(
        401, json={**body, "echo": "token"}, headers={"content-type": "application/problem+json"}
    )
    with pytest.raises(Exception, match="echo"):  # extra members are a contract violation
        assert_problem(leaky, status=401, code="auth.token_invalid")


def _toy_lab(db: Path, trusted: KeyPair, attacker: KeyPair) -> Lab:
    engine = create_engine(f"sqlite+pysqlite:///{db}")
    with engine.begin() as conn:
        for table in BUSINESS_TABLES:
            conn.execute(text(f"CREATE TABLE {table} (id TEXT PRIMARY KEY, v TEXT)"))
        conn.execute(text("CREATE TABLE audit_events (id INTEGER PRIMARY KEY, reason_code TEXT)"))
    return Lab(httpx.AsyncClient(), engine, TokenMint(trusted, attacker), load_fixtures())


def test_snapshot_detects_a_business_mutation_but_ignores_nothing(
    tmp_path: Path, trusted_keys: KeyPair, attacker_keys: KeyPair
) -> None:
    lab = _toy_lab(tmp_path / "toy.sqlite", trusted_keys, attacker_keys)
    lab.sql("INSERT INTO projects (id, v) VALUES ('p1', 'x')")
    before = lab.snapshot()
    assert lab.snapshot() == before  # stable when nothing changed
    lab.sql("UPDATE projects SET v = 'y' WHERE id = 'p1'")
    after = lab.snapshot()
    assert after != before  # a mutation is visible
    assert after.business != before.business


def test_snapshot_reports_exactly_the_new_audit_rows_and_audit_counts_as_a_change(
    tmp_path: Path, trusted_keys: KeyPair, attacker_keys: KeyPair
) -> None:
    lab = _toy_lab(tmp_path / "toy2.sqlite", trusted_keys, attacker_keys)
    before = lab.snapshot()
    lab.sql("INSERT INTO audit_events (reason_code) VALUES ('authz.forbidden')")
    after = lab.snapshot()
    assert after.business == before.business  # audit is separate from business state
    assert after != before  # but a whole-DB comparison (TL-01) still sees the audit write
    new_rows = after.new_audit_rows(before)
    assert len(new_rows) == 1
    assert new_rows[0]["reason_code"] == "authz.forbidden"


def test_time_is_not_frozen_so_nbf_and_exp_offsets_mean_what_they_say(mint: TokenMint) -> None:
    now = int(time.time())
    claims = mint.claims(SUB, nbf_offset=300, exp_offset=600)
    assert claims["nbf"] - now in range(299, 302)  # type: ignore[operator]
