"""Behavioural test harness (independent of the application's own auth/policy code).

Independence (spec s5: "avoid coupling test expected result to the same helper that enforces
it"):
* Tokens are minted here with PyJWT + cryptography. The app's verifier is never imported.
* Database state is read with raw SQL, table names taken from the spec's relational model.
* Expected outcomes come from the oracle DATA (CSV/TOML) and the case catalog, not app code.

The only application imports live in :func:`build_lab`. While the code does not exist (M0) they
fail the CALLING TEST with an explicit message. A red test is a visible, honest gap; it is never
skipped, xfailed or turned green by weakening the assertion.

The interface the application must provide (see docs/api-contract.md s9):

    tenantlab.config.Settings(database_url, jwt_issuer, jwt_audience, jwt_public_key_pem)
    tenantlab.db.migrate.upgrade_to_head(database_url) -> None
    tenantlab.db.seed.seed_fixtures(database_url) -> None     # loads lab/fixtures/fixtures.toml
    tenantlab.api.app.create_app(settings) -> ASGI application
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine, create_engine, text

from tenantlab.lab.fixtures.loader import Fixtures, load_fixtures
from tenantlab.schemas.errors import PROBLEM_MEDIA_TYPE, ProblemDetail

#: `TENANTLAB_TEST_DB=postgres` runs `build_lab` on PostgreSQL (needs Docker), not SQLite.
DB_SWITCH: Final = "TENANTLAB_TEST_DB"
ISSUER: Final = "https://issuer.tenantlab.invalid"
AUDIENCE: Final = "tenantlab-api"
BASE_URL: Final = "http://tenantlab.invalid"  # reserved TLD; ASGITransport never opens a socket
MAX_TOKEN_LIFETIME_SECONDS: Final = 900

BUSINESS_TABLES: Final = (
    "principals",
    "tenants",
    "memberships",
    "markets",
    "tenant_market_access",
    "projects",
    "invoices",
    "project_contacts",
)


# --------------------------------------------------------------------- tokens ----


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64json(obj: Mapping[str, Any]) -> str:
    return _b64(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


@dataclass(frozen=True)
class KeyPair:
    private: Ed25519PrivateKey
    public_pem: str


def generate_keypair() -> KeyPair:
    """Ephemeral Ed25519 key. Never written to disk, never committed, never logged."""
    private = Ed25519PrivateKey.generate()
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return KeyPair(private, pem.decode("ascii"))


class TokenMint:
    """Mints trusted and hostile tokens. Offsets are seconds relative to 'now'."""

    def __init__(self, trusted: KeyPair, attacker: KeyPair) -> None:
        self._trusted = trusted
        self._attacker = attacker

    def claims(
        self,
        sub: str,
        *,
        iat_offset: int = 0,
        nbf_offset: int = 0,
        exp_offset: int = 300,
        iss: str = ISSUER,
        aud: str = AUDIENCE,
        omit: Iterable[str] = (),
        extra: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": sub,
            "jti": str(uuid.uuid4()),
            "iss": iss,
            "aud": aud,
            "iat": now + iat_offset,
            "nbf": now + nbf_offset,
            "exp": now + exp_offset,
        }
        claims.update(extra or {})
        for name in omit:
            claims.pop(name, None)
        return claims

    def mint(self, sub: str, **kwargs: Any) -> str:
        """A correctly signed token (trusted key, EdDSA) with the requested claim variations."""
        return jwt.encode(self.claims(sub, **kwargs), self._trusted.private, algorithm="EdDSA")

    def signed_by_attacker(self, sub: str) -> str:
        return jwt.encode(self.claims(sub), self._attacker.private, algorithm="EdDSA")

    def alg_none(self, sub: str) -> str:
        header = {"alg": "none", "typ": "JWT"}
        return f"{_b64json(header)}.{_b64json(self.claims(sub))}."

    def hs256_key_confusion(self, sub: str) -> str:
        """Classic algorithm-confusion forgery: HMAC-sign with the PUBLIC key as the secret."""
        signing_input = f"{_b64json({'alg': 'HS256', 'typ': 'JWT'})}.{_b64json(self.claims(sub))}"
        mac = hmac.new(
            self._trusted.public_pem.encode("ascii"), signing_input.encode("ascii"), hashlib.sha256
        )
        return f"{signing_input}.{_b64(mac.digest())}"

    def truncated_signature(self, sub: str) -> str:
        return self.mint(sub)[:-12]

    def tampered_payload(self, sub: str, other_sub: str) -> str:
        """Valid signature for `sub`, payload swapped to `other_sub`: signature must not verify."""
        header, _payload, signature = self.mint(sub).split(".")
        return f"{header}.{_b64json(self.claims(other_sub))}.{signature}"


# ------------------------------------------------------------------- database ----


@dataclass(frozen=True)
class Snapshot:
    business: dict[str, tuple[tuple[object, ...], ...]]
    audit: tuple[dict[str, object], ...]

    def new_audit_rows(self, before: Snapshot) -> tuple[dict[str, object], ...]:
        return self.audit[len(before.audit) :]


def norm_uuid(value: object) -> str:
    """UUIDs may be stored as 36-char or 32-char hex: compare canonical form."""
    return str(uuid.UUID(str(value)))


# ------------------------------------------------------------------------ lab ----


@dataclass
class Lab:
    client: httpx.AsyncClient
    engine: Engine
    mint: TokenMint
    fx: Fixtures
    #: run on `aclose`, e.g. the app's lifespan shutdown, which disposes ITS connection pool
    on_close: list[Callable[[], Awaitable[object]]] = field(default_factory=list)

    def token(self, principal_key: str, **kwargs: Any) -> str:
        return self.mint.mint(self.fx.principal(principal_key).id, **kwargs)

    def bearer(self, principal_key: str, **kwargs: Any) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token(principal_key, **kwargs)}"}

    async def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        json_body: object | None = None,
        content: bytes | None = None,
        params: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        return await self.client.request(
            method, path, headers=headers, json=json_body, content=content, params=params
        )

    def snapshot(self) -> Snapshot:
        with self.engine.connect() as conn:
            business = {
                table: tuple(
                    tuple(row)
                    for row in conn.execute(text(f"SELECT * FROM {table} ORDER BY 1"))  # noqa: S608 - constant table names
                )
                for table in BUSINESS_TABLES
            }
            audit = tuple(
                dict(row._mapping)
                # `id` is the rowid alias on SQLite and a bigserial on PostgreSQL
                for row in conn.execute(text("SELECT * FROM audit_events ORDER BY id"))
            )
        return Snapshot(business, audit)

    def drop_table(self, table: str) -> None:
        """Drop a table to simulate a database failure (callers pass constant names only)."""
        self.sql(
            f"DROP TABLE {table}" + ("" if self.engine.dialect.name == "sqlite" else " CASCADE")
        )

    def sql(self, statement: str, **params: object) -> None:
        """Direct DB write by a test, modelling an out-of-band state change (revocation,
        suspension). It bypasses the application on purpose."""
        with self.engine.begin() as conn:
            conn.execute(text(statement), params)

    # Out-of-band state changes use NATURAL keys (email, slug) so they do not depend on how the
    # application stores UUIDs (36-char vs 32-char hex).
    def set_membership(
        self, principal: str, tenant: str, *, role: str | None = None, status: str | None = None
    ) -> None:
        email = self.fx.principal(principal).email
        slug = self.fx.tenant(tenant).slug
        if role is not None:
            self.sql(
                "UPDATE memberships SET role = :v "
                "WHERE principal_id = (SELECT id FROM principals WHERE email = :email) "
                "AND tenant_id = (SELECT id FROM tenants WHERE slug = :slug)",
                v=role,
                email=email,
                slug=slug,
            )
        if status is not None:
            self.sql(
                "UPDATE memberships SET status = :v "
                "WHERE principal_id = (SELECT id FROM principals WHERE email = :email) "
                "AND tenant_id = (SELECT id FROM tenants WHERE slug = :slug)",
                v=status,
                email=email,
                slug=slug,
            )

    def set_tenant_state(self, tenant: str, state: str) -> None:
        self.sql(
            "UPDATE tenants SET state = :v WHERE slug = :slug",
            v=state,
            slug=self.fx.tenant(tenant).slug,
        )

    async def aclose(self) -> None:
        await self.client.aclose()
        for closer in self.on_close:
            await closer()
        self.engine.dispose()


async def build_lab(
    db_file: Path, trusted: KeyPair, attacker: KeyPair, *, postgres: bool = False
) -> Lab:
    """Create a migrated, seeded lab app. Fails the calling test while it is not built."""
    try:
        from tenantlab.api.app import create_app  # noqa: PLC0415
        from tenantlab.config import Settings  # noqa: PLC0415
        from tenantlab.db.migrate import upgrade_to_head  # noqa: PLC0415
        from tenantlab.db.seed import seed_fixtures  # noqa: PLC0415
    except ImportError as exc:
        pytest.fail(
            f"NOT IMPLEMENTED (milestone M1): lab interface missing: {exc}. "
            "This red test specifies behaviour that the next milestone must provide; "
            "see docs/api-contract.md section 9.",
            pytrace=False,
        )
    url = f"sqlite+pysqlite:///{db_file}"
    if postgres or os.environ.get(DB_SWITCH) == "postgres":
        # M5: the very same suite against a real PostgreSQL database (one fresh database per lab)
        from tests.pgserver import server  # noqa: PLC0415

        url = server().new_database_url()
    settings = Settings(
        database_url=url,
        jwt_issuer=ISSUER,
        jwt_audience=AUDIENCE,
        jwt_public_key_pem=trusted.public_pem,
    )
    upgrade_to_head(url)
    seed_fixtures(url)
    app = create_app(settings)
    # ASGITransport does not run the app's lifespan, so the app's connection pool would never be
    # disposed. On SQLite (NullPool) that is invisible; on PostgreSQL every test leaked its pool.
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)
    lab = Lab(client, create_engine(url), TokenMint(trusted, attacker), load_fixtures())
    lab.on_close.append(lambda: lifespan.__aexit__(None, None, None))
    return lab


# ----------------------------------------------------------------- assertions ----


def assert_problem(response: httpx.Response, *, status: int, code: str) -> dict[str, Any]:
    """Assert an RFC 9457 problem body that satisfies the M0 schema, and return it."""
    assert response.status_code == status, (
        f"expected {status}, got {response.status_code}: {response.text[:300]}"
    )
    assert response.headers["content-type"].split(";")[0].strip() == PROBLEM_MEDIA_TYPE
    body = response.json()
    ProblemDetail.model_validate(body)  # strict contract from M0 (extra members forbidden)
    assert body["code"] == code
    assert body["status"] == status
    assert isinstance(body, dict)
    return body


def assert_no_leak(
    text_body: str,
    fx: Fixtures,
    *,
    forbidden_tenants: Iterable[str] = (),
    allow_private: bool = False,
) -> None:
    """No private sentinel, no synthetic e-mail, no sentinel of a tenant the actor may not see."""
    if not allow_private:
        assert fx.private_sentinel not in text_body, "private contact data leaked"
    assert "@tenantlab.invalid" not in text_body, "a synthetic e-mail address leaked"
    for tenant in forbidden_tenants:
        assert f"{fx.tenant_sentinel_prefix}{tenant}" not in text_body, (
            f"tenant {tenant} data leaked"
        )


def body_sans_request_id(body: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in body.items() if k != "request_id"}


def assert_single_deny_audit(
    lab: Lab,
    before: Snapshot,
    response: httpx.Response,
    *,
    actor: str,
    tenant: str | None,
    action: str,
    resource_type: str,
    reason_code: str,
) -> Snapshot:
    """A denial changes NO business data and writes exactly one audit row (docs/api-contract.md
    s6). `tenant=None` means tenant_id must be NULL (never pollute a tenant's audit log).
    Returns the new snapshot."""
    after = lab.snapshot()
    assert after.business == before.business, "a denied request mutated business data"
    rows = after.new_audit_rows(before)
    assert len(rows) == 1, f"expected exactly one audit row, got {len(rows)}: {rows}"
    row = rows[0]
    assert norm_uuid(row["actor_id"]) == actor
    if tenant is None:
        assert row["tenant_id"] is None, "audit row must not be attributed to a tenant"
    else:
        assert norm_uuid(row["tenant_id"]) == tenant
    assert row["decision"] == "deny"
    assert row["reason_code"] == reason_code
    assert row["action"] == action
    assert row["resource_type"] == resource_type
    assert norm_uuid(row["correlation_id"]) == response.json()["request_id"]
    return after
