"""Settings carry public material only, and a misconfiguration stops the service from starting."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import ValidationError

from tenantlab.auth.tokens import ConfigurationError, load_public_key
from tenantlab.config import Settings
from tests.harness import AUDIENCE, ISSUER, KeyPair, generate_keypair

URL = "sqlite+pysqlite:////tmp/never-opened.sqlite"


def _settings(pem: str, **overrides: str) -> Settings:
    values = {
        "database_url": URL,
        "jwt_issuer": ISSUER,
        "jwt_audience": AUDIENCE,
        "jwt_public_key_pem": pem,
        **overrides,
    }
    return Settings(**values)  # type: ignore[arg-type]


def _private_pem(keys: KeyPair) -> str:
    return keys.private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def test_valid_settings_are_accepted(trusted_keys: KeyPair) -> None:
    settings = _settings(trusted_keys.public_pem)
    assert settings.jwt_issuer == ISSUER
    assert settings.database_url.get_secret_value() == URL


def test_the_database_url_is_never_shown_in_a_repr(trusted_keys: KeyPair) -> None:
    secret_url = "postgresql+psycopg://user:hunter2@db.invalid/app"
    settings = _settings(trusted_keys.public_pem, database_url=secret_url)
    assert "hunter2" not in repr(settings)
    assert "hunter2" not in str(settings)
    assert "hunter2" not in settings.model_dump_json()


def test_a_private_key_is_refused_and_never_echoed(trusted_keys: KeyPair) -> None:
    private_pem = _private_pem(trusted_keys)
    with pytest.raises(ValidationError) as caught:
        _settings(private_pem)
    message = str(caught.value)
    assert "PRIVATE KEY" not in message
    body = "".join(private_pem.splitlines()[1:-1])
    assert body[:20] not in message


def test_a_private_key_is_refused_by_the_loader_too(trusted_keys: KeyPair) -> None:
    with pytest.raises(ConfigurationError):
        load_public_key(_private_pem(trusted_keys))


@pytest.mark.parametrize(
    "make",
    [
        lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
        lambda: ec.generate_private_key(ec.SECP256R1()),
    ],
    ids=["rsa", "ec_p256"],
)
def test_only_ed25519_public_keys_are_accepted(make: object) -> None:
    key = make()  # type: ignore[operator]
    pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    with pytest.raises(ConfigurationError, match="Ed25519"):
        load_public_key(pem)
    with pytest.raises(ValidationError):
        _settings(pem)


@pytest.mark.parametrize(
    "junk", ["", "not a pem", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"]
)
def test_garbage_is_refused(junk: str) -> None:
    with pytest.raises((ConfigurationError, ValidationError)):
        load_public_key(junk)
    with pytest.raises(ValidationError):
        _settings(junk)


@pytest.mark.parametrize("field", ["database_url", "jwt_issuer", "jwt_audience"])
def test_an_empty_required_value_is_refused(trusted_keys: KeyPair, field: str) -> None:
    with pytest.raises(ValidationError):
        _settings(trusted_keys.public_pem, **{field: ""})


def test_unknown_settings_are_refused(trusted_keys: KeyPair) -> None:
    with pytest.raises(ValidationError):
        Settings(  # type: ignore[call-arg]
            database_url=URL,
            jwt_issuer=ISSUER,
            jwt_audience=AUDIENCE,
            jwt_public_key_pem=trusted_keys.public_pem,
            jwt_private_key_pem="must not exist",
        )


def test_settings_are_immutable(trusted_keys: KeyPair) -> None:
    settings = _settings(trusted_keys.public_pem)
    with pytest.raises(ValidationError):
        settings.jwt_issuer = "https://other.invalid"  # type: ignore[misc]


def test_from_env_reads_the_four_variables(trusted_keys: KeyPair) -> None:
    env = {
        "TENANTLAB_DATABASE_URL": URL,
        "TENANTLAB_JWT_ISSUER": ISSUER,
        "TENANTLAB_JWT_AUDIENCE": AUDIENCE,
        "TENANTLAB_JWT_PUBLIC_KEY_PEM": trusted_keys.public_pem,
    }
    assert Settings.from_env(env).jwt_audience == AUDIENCE


@pytest.mark.parametrize(
    "missing",
    [
        "TENANTLAB_DATABASE_URL",
        "TENANTLAB_JWT_ISSUER",
        "TENANTLAB_JWT_AUDIENCE",
        "TENANTLAB_JWT_PUBLIC_KEY_PEM",
    ],
)
def test_from_env_with_a_missing_variable_refuses_to_start(
    trusted_keys: KeyPair, missing: str
) -> None:
    env = {
        "TENANTLAB_DATABASE_URL": URL,
        "TENANTLAB_JWT_ISSUER": ISSUER,
        "TENANTLAB_JWT_AUDIENCE": AUDIENCE,
        "TENANTLAB_JWT_PUBLIC_KEY_PEM": trusted_keys.public_pem,
    }
    del env[missing]
    with pytest.raises(ValidationError):
        Settings.from_env(env)


def test_fresh_keys_are_independent() -> None:
    assert generate_keypair().public_pem != generate_keypair().public_pem
