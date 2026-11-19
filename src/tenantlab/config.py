"""Application settings: public material only.

There is no setting for a private key, a shared secret or a password-bearing default. The database
URL is held as a SecretStr because a production URL may embed credentials (it is never logged).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from tenantlab.auth.tokens import ConfigurationError, load_public_key

__all__ = ["ConfigurationError", "Settings"]

_ENV_PREFIX: Final = "TENANTLAB_"


class Settings(BaseModel):
    """`database_url` is a SYNCHRONOUS SQLAlchemy URL (decision D-15)."""

    # hide_input_in_errors: a validation message must never echo a mistakenly supplied private key.
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    database_url: SecretStr = Field(min_length=1)
    jwt_issuer: str = Field(min_length=1, max_length=256)
    jwt_audience: str = Field(min_length=1, max_length=256)
    jwt_public_key_pem: str = Field(min_length=1, max_length=4096)

    @field_validator("jwt_public_key_pem")
    @classmethod
    def _must_be_an_ed25519_public_key(cls, value: str) -> str:
        load_public_key(value)  # raises ConfigurationError (a ValueError) without echoing input
        return value

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> Settings:
        """Build settings from `TENANTLAB_*` variables. A missing variable is an error."""
        return cls(
            database_url=SecretStr(environ.get(f"{_ENV_PREFIX}DATABASE_URL", "")),
            jwt_issuer=environ.get(f"{_ENV_PREFIX}JWT_ISSUER", ""),
            jwt_audience=environ.get(f"{_ENV_PREFIX}JWT_AUDIENCE", ""),
            jwt_public_key_pem=environ.get(f"{_ENV_PREFIX}JWT_PUBLIC_KEY_PEM", ""),
        )
