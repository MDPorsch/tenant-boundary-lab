"""Bearer-token verification (decision D-03, docs/api-contract.md s4).

* Algorithm is EdDSA (Ed25519) only and is pinned HERE, never taken from the token header.
* The verifier holds a PUBLIC key only. A private key is refused at construction.
* Required claims: sub, jti, iss, aud, iat, nbf, exp. iss/aud must equal the configured values
  exactly; leeway is zero; exp - iat must not exceed 900 seconds; sub must be a canonical UUIDv4.
* Every other claim (role, tenant_id, scope, ...) is ignored: authority comes from the database.

A rejection carries an internal `reason` for the log line. It is never sent to the client: every
failure looks the same on the wire (401 auth.token_invalid).
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any, Final

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tenantlab.ids import parse_uuid4

ALGORITHM: Final = "EdDSA"
MAX_TOKEN_LIFETIME_SECONDS: Final = 900
MAX_TOKEN_CHARS: Final = 2048
REQUIRED_CLAIMS: Final = ("sub", "jti", "iss", "aud", "iat", "nbf", "exp")
_COMPACT_JWS: Final = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


class ConfigurationError(ValueError):
    """The service is misconfigured. It must refuse to start rather than run insecurely."""


class TokenError(Exception):
    """A token was rejected. `reason` is for logs only and is never returned to a client."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    subject: uuid.UUID
    jti: str
    issued_at: int
    expires_at: int


def load_public_key(pem: str) -> Ed25519PublicKey:
    """Parse an Ed25519 PUBLIC key. Anything else (private key, RSA, EC, garbage) is refused.

    The error text never contains the input, so a private key pasted by mistake is not echoed.
    """
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except (ValueError, TypeError, UnicodeEncodeError):
        raise ConfigurationError(
            "jwt_public_key_pem is not a PEM-encoded public key (a private key must never be "
            "configured)"
        ) from None
    if not isinstance(key, Ed25519PublicKey):
        raise ConfigurationError("jwt_public_key_pem must be an Ed25519 public key")
    return key


def _is_int(value: object) -> bool:
    return type(value) is int  # bool is an int subclass; a float NumericDate is refused too


class TokenVerifier:
    def __init__(self, public_key: Ed25519PublicKey, issuer: str, audience: str) -> None:
        if not issuer or not audience:
            raise ConfigurationError("issuer and audience must be configured")
        self._key = public_key
        self._issuer = issuer
        self._audience = audience

    def verify(self, token: str) -> VerifiedToken:
        if len(token) > MAX_TOKEN_CHARS or _COMPACT_JWS.fullmatch(token) is None:
            raise TokenError("malformed")
        claims = self._decode(token)
        return self._check_claims(claims)

    def _decode(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise TokenError("malformed") from None
        if header.get("alg") != ALGORITHM:
            raise TokenError("alg_not_allowed")
        try:
            return jwt.decode(
                token,
                self._key,
                algorithms=[ALGORITHM],
                audience=self._audience,
                issuer=self._issuer,
                leeway=0,
                options={"require": list(REQUIRED_CLAIMS)},
            )
        except jwt.ExpiredSignatureError:
            raise TokenError("expired") from None
        except jwt.ImmatureSignatureError:
            raise TokenError("not_yet_valid") from None
        except jwt.InvalidIssuerError:
            raise TokenError("bad_issuer") from None
        except jwt.InvalidAudienceError:
            raise TokenError("bad_audience") from None
        except jwt.MissingRequiredClaimError:
            raise TokenError("missing_claim") from None
        except jwt.InvalidSignatureError:
            raise TokenError("bad_signature") from None
        except jwt.exceptions.InvalidSubjectError:
            raise TokenError("bad_subject") from None
        except jwt.exceptions.InvalidJTIError:
            raise TokenError("bad_jti") from None
        except jwt.exceptions.InvalidIssuedAtError:
            raise TokenError("bad_time_claim") from None
        except jwt.PyJWTError:
            raise TokenError("malformed") from None

    def _check_claims(self, claims: dict[str, Any]) -> VerifiedToken:
        # Defence in depth: re-assert what the library already checked, and add the rules it
        # does not know (single-string aud, integer times, lifetime cap, UUID subject).
        if claims.get("iss") != self._issuer or claims.get("aud") != self._audience:
            raise TokenError("bad_issuer_or_audience")
        iat, exp = claims.get("iat"), claims.get("exp")
        if not (_is_int(iat) and _is_int(exp) and _is_int(claims.get("nbf"))):
            raise TokenError("bad_time_claim")
        assert isinstance(iat, int)  # noqa: S101 - narrowing for the type checker only
        assert isinstance(exp, int)  # noqa: S101
        if exp <= iat or exp - iat > MAX_TOKEN_LIFETIME_SECONDS:
            raise TokenError("lifetime")
        subject = parse_uuid4(claims.get("sub"))
        jti = claims.get("jti")
        if subject is None:
            raise TokenError("bad_subject")
        if not isinstance(jti, str) or not jti or len(jti) > 128:
            raise TokenError("bad_jti")
        return VerifiedToken(subject, jti, iat, exp)
