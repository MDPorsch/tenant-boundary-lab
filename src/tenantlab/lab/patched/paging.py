"""Keyset pagination: `limit` and an opaque `cursor` (docs/api-contract.md s10.2, D-33).

The cursor is the base64url of the LAST id returned. It is not signed: it can only move the start
point inside the caller's own readable set, so it reveals nothing about ids the caller may not see.
Parsing is strict: ASCII digits only, canonical encoding only, no sign, no padding, no repeats.
"""

from __future__ import annotations

import base64
import binascii
import re
import uuid
from collections.abc import Mapping
from typing import Final

from tenantlab.ids import parse_uuid4
from tenantlab.schemas.errors import FieldError

DEFAULT_LIMIT: Final = 25
MAX_LIMIT: Final = 100
MAX_CURSOR_CHARS: Final = 256

_LIMIT: Final = re.compile(r"[1-9][0-9]{0,2}")
_CURSOR: Final = re.compile(r"[A-Za-z0-9_-]{1,256}")
_INT_CURSOR: Final = re.compile(r"[1-9][0-9]{0,17}")


class QueryError(Exception):
    """A query value is invalid. Carries the field error to report (never the value)."""

    def __init__(self, field: str, code: str) -> None:
        super().__init__(f"{field}:{code}")
        self.error = FieldError(loc=("query", field), code=code)


def encode_cursor(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("ascii")).rstrip(b"=").decode("ascii")


def _decode(raw: str) -> str:
    if _CURSOR.fullmatch(raw) is None:
        raise QueryError("cursor", "invalid_cursor")
    try:
        text = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("ascii")
    except (binascii.Error, UnicodeDecodeError):
        raise QueryError("cursor", "invalid_cursor") from None
    if encode_cursor(text) != raw:  # reject non-canonical encodings of the same bytes
        raise QueryError("cursor", "invalid_cursor")
    return text


def uuid_cursor(raw: str) -> uuid.UUID:
    parsed = parse_uuid4(_decode(raw))
    if parsed is None:
        raise QueryError("cursor", "invalid_cursor")
    return parsed


def int_cursor(raw: str) -> int:
    text = _decode(raw)
    if _INT_CURSOR.fullmatch(text) is None:
        raise QueryError("cursor", "invalid_cursor")
    return int(text)


def parse_limit(params: Mapping[str, str]) -> int:
    raw = params.get("limit")
    if raw is None:
        return DEFAULT_LIMIT
    if _LIMIT.fullmatch(raw) is None or int(raw) > MAX_LIMIT:
        raise QueryError("limit", "invalid_limit")
    return int(raw)
