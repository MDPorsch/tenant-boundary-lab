"""Identifier parsing shared by the token verifier and the request gates.

Every identifier in the API is a canonical lowercase UUIDv4 (docs/api-contract.md s1). Parsing is
strict on purpose: `uuid.UUID()` alone also accepts upper case, braces, a `urn:uuid:` prefix and
missing hyphens, which would give one resource several spellings.
"""

from __future__ import annotations

import re
import uuid
from typing import Final

_CANONICAL: Final = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def parse_uuid4(value: object) -> uuid.UUID | None:
    """Return the UUID if `value` is a canonical lowercase UUIDv4 string, otherwise None."""
    if not isinstance(value, str) or _CANONICAL.fullmatch(value) is None:
        return None
    parsed = uuid.UUID(value)
    return parsed if parsed.version == 4 else None
