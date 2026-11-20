"""The five controlled flaws. Each is an independent switch (decisions D-42 and D-53).

Importing this module is harmless: nothing here is vulnerable by itself.
"""

from __future__ import annotations

from enum import StrEnum


class Flaw(StrEnum):
    #: API1 BOLA. The membership lookup is not filtered by the object's tenant: the principal's
    #: highest active role in ANY tenant is used.
    TENANT_PREDICATE_OMITTED = "tenant_predicate_omitted"
    #: API5 BFLA. The capability (role) gate is skipped.
    ROLE_CHECK_MISSING = "role_check_missing"
    #: API3 BOPLA. The general project JSON embeds each contact's private e-mail and phone.
    PRIVATE_PROPERTY_SERIALIZED = "private_property_serialized"
    #: API1. The market-access gate is skipped (hidden-market objects are reachable and counted).
    MARKET_BOUNDARY_OMITTED = "market_boundary_omitted"
    #: API5 / API1 (TL-17). The project PATCH is applied and COMMITTED before the authorization
    #: check runs, which then answers 403 or 404 as usual: the status code is exactly what a correct
    #: app returns, but the row has changed. Only a state diff can see it.
    WRITE_BEFORE_AUTHORIZATION = "write_before_authorization"


ALL_FLAWS = frozenset(Flaw)


def parse_flaws(text: str) -> frozenset[Flaw]:
    """`all`, `none`, or a comma-separated list of flaw NAMES (case-insensitive). Anything else
    is an error: a typo must not silently run a differently broken lab."""
    value = text.strip()
    if value.lower() == "all":
        return ALL_FLAWS
    if value.lower() in ("none", ""):
        return frozenset()
    chosen: set[Flaw] = set()
    for part in value.split(","):
        try:
            chosen.add(Flaw[part.strip().upper()])
        except KeyError:
            raise ValueError(f"unknown flaw {part.strip()!r}") from None
    return frozenset(chosen)
