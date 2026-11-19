"""Strict identifier parsing: exactly one spelling per resource."""

from __future__ import annotations

import uuid

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tenantlab.ids import parse_uuid4

CANONICAL = "2000000a-0000-4000-8000-00000000000b"  # hex letters: upper-casing changes it


def test_a_canonical_lowercase_uuid4_parses() -> None:
    assert parse_uuid4(CANONICAL) == uuid.UUID(CANONICAL)


@pytest.mark.parametrize(
    "value",
    [
        CANONICAL.upper(),
        CANONICAL.replace("-", ""),
        f"{{{CANONICAL}}}",
        f"urn:uuid:{CANONICAL}",
        f" {CANONICAL}",
        f"{CANONICAL} ",
        f"{CANONICAL}\n",
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",  # a version-1 UUID
        "00000000-0000-0000-0000-000000000000",  # the nil UUID
        "20000000-0000-4000-8000-00000000000g",
        "",
        "not-a-uuid",
        "x" * 5000,
        # full-width digits: str.isdigit() and a loose regex would accept them
        "\uff12\uff10\uff10\uff10\uff10\uff10\uff10\uff10-0000-4000-8000-000000000001",
    ],
)
def test_every_other_spelling_is_refused(value: str) -> None:
    assert parse_uuid4(value) is None


@pytest.mark.parametrize("value", [None, 1, 1.5, b"x", CANONICAL.encode(), uuid.UUID(CANONICAL)])
def test_a_non_string_is_refused(value: object) -> None:
    assert parse_uuid4(value) is None


@settings(max_examples=300, deadline=None)
@given(st.uuids(version=4))
def test_every_canonical_uuid4_round_trips(value: uuid.UUID) -> None:
    assert parse_uuid4(str(value)) == value


@settings(max_examples=300, deadline=None)
@given(st.text())
def test_parsing_never_raises_and_only_accepts_the_canonical_spelling(value: str) -> None:
    parsed = parse_uuid4(value)
    if parsed is not None:
        assert str(parsed) == value
        assert parsed.version == 4
