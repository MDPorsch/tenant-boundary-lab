"""Loader for the TL-01..TL-20 case catalog (oracle/data/case_catalog.toml)."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from importlib import resources
from typing import Final, Literal

from tenantlab.oracle.matrix import OracleDataError

# OWASP API Security Top 10:2023 identifiers (plus "n/a" for data-integrity/race cases).
OWASP_API_2023: Final = frozenset({f"API{n}:2023" for n in range(1, 11)} | {"n/a"})
MILESTONES: Final = frozenset({"M1", "M2", "M3", "M4", "M5", "M6"})
_ID_RE: Final = re.compile(r"^TL-(0[1-9]|1[0-9]|20)$")

CaseState = Literal["red", "planned"]


@dataclass(frozen=True, slots=True)
class CatalogCase:
    id: str
    title: str
    owasp: tuple[str, ...]
    milestones: tuple[str, ...]
    state: CaseState
    mutation_allowed: bool
    test_modules: tuple[str, ...]
    expected: str


def _str_tuple(case_id: str, key: str, value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise OracleDataError(f"{case_id}: {key} must be a list of strings")
    return tuple(value)


def load_catalog() -> tuple[CatalogCase, ...]:
    """Load and validate the packaged case catalog."""
    text = (
        resources.files("tenantlab.oracle")
        .joinpath("data", "case_catalog.toml")
        .read_text(encoding="utf-8")
    )
    return parse_catalog(text)


def parse_catalog(text: str) -> tuple[CatalogCase, ...]:
    """Parse catalog TOML. Anything malformed raises OracleDataError."""
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise OracleDataError(f"case_catalog.toml: invalid TOML: {exc}") from exc
    cases_raw = raw.get("cases")
    if not isinstance(cases_raw, list) or not cases_raw:
        raise OracleDataError("case_catalog.toml: no [[cases]]")
    cases: list[CatalogCase] = []
    seen: set[str] = set()
    for item in cases_raw:
        case_id = item.get("id")
        if not isinstance(case_id, str) or not _ID_RE.match(case_id) or case_id in seen:
            raise OracleDataError(f"case_catalog.toml: bad or duplicate id {case_id!r}")
        seen.add(case_id)
        owasp = _str_tuple(case_id, "owasp", item.get("owasp"))
        milestones = _str_tuple(case_id, "milestones", item.get("milestones"))
        modules = _str_tuple(case_id, "test_modules", item.get("test_modules"))
        state = item.get("state")
        expected = item.get("expected")
        title = item.get("title")
        mutation = item.get("mutation_allowed")
        if not owasp or not set(owasp) <= OWASP_API_2023:
            raise OracleDataError(f"{case_id}: unknown OWASP id in {owasp!r}")
        if not milestones or not set(milestones) <= MILESTONES:
            raise OracleDataError(f"{case_id}: unknown milestone in {milestones!r}")
        if state not in ("red", "planned"):
            raise OracleDataError(f"{case_id}: bad state {state!r}")
        if not isinstance(expected, str) or len(expected) < 40:
            raise OracleDataError(f"{case_id}: 'expected' must be a concrete statement")
        if not isinstance(title, str) or not title:
            raise OracleDataError(f"{case_id}: missing title")
        if not isinstance(mutation, bool):
            raise OracleDataError(f"{case_id}: mutation_allowed must be a bool")
        cases.append(
            CatalogCase(case_id, title, owasp, milestones, state, mutation, modules, expected)
        )
    return tuple(cases)
