"""The TL-01..TL-20 catalog must match the spec's matrix and milestone plan."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tenantlab.oracle.catalog import CatalogCase, load_catalog

REPO = Path(__file__).resolve().parents[2]

# Second encoding of spec s10 (milestone plan) + s9 ("Include TL-17", "Postgres TL-12/20").
FIRST_MILESTONE = {
    **dict.fromkeys(["TL-01", "TL-02", "TL-03", "TL-04", "TL-05", "TL-14", "TL-18"], "M1"),
    **dict.fromkeys(
        ["TL-06", "TL-07", "TL-08", "TL-09", "TL-10", "TL-11", "TL-12", "TL-13", "TL-15", "TL-19"],
        "M2",
    ),
    "TL-16": "M3",  # M3 builds the vulnerable lab; its isolation guard is TL-16
    "TL-17": "M4",
    "TL-20": "M5",
}


@pytest.fixture(scope="module")
def cases() -> dict[str, CatalogCase]:
    return {c.id: c for c in load_catalog()}


def test_exactly_twenty_cases_tl01_to_tl20(cases: dict[str, CatalogCase]) -> None:
    assert sorted(cases) == [f"TL-{n:02d}" for n in range(1, 21)]


def test_first_milestone_matches_the_spec_plan(cases: dict[str, CatalogCase]) -> None:
    assert {cid: c.milestones[0] for cid, c in cases.items()} == FIRST_MILESTONE


def test_postgres_concurrency_cases_are_scheduled_for_m5(cases: dict[str, CatalogCase]) -> None:
    assert "M5" in cases["TL-12"].milestones
    assert "M5" in cases["TL-20"].milestones


def test_every_case_states_concrete_falsifiable_evidence(cases: dict[str, CatalogCase]) -> None:
    for case in cases.values():
        assert len(case.expected) >= 60, case.id
        assert case.test_modules or case.state == "planned", case.id


def test_cases_that_forbid_mutation_require_unchanged_state_evidence(
    cases: dict[str, CatalogCase],
) -> None:
    """A status code alone never proves safety: the spec says a 403 may hide a write (TL-17).
    Every no-mutation case must say that state is compared (unchanged/identical/atomic)."""
    exempt = {"TL-16", "TL-17"}  # TL-16 is a startup guard; TL-17 IS the state-diff case
    for case in cases.values():
        if not case.mutation_allowed and case.id not in exempt:
            text = case.expected.lower()
            assert any(w in text for w in ("unchanged", "identical", "atomic")), case.id


def test_red_cases_have_real_test_functions_that_name_them(cases: dict[str, CatalogCase]) -> None:
    for case in cases.values():
        if case.state != "red":
            continue
        prefix = f"test_{case.id.lower().replace('-', '')}_"  # TL-01 -> test_tl01_
        found = False
        for module in case.test_modules:
            path = REPO / module
            assert path.is_file(), f"{case.id}: {module} does not exist"
            tree = ast.parse(path.read_text(encoding="utf-8"))
            found |= any(
                isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name.startswith(prefix)
                for n in ast.walk(tree)
            )
        assert found, f"{case.id}: no test function starting with {prefix!r}"


def test_the_m1_red_set_is_exactly_the_m1_cases(cases: dict[str, CatalogCase]) -> None:
    red = {cid for cid, c in cases.items() if c.state == "red"}
    assert red == {cid for cid, m in FIRST_MILESTONE.items() if m == "M1"}
