"""The human-readable docs must agree with the machine-readable policy.

Reviewers approve the Markdown; the tests judge the CSV/TOML. If the two could drift, an owner could
approve one policy while the tests enforce another. Tables are parsed and compared cell by cell.
"""

from __future__ import annotations

import re
from pathlib import Path

from tenantlab.oracle.catalog import load_catalog
from tenantlab.oracle.matrix import Role, load_capabilities, load_gates
from tenantlab.schemas.errors import ErrorCode

DOCS = Path(__file__).resolve().parents[2] / "docs"


def _rows(markdown: str, first_cell: re.Pattern[str]) -> list[list[str]]:
    """Table rows whose first cell matches, split into stripped cells."""
    out: list[list[str]] = []
    for line in markdown.splitlines():
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if cells and first_cell.fullmatch(cells[0]):
                out.append(cells)
    return out


def _tick(cell: str) -> str:
    return cell.strip("`")


def test_capability_table_in_docs_equals_the_csv() -> None:
    text = (DOCS / "authorization-matrix.md").read_text(encoding="utf-8")
    rows = _rows(text, re.compile(r"`[a-z.]+`"))
    docs = {_tick(r[0]): (_tick(r[1]), [c == "Y" for c in r[2:6]]) for r in rows if len(r) == 6}
    csv_rules = {r.operation: r for r in load_capabilities().rules}
    assert set(docs) == set(csv_rules)
    for operation, (capability, flags) in docs.items():
        rule = csv_rules[operation]
        assert capability == rule.capability
        order = [Role.OWNER, Role.ADMIN, Role.EDITOR, Role.VIEWER]  # column order in the doc
        assert flags == [role in rule.allowed_roles for role in order], operation


def test_gate_table_in_docs_equals_the_csv() -> None:
    text = (DOCS / "authorization-matrix.md").read_text(encoding="utf-8")
    rows = _rows(text, re.compile(r"\d+"))
    docs = {int(r[0]): r for r in rows if len(r) == 5}
    gates = {g.order: g for g in load_gates()}
    assert set(docs) == set(gates)
    for order, row in docs.items():
        gate = gates[order]
        assert _tick(row[1]) == gate.gate
        status, code = row[3].split(" ")
        assert int(status) == gate.http_status
        assert _tick(code) == gate.problem_code.value
        assert row[4] == gate.audit


def test_error_code_table_in_api_contract_covers_every_code_with_the_csv_status() -> None:
    text = (DOCS / "api-contract.md").read_text(encoding="utf-8")
    rows = _rows(text, re.compile(r"`[a-z]+\.[a-z_]+`"))
    docs = {_tick(r[0]): r for r in rows if len(r) == 4 and r[1].isdigit()}
    assert set(docs) == {code.value for code in ErrorCode}
    gate_status = {g.problem_code.value: g.http_status for g in load_gates()}
    for code, status in gate_status.items():
        assert int(docs[code][1]) == status, code


def test_every_operation_has_a_route_in_the_api_contract() -> None:
    text = (DOCS / "api-contract.md").read_text(encoding="utf-8")
    for rule in load_capabilities().rules:
        assert f"`{rule.operation}`" in text, rule.operation


def test_test_matrix_equals_the_catalog() -> None:
    text = (DOCS / "test-matrix.md").read_text(encoding="utf-8")
    rows = {r[0]: r for r in _rows(text, re.compile(r"TL-\d\d")) if len(r) == 6}
    cases = {c.id: c for c in load_catalog()}
    assert set(rows) == set(cases)
    for case_id, row in rows.items():
        case = cases[case_id]
        assert row[2] == ", ".join(o.removesuffix(":2023") for o in case.owasp), case_id
        assert row[3] == ", ".join(case.milestones), case_id
        assert row[4] == case.state, case_id
        if case.state != "planned":
            assert all(f"`{m}`" in row[5] for m in case.test_modules), case_id


def test_decisions_referenced_in_docs_exist_in_decisions_md() -> None:
    decisions = (DOCS.parent / "DECISIONS.md").read_text(encoding="utf-8")
    defined = set(re.findall(r"^\| (D-\d+) \|", decisions, flags=re.MULTILINE))
    referenced: set[str] = set()
    for path in [*DOCS.glob("*.md"), DOCS.parent / "README.md", DOCS.parent / "LIMITATIONS.md"]:
        referenced |= set(re.findall(r"\bD-\d+\b", path.read_text(encoding="utf-8")))
    assert referenced <= defined, (
        f"docs reference undefined decisions: {sorted(referenced - defined)}"
    )
