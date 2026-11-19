"""The oracle must stay independent of the code it judges (spec s2, s5, s9 caveat).

"A policy oracle implemented as a copy of production code is not independent."
This is enforced structurally: an AST scan of every module under tenantlab.oracle.
"""

from __future__ import annotations

import ast
from pathlib import Path

import tenantlab.oracle

FORBIDDEN_PREFIXES = (
    "tenantlab.api",
    "tenantlab.auth",
    "tenantlab.db",
    "tenantlab.runner",
    "tenantlab.lab.patched",
    "tenantlab.lab.vulnerable",
)


def _imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise AssertionError(f"{path}: relative import hides the dependency graph")
            if node.module:
                found.add(node.module)
                found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def test_oracle_modules_import_no_enforcement_code() -> None:
    root = Path(next(iter(tenantlab.oracle.__path__)))
    modules = sorted(root.rglob("*.py"))
    assert modules, "oracle package unexpectedly empty"
    for module in modules:
        for imported in _imports(module):
            assert not imported.startswith(FORBIDDEN_PREFIXES), (
                f"{module.relative_to(root)} imports {imported}: the oracle must not depend on "
                "the code it is meant to judge"
            )


def test_the_scan_itself_detects_a_violation(tmp_path: Path) -> None:
    """Guard the guard: prove the checker is not vacuous."""
    bad = tmp_path / "bad.py"
    bad.write_text("from tenantlab.auth.policy import decide\n", encoding="utf-8")
    assert any(i.startswith(FORBIDDEN_PREFIXES) for i in _imports(bad))
