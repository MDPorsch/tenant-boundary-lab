"""The code that ENFORCES policy must not read the oracle that JUDGES it (the mirror of
test_oracle_independence.py). If the application loaded the oracle's CSV, a bug in the loader or in
the data would be copied into both sides and every test would still pass.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import tenantlab

PACKAGE_ROOT = Path(next(iter(tenantlab.__path__)))
ENFORCEMENT_PACKAGES = ("api", "auth", "db", "lab/patched")
FORBIDDEN_PREFIXES = ("tenantlab.oracle", "tenantlab.lab.vulnerable", "tenantlab.runner")


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


@pytest.mark.parametrize("package", ENFORCEMENT_PACKAGES)
def test_enforcement_code_imports_neither_the_oracle_nor_the_vulnerable_lab(package: str) -> None:
    modules = sorted((PACKAGE_ROOT / package).rglob("*.py"))
    assert modules, f"{package} unexpectedly empty"
    for module in modules:
        for imported in _imports(module):
            assert not imported.startswith(FORBIDDEN_PREFIXES), (
                f"{module.relative_to(PACKAGE_ROOT)} imports {imported}: enforcement code must be "
                "independent of the oracle and must never reach the deliberately vulnerable lab"
            )


def test_the_top_level_modules_are_also_independent() -> None:
    for name in ("config.py", "ids.py"):
        for imported in _imports(PACKAGE_ROOT / name):
            assert not imported.startswith(FORBIDDEN_PREFIXES), (name, imported)


def test_the_scan_itself_detects_a_violation(tmp_path: Path) -> None:
    """Guard the guard: the checker must not be vacuous."""
    bad = tmp_path / "bad.py"
    bad.write_text("from tenantlab.oracle.matrix import load_capabilities\n", encoding="utf-8")
    assert any(i.startswith(FORBIDDEN_PREFIXES) for i in _imports(bad))
    sneaky = tmp_path / "sneaky.py"
    sneaky.write_text("from tenantlab import oracle\n", encoding="utf-8")
    assert any(i.startswith(FORBIDDEN_PREFIXES) for i in _imports(sneaky))
