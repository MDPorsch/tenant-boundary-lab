"""The DELIBERATELY VULNERABLE lab (milestone M3). Local, synthetic, never deployed.

Nothing outside this package may import it (checked in a clean interpreter and by an AST scan), it
is excluded from the built wheel, and it refuses to start unless every guard in `guard.py` passes.
See docs/vulnerable-lab.md.
"""

from __future__ import annotations

from tenantlab.lab.vulnerable.app import create_vulnerable_app
from tenantlab.lab.vulnerable.flaws import ALL_FLAWS, Flaw, parse_flaws
from tenantlab.lab.vulnerable.guard import LabIsolationError

__all__ = ["ALL_FLAWS", "Flaw", "LabIsolationError", "create_vulnerable_app", "parse_flaws"]
