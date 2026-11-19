"""Independent policy oracle.

INDEPENDENCE RULE (enforced by tests/unit/test_oracle_independence.py): nothing under
``tenantlab.oracle`` may import enforcement code (``tenantlab.api``, ``tenantlab.auth``,
``tenantlab.db``, ``tenantlab.lab.patched``, ``tenantlab.lab.vulnerable``). The expected
behaviour is declared in CSV/TOML data authored before the application code, so a bug in
the application cannot also be baked into the thing that judges it.
"""
