# Test matrix

Source of truth: `src/tenantlab/oracle/data/case_catalog.toml` (loaded and validated by
`tenantlab.oracle.catalog`). `tests/unit/test_docs_sync.py` fails if this table drifts from it.

State: **red** = a failing test exists today and names the case (tests first); **planned** = the test
is written at the *start* of the listed milestone, before its code.

| Case | Scenario | OWASP API 2023 | First milestone | State | Test module |
|---|---|---|---|---|---|
| TL-01 | No, malformed or forged bearer | API2 | M1 | red | `tests/negative/test_m1_authentication.py` |
| TL-02 | Expired, not-yet-valid, wrong issuer/audience JWT | API2 | M1 | red | `tests/negative/test_m1_authentication.py` |
| TL-03 | Disabled actor or revoked membership | API2, API1 | M1 | red | `tests/negative/test_m1_tenant_gates.py` |
| TL-04 | Authenticated user guesses another tenant UUID | API1 | M1 | red | `tests/negative/test_m1_tenant_gates.py` |
| TL-05 | Multi-membership user selects an unauthorized tenant | API1, API5 | M1 | red | `tests/negative/test_m1_tenant_gates.py` |
| TL-06 | Viewer PATCH, admin endpoint, field overposting | API5, API3 | M2 | planned | (M2) |
| TL-07 | Project A id with invoice B id in a nested route | API1 | M2 | planned | (M2) |
| TL-08 | Cross-market access within the same tenant | API1 | M2 | planned | (M2) |
| TL-09 | Property-level leakage via response, pagination, export, error | API3 | M2 | planned | (M2) |
| TL-10 | Hostile pagination and identifier input | API4 | M2 | planned | (M2) |
| TL-11 | Last owner removes themselves | API5 | M2 | planned | (M2) |
| TL-12 | Two writers use the same `row_version` | n/a | M2, M5 | planned | (M2, M5 on PostgreSQL) |
| TL-13 | Membership revoked between list and object read | API1 | M2 | planned | (M2) |
| TL-14 | Suspended tenant or changed membership state with prior access | API1 | M1 | red | `tests/negative/test_m1_tenant_gates.py` |
| TL-15 | UTF-8, overlong fields, unknown keys, type confusion | API3, API4 | M2 | planned | (M2) |
| TL-16 | Vulnerable router enabled outside the local lab | API8 | M3 | planned | (M3) |
| TL-17 | Database write occurs and then a 403 is returned | API5, API1 | M4 | planned | (M4) |
| TL-18 | Client-supplied identity or role headers/body | API3, API5 | M1 | red | `tests/negative/test_m1_untrusted_context.py` |
| TL-19 | List totals and timing reveal hidden data | API1, API3 | M2 | planned | (M2) |
| TL-20 | Overlapping membership and market-access changes | API1 | M5 | planned | (M5 on PostgreSQL) |

## Other test layers (M0)

| Layer | Location | What it protects |
|---|---|---|
| Oracle contract | `tests/unit/test_authorization_matrix_contract.py` | The CSVs equal the spec's policy, encoded a second time; monotonicity; concealment and audit invariants |
| Oracle independence | `tests/unit/test_oracle_independence.py` | The oracle cannot import code it judges (AST scan, with a guard against a vacuous scan) |
| Fixtures | `tests/unit/test_fixtures_contract.py` | Referential integrity, UUIDv4, no leak-prone data, every trap fixture present |
| Catalog | `tests/unit/test_case_catalog_contract.py` | 20 cases, milestone plan equals the spec, red cases really have named tests |
| Error contract | `tests/unit/test_error_contract.py` | Strict problem+json, no input echo, server-only request id |
| Fail closed | `tests/unit/test_loaders_fail_closed.py` | A malformed oracle raises instead of degrading |
| Harness self-check | `tests/unit/test_harness_selfcheck.py` | Hostile tokens are well-formed (the HS256 forgery's MAC is correct), snapshots detect mutations |
| Docs sync | `tests/unit/test_docs_sync.py` | Docs list every operation, gate, error code and case |

Planned layers: `tests/integration`, `tests/property` (Hypothesis, M5), `tests/concurrency` (PostgreSQL, M5).
