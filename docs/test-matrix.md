# Test matrix

Source of truth: `src/tenantlab/oracle/data/case_catalog.toml` (loaded and validated by
`tenantlab.oracle.catalog`). `tests/unit/test_docs_sync.py` fails if this table drifts from it.

State: **planned** = the test is written at the *start* of the listed milestone, before its code;
**red** = a failing test exists and names the case (tests first) but the code is not built;
**green** = the test exists, names the case and passes against the built code. A case moves
planned, red, green and never backwards.

| Case | Scenario | OWASP API 2023 | First milestone | State | Test module |
|---|---|---|---|---|---|
| TL-01 | No, malformed or forged bearer | API2 | M1 | green | `tests/negative/test_m1_authentication.py` |
| TL-02 | Expired, not-yet-valid, wrong issuer/audience JWT | API2 | M1 | green | `tests/negative/test_m1_authentication.py` |
| TL-03 | Disabled actor or revoked membership | API2, API1 | M1 | green | `tests/negative/test_m1_tenant_gates.py` |
| TL-04 | Authenticated user guesses another tenant UUID | API1 | M1 | green | `tests/negative/test_m1_tenant_gates.py` |
| TL-05 | Multi-membership user selects an unauthorized tenant | API1, API5 | M1 | green | `tests/negative/test_m1_tenant_gates.py` |
| TL-06 | Viewer PATCH, admin endpoint, field overposting | API5, API3 | M2 | planned | (M2) |
| TL-07 | Project A id with invoice B id in a nested route | API1 | M2 | planned | (M2) |
| TL-08 | Cross-market access within the same tenant | API1 | M2 | planned | (M2) |
| TL-09 | Property-level leakage via response, pagination, export, error | API3 | M2 | planned | (M2) |
| TL-10 | Hostile pagination and identifier input | API4 | M2 | planned | (M2) |
| TL-11 | Last owner removes themselves | API5 | M2 | planned | (M2) |
| TL-12 | Two writers use the same `row_version` | n/a | M2, M5 | planned | (M2, M5 on PostgreSQL) |
| TL-13 | Membership revoked between list and object read | API1 | M2 | planned | (M2) |
| TL-14 | Suspended tenant or changed membership state with prior access | API1 | M1 | green | `tests/negative/test_m1_tenant_gates.py` |
| TL-15 | UTF-8, overlong fields, unknown keys, type confusion | API3, API4 | M2 | planned | (M2) |
| TL-16 | Vulnerable router enabled outside the local lab | API8 | M3 | planned | (M3) |
| TL-17 | Database write occurs and then a 403 is returned | API5, API1 | M4 | planned | (M4) |
| TL-18 | Client-supplied identity or role headers/body | API3, API5 | M1 | green | `tests/negative/test_m1_untrusted_context.py` |
| TL-19 | List totals and timing reveal hidden data | API1, API3 | M2 | planned | (M2) |
| TL-20 | Overlapping membership and market-access changes | API1 | M5 | planned | (M5 on PostgreSQL) |

## Other test layers (M0 and M1)

| Layer | Location | What it protects |
|---|---|---|
| Oracle contract | `tests/unit/test_authorization_matrix_contract.py` | The CSVs equal the spec's policy, encoded a second time; monotonicity; concealment and audit invariants |
| Oracle independence | `tests/unit/test_oracle_independence.py` | The oracle cannot import code it judges (AST scan, with a guard against a vacuous scan) |
| Fixtures | `tests/unit/test_fixtures_contract.py` | Referential integrity, UUIDv4, no leak-prone data, every trap fixture present |
| Catalog | `tests/unit/test_case_catalog_contract.py` | 20 cases, milestone plan equals the spec, cases with tests really have named tests, shipped milestones are green and later ones planned |
| Error contract | `tests/unit/test_error_contract.py` | Strict problem+json, no input echo, server-only request id |
| Fail closed | `tests/unit/test_loaders_fail_closed.py` | A malformed oracle raises instead of degrading |
| Harness self-check | `tests/unit/test_harness_selfcheck.py` | Hostile tokens are well-formed (the HS256 forgery's MAC is correct), snapshots detect mutations |
| Docs sync | `tests/unit/test_docs_sync.py` | Docs list every operation, gate, error code and case |
| App policy equals oracle | `tests/unit/test_app_policy_matches_oracle.py` | The application's own capability table equals the oracle cell by cell; default deny; exact role strings only |
| App independence | `tests/unit/test_app_independence.py` | `api`, `auth`, `db` import neither the oracle nor the vulnerable lab (mirror of the oracle guard) |
| Route registry | `tests/unit/test_route_registry.py` | Registry equals the api-contract route table and the oracle operations; only registered routes are mounted; no endpoint lets the framework parse input before the gates; every route is 401 for an anonymous caller with no database |
| Problem table | `tests/unit/test_problems.py` | One fixed status/title/detail per code, equal to `gates.csv` and the contract table; strict schema |
| Token verifier | `tests/unit/test_token_verifier.py` | Why each bad token is refused (reason codes), alg never trusted from the header, extra claims ignored, Hypothesis: junk only ever yields `TokenError` |
| Settings | `tests/unit/test_settings.py` | Public key only, Ed25519 only, a private key is refused and never echoed, missing variable refuses to start |
| Identifiers | `tests/unit/test_ids.py` | Exactly one spelling per UUID (Hypothesis round trip and never-raises) |
| Database layer | `tests/unit/test_database_layer.py` | Migration equals the models, every CHECK / UNIQUE / foreign key enforced with a valid control, seed equals fixtures and is atomic and refuses data, engine rules |
| Middleware | `tests/unit/test_middleware.py` | Request id, body cap for streamed bodies, 500/503 mapping without leaks, crash after the response started is re-raised |
| Gate pipeline | `tests/negative/test_m1_gate_pipeline.py` | Gate 0 (413), market scope before role, invoice coherence and nested route, malformed path ids (D-11), query strictness, fail-closed 503, logging, concurrency, response headers |

Mutation check of the M1 code: `uv run python tools/mutation_m1.py` (see `docs/milestones/M1.md`).

Planned layers: `tests/integration`, `tests/property` (Hypothesis, M5), `tests/concurrency` (PostgreSQL, M5).
