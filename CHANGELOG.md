# Changelog

All notable changes are recorded here. Pre-release; no version has been tagged.

## [Unreleased]

### M2.1: timing hardening and secret scanning

- Measured first: a hidden-market project took 5 SQL statements and was +23.5% slower than a missing
  one (p < 0.001) because the gates returned early; the old timing test tolerated a factor of five
  and sampled one class after the other (time drifts ~29% across a run).
- Gates 3-5 now do constant work (D-40): the same lookups in the same order for every not-visible
  outcome, then decide in the documented order. Hidden vs missing is now +0.9%.
- TL-19 timing evidence: a deterministic same-SQL test per route family, an interleaved permutation
  test with a 15% floor over two rounds, a detector check, and tests of the statistics. Written red
  first. 1098 tests; mutation tools 69/69 (M1) and 52/52 (M2).
- `tools/secret_scan.py` (gitleaks over all history and the tree, with a canary that proves the
  scanner works): no findings.
- Design brief for the productization of this project (`docs/productization/boundarycheck-design.md`,
  proposed, nothing implemented).

### M2: the patched API

- All ten routes implemented behind the M1 gates: project list/create/read/patch, private contacts,
  invoices (plain and nested), membership update, tenant audit log. Contract first: request and
  response shapes in `docs/api-contract.md` s10, decisions D-30..D-39.
- `lab/patched/`: strict request parsing (media type, UTF-8, duplicate keys, NaN, strict types,
  title rules), response models that forbid extra fields, keyset paging, bounded reads (statement
  count independent of the data), and **write statements that carry their own authority, quota,
  version and last-owner predicates**. A change and its `allow` audit row commit together.
- Failure behaviour: a lost race is retried at most 3 times with the gates re-run (404/403/409/429
  as the truth now is), then 503; any database failure, including a failed audit write, is 503.
- 446 tests added (1081 total, all green, 99% coverage of `src`): 356 written red first, then races
  between a handler's pre-check and its write, and each write statement on its own.
- Case catalog: TL-06..13, 15 and 19 are `green` (TL-12's PostgreSQL part is M5).
- `tools/mutation_m2.py`: 49 injected bugs, all caught; `tools/mutation_m1.py` re-run on the final tree.
- Changed M1 tests on purpose: the "no GET writes audit" control now allows the audited private
  contact read; the registry tests expect every route implemented.
- `gates.csv`: gate 10 (stale precondition) also covers the membership `version`.

### M1: identity and deny-by-default gates

- Settings (public material only), strict UUID parsing, EdDSA-only token verifier (decision D-03
  plus the strictness in D-26).
- SQLAlchemy models and hand-written Alembic migration `0001`: CHECK, UNIQUE and foreign-key
  constraints enforced (SQLite foreign keys switched on per connection); deterministic, atomic seed
  that refuses a non-empty database.
- Route registry and gate pipeline (gates 0-6 and the query part of gate 8): server-generated
  request id, 413 body cap, 401 without a database row, disabled principal, active membership,
  suspended tenant, market scope before role, role capability, strict path ids and query names.
  Every denial is audited once (tenant NULL unless the actor is an active member); a database
  failure fails closed with 503.
- `GET /v1/tenants/{tenant_id}/me`; the nine other routes pass the gates and answer 501 until M2.
- The 96 tests written red in M0 now pass unedited. 389 tests added (unit, database, middleware,
  gate pipeline); total 635, all green, 99% line+branch coverage of `src`.
- Case catalog: TL-01..05, TL-14 and TL-18 are `green`.
- `tools/mutation_m1.py`: 69 injected security bugs, all caught by the suite.
- Fixes found by the new tests: PyJWT subject/jti/iat errors were mapped through a wrong attribute
  path; the M0 harness self-check leaked SQLite connections.

### M0: contracts (no application yet)

- Independent oracle data: `capabilities.csv`, `gates.csv`, `field_policy.csv`, `case_catalog.toml`
  (20 cases mapped to OWASP API Security Top 10:2023), with strict fail-closed loaders.
- Synthetic fixtures (7 principals, 3 tenants, 2 markets, 4 projects, 3 invoices, 4 contacts) with
  trap rows for ownership-vs-membership, hidden-market and suspended-tenant cases.
- RFC 9457 error contract (`ProblemDetail`, `ErrorCode`).
- Tests: contract suite (passes) and 96 behavioural red tests for TL-01..05, TL-14, TL-18 (fail by
  design until M1), with a harness that mints hostile tokens independently of the application.
- Documentation: architecture, threat model, authorization matrix, API contract, test matrix,
  DECISIONS, LIMITATIONS, SECURITY.
