# Changelog

All notable changes are recorded here. Pre-release; no version has been tagged.

## [Unreleased]

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
