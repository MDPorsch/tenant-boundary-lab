# Changelog

All notable changes are recorded here.

## [0.1.0] - 2026-11-20

First tagged release: milestones M0 to M6. The owner approved the M3 isolation review and the licence
(Apache-2.0) on 2026-11-20 (D-16, D-41, D-43, D-44, D-46, D-48) and asked for M4 to M6, including this
tagged release. D-53 and D-56 (the fifth flaw and the lock-based write path) still await their approval.

### M6: samples, diagram, release

- `docs/samples/`: four real boundarycheck reports (patched, role flaw, write-before-authorization, and
  the same flawed lab run reads-only, which is clean) and a terminal transcript.
- A Mermaid architecture diagram (`docs/architecture.md`), the policy review, the 0.1.0 tag.

### M5: PostgreSQL concurrency, a sweep and properties

- **Four defects found by running the suite on PostgreSQL, all fixed** (D-56, D-57): two owners
  demoting each other at once left a tenant with **no owner**; two concurrent creates at 999 projects
  made **1001**; an authority change (revocation, downgrade, disable, suspension, market removal) could
  commit while a write relying on it was in flight; and `INSERT ... SELECT` reported `rowcount == -1`
  through psycopg 3, so every project creation failed closed with 503.
- Writes now lock the rows their authority rests on, in one fixed order (tenant, principal, membership,
  market access), inside the write transaction.
- `tests/postgres/` (15 tests, a throwaway container from an image pinned by digest) and
  `TENANTLAB_TEST_DB=postgres` to run the M1 and M2 suites on PostgreSQL unchanged.
- `tests/negative/test_m5_sweep.py` (every route x every caller x every target, one independent checker
  that is shown to fail on each of the five flaws) and `test_m5_properties.py` (Hypothesis).
- CI: a `postgres` job. Mutation check `tools/mutation_m5.py` (28 mutants).

### M4: forbidden-mutation detection (TL-17)

- Fifth controlled flaw `WRITE_BEFORE_AUTHORIZATION` in the vulnerable lab (D-53): the project PATCH
  is committed before the authorization gates run, so a refused request still changes the row while
  its status code is exactly the correct one.
- `tests/support_m4.py`: a raw-SQL state diff over the business tables (D-54), itself tested.
- TL-17: every denied or refused write to the patched app leaves the business tables identical
  (20 denials, 5 refusals, 3 detector controls), and the flawed app is caught by the diff.

### M3: the deliberately vulnerable lab

- `tenantlab/lab/vulnerable/`: six routes with four independently switchable flaws (tenant predicate
  omitted, role check missing, private property serialized, market boundary omitted). With no flaw
  enabled it answers like the patched app to a 323-request matrix; each exploit works under exactly
  its own flaw; the patched app denies all of them.
- Isolation in eight tested layers (`docs/vulnerable-lab.md`): never imported by the default app
  (checked in a clean interpreter), excluded from the wheel, import allow-list with no network
  client, start-up guard (LAB_MODE exactly 1, environment lab or test, loopback literal bind, SQLite
  file, synthetic data only), request guard (non-loopback peers get 403 however it was started),
  Unix-socket launcher, container with no network, visible marking.
- Container: `deploy/Dockerfile.vulnerable-lab`, `deploy/compose.vulnerable-lab.yaml`,
  `deploy/container_selfcheck.py`. Colima and the Docker CLI installed. Measured inside: uid 10001,
  loopback interface only, outbound TCP and DNS blocked, read-only root, no capabilities; a control on
  the default network reaches out, so the check is not vacuous.
- Found by a test: uvicorn chmods a Unix socket to 0666, so the first design's "owner-only socket"
  was false. The launcher now requires an owner-only directory and chmods the socket to 0600 (D-48).
- `tools/mutation_m3.py`: 42 bugs in the guards, flaw switches, launcher, wheel and container.
- Decisions D-41..D-48; D-41, D-43, D-44, D-46, D-48 are for your isolation review.

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
