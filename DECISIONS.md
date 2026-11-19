# Decisions

Accepted trade-offs and spec interpretations. "Owner approval" = the shared standard requires a human
to confirm it before the dependent milestone proceeds. Each entry says what was chosen and why, so
it can be challenged.

| ID | Decision | Owner approval |
|---|---|---|
| D-01 | **Python 3.13** via `uv` (3.13.18 installed with `uv python install`). `requires-python = ">=3.13,<3.14"`. The machine's system Python 3.14.7 is deliberately not used; 3.14 is added only after dependency compatibility is verified (spec). | No |
| D-02 | `src/` layout, package `tenantlab`, `uv_build` backend, `uv.lock` committed. Dependency ranges have upper bounds; exact versions live in the lockfile. `pyproject.toml` author has **no e-mail** (privacy). | No |
| D-03 | **Token verification:** PyJWT (with `cryptography`), algorithm **EdDSA/Ed25519 only**, pinned by the verifier; required `sub jti iss aud iat nbf exp`; leeway 0 s; max lifetime 900 s; verifier holds a **public** key only; other claims ignored. Tokens in tests are minted by the harness with ephemeral in-memory keys. | **Yes** (auth/token format) |
| D-04 | **Object ownership never grants rights.** `projects.owner_principal_id` is informational. Fixture trap: PA1's owner is Frank, whose membership is revoked (TL-03). | **Yes** (policy) |
| D-05 | **Resource scope (market) is evaluated before role.** The shared standard lists role/capability before scope, but then a hidden-market object would answer 403 to a viewer and 404 to a non-member, which discloses existence. Scope first makes "not visible" one 404 for every role. The capability gate still precedes body parsing and every side effect. | **Yes** (deviation from standard) |
| D-06 | **Concealment:** every "not visible" case is the same `404 resource.not_found`; "visible but not allowed" is `403 authz.forbidden`; a suspended tenant is disclosed (`403 tenant.suspended`) only to its active members. | **Yes** (policy) |
| D-07 | Fixture addition **gina**: owner of suspended tenant C. The spec lists tenants A/B/C but no member of C, which TL-14 needs. | **Yes** (spec addition) |
| D-08 | Added `GET /v1/tenants/{tenant_id}/me` (context probe). It gives every negative test a positive control (a deny-everything app would otherwise pass them) and proves roles come from the DB. Exposes only the caller's own `principal_id`, `tenant_id`, `role`. | **Yes** (spec addition) |
| D-09 | Added the nested route `GET /v1/projects/{project_id}/invoices/{invoice_id}`. TL-07 is defined on a nested route but the spec's API table has none. | **Yes** (spec addition) |
| D-10 | **Audit policy:** pre-authentication failures (401, 413) write **no database row** (spec TL-01/02 "no DB change"; prevents anonymous audit flooding), only structured logs. Later denials write one row; `tenant_id` is NULL unless the actor is an active member of the resolved tenant and the target is visible (nobody can write into another tenant's audit log, and hidden vs missing objects leave identical rows). Mutations and private-contact reads are audited; ordinary successful reads are not (write amplification). | **Yes** (policy) |
| D-11 | An authenticated caller sending a malformed UUID path identifier gets `422 request.invalid` after gates 1-2: it cannot name any resource, so there is nothing to conceal. | No |
| D-12 | Unknown JSON properties and unknown query parameters are **rejected** (422), not ignored. The spec says "ignore/reject" for an unauthorized `owner` field; rejecting makes mass-assignment attempts visible and testable. | No |
| D-13 | The private-contacts route answers **403** to editor/viewer; it never returns 200 with fields removed ("no BOPLA fallback"). | No |
| D-14 | Cursor pagination only (`limit` 1..100, default 25, `cursor` <= 256 chars); `page`/`offset` are unknown parameters. `total` counts only objects the actor may read. | No |
| D-15 | `Settings.database_url` is a **synchronous** SQLAlchemy URL and the app uses synchronous sessions (FastAPI runs them in a threadpool). Simplest correct basis for PostgreSQL row-locking tests in M5. The tests' DB snapshots use a sync engine. | No |
| D-16 | **No `LICENSE` and no CI workflow yet.** The licence is an owner decision made after confirming no employer/client code is included (START_BUILDING). CI is scheduled for M5 with SHA-pinned actions verified at that time; a red CI in M0 would only add noise. | **Yes** (licence) |
| D-17 | **Red tests are real failing tests**, marked `milestone("Mx")`, never `skip`/`xfail`. `pytest` exits non-zero until M1 ships. `pytest -m "not milestone"` is the green contract suite. | No |
| D-18 | **Bodies are parsed after the gates** (found while validating tests against a spike: FastAPI parses JSON before dependencies, which would make anonymous malformed JSON a 422). | No |
| D-19 | Request ids are server-generated UUIDv4, returned as `X-Request-ID`, and equal the problem `request_id` and the audit `correlation_id`. A client value is never reused. | No |
| D-20 | The GitHub repository is **private**. Making it public is the owner's decision (START_BUILDING). Private vulnerability reporting must be enabled by the owner; the agent does not change repository settings. | **Yes** (publication) |
