# API contract

Status: **M0 contract, not yet implemented.** Authoritative sources: this file for shapes and
conventions; `src/tenantlab/oracle/data/gates.csv` for the ordered checks and their outcomes;
`capabilities.csv` for who may do what; `field_policy.csv` for which fields appear where.
Spec reference: `specifications/01_tenant_boundary_lab.md` s5-s6, shared standard s2.

## 1. Conventions

* Transport in tests: `httpx.ASGITransport` (in-process, zero sockets). Base URL is never real.
* All API paths are under `/v1`. All identifiers are canonical lowercase UUIDv4 strings.
* Authentication: `Authorization: Bearer <JWT>` only (see s4). A token in a query string or any
  other header is not a credential.
* Every response carries `X-Request-ID`: a **server-generated** UUIDv4. A client-supplied
  `X-Request-ID` is never echoed or reused (log-injection guard, TL-18). On error responses the
  same value is the problem body's `request_id` and the audit row's `correlation_id`.
* Success bodies are `application/json`; every non-2xx body is `application/problem+json` (s3).
* Request bodies: JSON object, UTF-8, at most **65 536 bytes**. Unknown properties and unknown
  query parameters are **rejected** (422), never ignored.
* Timestamps are UTC-aware ISO-8601. The server never trusts a client timestamp for a decision.

## 2. Routes

Gates 0-6 (and 7 where applicable) are enforced for **every** route from M1 on (deny by default).
Until M2 a request that passes all gates may reach a placeholder handler answering `501` with code
`internal.error`; no M1 test depends on that response.

| Method and path | Operation (capabilities.csv) | Notes | Handler milestone |
|---|---|---|---|
| `GET /v1/tenants/{tenant_id}/me` | `tenant.context.read` | Lab addition D-08: server-derived context. 200 body is exactly `{principal_id, tenant_id, role}` | M1 |
| `GET /v1/tenants/{tenant_id}/projects` | `project.list` | cursor pagination, `total` counts only readable objects | M2 |
| `POST /v1/tenants/{tenant_id}/projects` | `project.create` | body `{title, market}` only; 201 | M2 |
| `GET /v1/projects/{project_id}` | `project.read` | embeds `contacts: [{id, public_name}]` | M2 |
| `PATCH /v1/projects/{project_id}` | `project.write` | body `{title?, status?, row_version}`; `row_version` is the version the client read | M2 |
| `GET /v1/projects/{project_id}/contacts` | `contact.private.read` | admin/owner only; non-admin gets **403**, never a stripped 200 (D-13) | M2 |
| `GET /v1/invoices/{invoice_id}` | `invoice.read` | tenant + market of the parent project must be visible | M2 |
| `GET /v1/projects/{project_id}/invoices/{invoice_id}` | `invoice.read` | Nested route added for TL-07 (D-09); 404 unless the invoice belongs to that project | M2 |
| `PUT /v1/tenants/{tenant_id}/members/{principal_id}` | `member.role.write` | body `{role, status, version}`; owner only | M2 |
| `GET /v1/tenants/{tenant_id}/audit` | `audit.read` | tenant-filtered, cursor pagination | M2 |

Pagination: `limit` 1..100 (default 25) and an opaque `cursor` (at most 256 characters). `page`,
`offset` and any other parameter are unknown and yield 422. List bodies are
`{items, next_cursor, total}`; `total` is the number of objects **this actor may read**.

Limits: at most 1 000 projects per tenant (429 `quota.exceeded`); `title` 1..120 characters with no
control characters (NUL included).

## 3. Error contract (RFC 9457)

Schema: `tenantlab.schemas.errors.ProblemDetail` (strict; extra members forbidden).

```json
{
  "type": "urn:tenantlab:error:resource.not_found",
  "title": "Not found",
  "status": 404,
  "code": "resource.not_found",
  "detail": "The requested resource was not found.",
  "request_id": "5e1b0e0e-3b0a-4b86-8a3e-0f4d1e1d2c3b",
  "errors": []
}
```

`detail` is a fixed string per code and **never echoes user input**. `errors` (validation only,
max 20) holds `{loc, code}` pairs, never the offending value. 401 responses add
`WWW-Authenticate: Bearer`.

| Code | Status | Gate | Meaning |
|---|---|---|---|
| `auth.token_invalid` | 401 | 1 | Missing, malformed, forged, expired or otherwise unacceptable credential, **including a validly signed token for an unknown principal** (no account-existence oracle) |
| `auth.principal_disabled` | 403 | 2 | The authenticated principal is disabled |
| `resource.not_found` | 404 | 3, 5 | Not visible to the caller: does not exist, is another tenant's, is in a market the tenant lacks, or the caller has no active membership. One shape for all of these |
| `tenant.suspended` | 403 | 4 | The caller is an active member of a suspended tenant (disclosed to members only) |
| `authz.forbidden` | 403 | 6 | Visible to the caller but their role lacks the capability |
| `authz.market_denied` | 403 | 7 | Create requested in a market the tenant is not permitted to use |
| `request.invalid` | 422 | 8 | Validation failure (unknown/forbidden/overlong/mistyped property or parameter, bad UUID, bad cursor/limit) |
| `request.too_large` | 413 | 0 | Body exceeds 65 536 bytes (checked before authentication) |
| `conflict.stale_revision` | 409 | 10 | `row_version` precondition failed |
| `conflict.last_owner` | 409 | 11 | The change would leave the tenant without an active owner |
| `quota.exceeded` | 429 | 9 | Per-tenant quota exceeded |
| `service.unavailable` | 503 | n/a | A dependency (database) is unavailable: **fail closed**, never allow |
| `internal.error` | 500 | n/a | Unexpected server error; generic body, no stack trace or SQL |

## 4. Token contract (D-03, human review required)

* Compact JWS, algorithm **EdDSA (Ed25519) only**; the algorithm is pinned by the verifier and
  never taken from the token header. `alg=none` and any other algorithm are rejected.
* The verifier holds a **public** key only. No setting for a private key exists.
* Required claims: `sub` (principal UUID), `jti`, `iss`, `aud`, `iat`, `nbf`, `exp`. `iss` and
  `aud` must equal the configured values exactly. Leeway is 0 s.
* `exp - iat` must be **at most 900 s** (900 accepted, 901 rejected).
* `sub` must be a UUID of an existing principal; otherwise it is indistinguishable from any other
  invalid token (401).
* Any other claim (`role`, `roles`, `tenant_id`, `scope`, `is_admin` ...) is **ignored**: role and
  tenant authority come from the database on every request.

## 5. Concealment (403 versus 404)

The 403/404 split depends only on whether the caller may **see** the target, never on whether a
hidden thing exists (D-05, D-06).

| Situation | Response |
|---|---|
| Tenant path: caller has no active membership (revoked, never a member, or the tenant does not exist) | 404 `resource.not_found`, identical body |
| Object path: object missing, or in another tenant the caller is not in, or in a market its tenant lacks | 404 `resource.not_found`, identical body |
| Caller is an active member but the tenant is suspended | 403 `tenant.suspended` (members only; non-members still get the plain 404) |
| Target visible, role lacks capability | 403 `authz.forbidden` |
| Authenticated but the path identifier is not a UUID | 422 `request.invalid` (it cannot name any resource, D-11) |

## 6. Audit contract

Table `audit_events(id, actor_id, tenant_id, action, resource_type, resource_id, decision,
reason_code, timestamp, correlation_id)`. Never contains tokens, bodies or private fields.

* `action` is the oracle **operation id** of the matched route (for example `project.write`),
  never user input. `resource_type` is one of `tenant|project|invoice|contact|membership|audit`.
  `decision` is `allow|deny`. `correlation_id` equals the response `request_id`.
* **Pre-authentication failures (gates 0-1) write no database row**, only a structured log line
  (TL-01/TL-02: "no DB change"; prevents anonymous audit flooding).
* A denial at gates 2, 3 and 5 writes one row with the actor set and `tenant_id` **NULL**. A denial
  at gates 4 and 6-11 writes one row with the resolved `tenant_id` (the actor is an active member).
  So nobody can write into a tenant's audit log, or reveal hidden objects through it (D-10).
* Successful mutations and successful private-contact reads are audited. Ordinary successful reads
  are not (write amplification; stated in LIMITATIONS.md).
* The audit endpoint returns only rows whose `tenant_id` equals the path tenant.

## 7. Check order (summary of `gates.csv`)

`0 transport_limits -> 1 authenticate -> 2 principal_status -> 3 tenant_membership -> 4 tenant_state
-> 5 resource_scope (market) -> 6 role_capability -> 7 market_permit -> 8 input_validation ->
9 quota -> 10/11 state preconditions -> action -> audit`.

Deviation from the shared standard (D-05): resource scope is evaluated **before** role, so a hidden
object is a 404 for every role. The capability gate still precedes any body parsing or side effect.

## 8. Implementation constraints discovered while validating the tests

* **Bodies are read after the gates.** FastAPI/Starlette parse JSON bodies *before* dependencies
  run, which would turn "anonymous + malformed JSON" into 422. M1 must authenticate and authorize
  first and parse/validate the body afterwards (for example by taking the raw `Request` and
  validating with Pydantic inside the handler, or a custom route class). Required by the
  TL-01 test `test_tl01_authentication_precedes_body_parsing`.
* The 401/403/404 outcomes above must not depend on the order in which the database returns rows.

## 9. M1 interface the red tests rely on

The red tests (`tests/negative/test_m1_*.py`) import exactly these names; M1 may add more but must
provide these:

```python
tenantlab.config.Settings(database_url, jwt_issuer, jwt_audience, jwt_public_key_pem)  # pydantic model
tenantlab.db.migrate.upgrade_to_head(database_url: str) -> None   # Alembic; never runs on app startup
tenantlab.db.seed.seed_fixtures(database_url: str) -> None        # loads lab/fixtures/fixtures.toml
tenantlab.api.app.create_app(settings: Settings) -> ASGI application
```

`database_url` is a **synchronous** SQLAlchemy URL (`sqlite+pysqlite:///...`; later
`postgresql+psycopg://...`) (D-15). The tests read table state with raw SQL using the table names in
`specifications/01_tenant_boundary_lab.md` s4, and use `rowid` ordering for `audit_events` on
SQLite (the PostgreSQL harness variant arrives with M5).
