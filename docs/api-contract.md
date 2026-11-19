# API contract

Status: **M2.** All ten routes are implemented (docs s10 gives the request and response shapes).
Authoritative sources: this file for shapes and
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
* Every response carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
* An unknown path, a wrong method on a known path, a trailing slash and any docs/OpenAPI URL answer
  the same generic `404 resource.not_found` (D-22). A malformed or repeated `Content-Length` is
  `422 request.invalid` before authentication (D-23).

## 2. Routes

Gates 0-6 (and 7 where applicable) are enforced for **every** route from M1 on (deny by default).
Every request passes the same gates first; the handler runs only after them. (In M1 the
nine data routes answered a placeholder `501`; that mechanism remains for a route marked
not implemented in the registry.)

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
* `resource_id` is the identifier the caller asked for once it parsed as a UUIDv4 (`NULL` if it was
  malformed); for collection routes it is the parent's id (D-24).
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

## 8. Implementation constraints (implemented, guarded by tests)

* **Bodies are read after the gates.** FastAPI/Starlette parse JSON bodies *before* dependencies
  run, which would turn "anonymous + malformed JSON" into 422. The endpoint wrapper therefore takes
  only the raw `Request`; handlers read and validate the body after the gates. Required by
  `test_tl01_authentication_precedes_body_parsing`, and guarded structurally by
  `test_no_endpoint_lets_the_framework_parse_input_before_the_gates`.
* The 401/403/404 outcomes above must not depend on the order in which the database returns rows.

## 9. The interface the M1 tests rely on (implemented)

The M1 tests (`tests/negative/test_m1_*.py`) import exactly these names:

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

## 10. Request and response shapes (M2)

Written **before** the M2 tests and handlers; `tests/negative/test_m2_*.py` encode it. Surfaces are
named as in `field_policy.csv`; a test compares every response with that file.

### 10.1 Responses

| Route | Success | Body |
|---|---|---|
| `GET /v1/tenants/{t}/projects` | 200 | page of `project.list_item`, ascending `id` |
| `POST /v1/tenants/{t}/projects` | 201 | `project.detail` of the new project |
| `GET /v1/projects/{p}` | 200 | `project.detail` |
| `PATCH /v1/projects/{p}` | 200 | `project.detail` after the change (`row_version` + 1) |
| `GET /v1/projects/{p}/contacts` | 200 | page of `contacts.private`, ascending `id` |
| `GET /v1/invoices/{i}`, `GET /v1/projects/{p}/invoices/{i}` | 200 | `invoice.detail` |
| `PUT /v1/tenants/{t}/members/{principal}` | 200 | `membership.detail` after the change (`version` + 1) |
| `GET /v1/tenants/{t}/audit` | 200 | page of `audit.list_item`, newest first (descending `id`) |

A **page** is `{"items": [...], "next_cursor": string or null, "total": integer}`. `total` is the
number of objects the actor may read (a hidden-market project is not counted, D-14); `next_cursor`
is null on the last page.

| Surface | Fields | Floor |
|---|---|---|
| `project.list_item` | `id tenant_id market title status row_version` | viewer |
| `project.detail` | the list item, plus `contacts` (at most 100 of `{id, public_name}`), plus `owner_principal_id` | viewer; `owner_principal_id` editor and above |
| `contacts.private` | `id public_name email_private phone_private` | admin |
| `invoice.detail` | `id tenant_id project_id amount_minor currency status` | viewer |
| `membership.detail` | `principal_id tenant_id role status version` | owner |
| `audit.list_item` | `id actor_id tenant_id action resource_type resource_id decision reason_code timestamp correlation_id` | admin |

### 10.2 Requests

Body rules (all body routes, decision D-30): `Content-Type: application/json`, a non-empty UTF-8 JSON
**object**, no duplicate keys, no `NaN`/`Infinity`, strict types (a boolean is not an integer, a
string is not a number), unknown keys rejected. The 422 body lists `{loc, code}` pairs only; an
unknown key is reported as `{"loc": ["body"], "code": "unknown_field"}` and its name is never echoed.

| Route | Body | Rules |
|---|---|---|
| `POST /v1/tenants/{t}/projects` | `{title, market}`, both required | `title` 1..120 code points, no control characters (`Cc`), no surrogates, no bidi override characters; `market` a string |
| `PATCH /v1/projects/{p}` | `{title?, status?, row_version}` | at least one of `title`, `status`; `status` is `draft`, `active` or `archived`; `row_version` an integer 1..2147483647 equal to the stored value |
| `PUT /v1/tenants/{t}/members/{principal}` | `{role, status, version}`, all required | `role` owner/admin/editor/viewer; `status` active/revoked; `version` an integer equal to the stored value; updates an **existing** membership only |

Query (list routes `projects`, `contacts`, `audit`): `limit` is 1..100 written as plain ASCII digits
without sign or padding (default 25); `cursor` is at most 256 characters of base64url. Anything else,
a repeated parameter, or an unknown parameter is 422.

### 10.3 Order of the remaining checks

Gates 1-6 and the query names (M1), then: body media type and JSON syntax, **gate 7** (create only:
a `market` the tenant may not use, or that does not exist, is `403 authz.market_denied`; evaluated
when `market` is a string), **gate 8** body validation, **gate 9** quota (at most 1 000 projects per
tenant, counting hidden-market projects, D-32), then the write. The write is **one statement that
re-checks authority** (active membership with a capable role, active tenant, market permitted,
quota, version) so a revocation that lands between the gates and the write cannot be overridden
(D-35). If that statement changes no row, the gates are re-run to report the true reason; if none
fails, **gate 10** (`409 conflict.stale_revision`) or **gate 11** (`409 conflict.last_owner`).

### 10.4 Audit

A successful `project.create`, `project.write`, `member.role.write` and `contact.private.read` writes
one `allow` row, `reason_code` `ok`, in the **same transaction** as the change (a failed audit write
rolls the change back). `resource_id` is the new project for a create. Other successful reads write
nothing. Every denial from gate 7 on writes one `deny` row scoped to the tenant (D-10, D-37).
