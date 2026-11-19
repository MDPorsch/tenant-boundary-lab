# Authorization matrix

**This is the artifact the owner must approve before any route is written** (spec M0: "Human
approve policy before routes"). The machine-readable sources of truth are
`src/tenantlab/oracle/data/capabilities.csv`, `gates.csv` and `field_policy.csv`. This page renders
them for humans; `tests/unit/test_docs_sync.py` fails if the operations or gates drift from the CSVs.

The matrix is the **oracle**: it is authored independently of the application and nothing under
`tenantlab.oracle` may import enforcement code (`tests/unit/test_oracle_independence.py`).

## 1. Roles x operations (`capabilities.csv`)

`Y` = allowed, `N` = denied. Anything not listed is **denied** (default deny).

| Operation | Capability | owner | admin | editor | viewer |
|---|---|:-:|:-:|:-:|:-:|
| `tenant.context.read` | `tenants:context:read` | Y | Y | Y | Y |
| `project.list` | `projects:read` | Y | Y | Y | Y |
| `project.read` | `projects:read` | Y | Y | Y | Y |
| `project.create` | `projects:create` | Y | Y | Y | N |
| `project.write` | `projects:write` | Y | Y | Y | N |
| `invoice.read` | `invoices:read` | Y | Y | Y | Y |
| `contact.private.read` | `contacts:private:read` | Y | Y | N | N |
| `member.role.write` | `members:write` | Y | N | N | N |
| `audit.read` | `audit:read` | Y | Y | N | N |

Invariants asserted by tests: permissions are monotonic (owner >= admin >= editor >= viewer); a viewer
holds only read capabilities; `members:write` is owner-only; there is no global/platform admin
operation in the MVP.

## 2. Gates, in the order they run (`gates.csv`)

A request is denied at the **first** failing gate. Audit column: `none` = log only, no DB write;
`tenant_null` = audit row with actor, `tenant_id` NULL; `tenant` = audit row scoped to the tenant.

| # | Gate | Denies when | Status / code | Audit |
|---|---|---|---|---|
| 0 | `transport_limits` | body over 65 536 bytes | 413 `request.too_large` | none |
| 1 | `authenticate` | bearer absent/malformed/unverifiable, wrong alg/iss/aud, bad or missing claim, expired, not yet valid, lifetime > 900 s, unknown `sub` | 401 `auth.token_invalid` | none |
| 2 | `principal_status` | principal is not `active` | 403 `auth.principal_disabled` | tenant_null |
| 3 | `tenant_membership` | no **active** membership in the target tenant, or target does not exist | 404 `resource.not_found` | tenant_null |
| 4 | `tenant_state` | tenant is not `active` | 403 `tenant.suspended` | tenant |
| 5 | `resource_scope` | the object's market is not permitted to its tenant | 404 `resource.not_found` | tenant_null |
| 6 | `role_capability` | role lacks the capability | 403 `authz.forbidden` | tenant |
| 7 | `market_permit` | create in a market the tenant lacks | 403 `authz.market_denied` | tenant |
| 8 | `input_validation` | unknown/forbidden/overlong/mistyped input, bad UUID/cursor/limit | 422 `request.invalid` | tenant |
| 9 | `quota` | per-tenant quota exceeded | 429 `quota.exceeded` | tenant |
| 10 | `state_precondition` | stale `row_version` | 409 `conflict.stale_revision` | tenant |
| 11 | `state_invariant` | would remove the last active owner | 409 `conflict.last_owner` | tenant |

Why scope (5) runs before role (6): see DECISIONS D-05.

## 3. Property-level rules (`field_policy.csv`)

Effective read floor on a surface = max(route floor, field floor).

* **Private contact data** (`email_private`, `phone_private`) exists on exactly one surface,
  `contacts.private` (admin/owner). It never appears in project list/detail, invoices, audit or error bodies.
  An editor or viewer calling that route gets **403**, not a 200 with the fields removed.
* The only property projected *within* a route is `project.owner_principal_id` on `project.detail`
  (editor and above). Object ownership is informational and **never grants rights** (D-04).
* **Server-owned, never client-writable:** `id`, `tenant_id`, `owner_principal_id` (projects);
  `principal_id`, `tenant_id` (memberships). Client-writable on create: `title`, `market`; on update:
  `title`, `status`, plus the `row_version` precondition.
* **Never exposed anywhere:** `principals.email`, `principals.auth_version`.

## 4. Who is who in the fixtures

| Principal | Tenant A | Tenant B | Tenant C (suspended) | Purpose |
|---|---|---|---|---|
| alice | **owner** (sole owner) | none | none | last-owner case, positive control |
| bob | viewer | none | none | viewer writes, guessing tenant B |
| carla | none | **admin** | none | other-tenant admin |
| dave | editor | viewer | none | roles must not bleed across tenants |
| erin (disabled) | editor (active row) | none | none | disabled principal with a live membership |
| frank | editor, **revoked** | none | none | revoked member who still owns project PA1 |
| gina | none | none | owner | suspended tenant (added in M0, D-07) |

| Project | Tenant | Market | Notes |
|---|---|---|---|
| PA1 | A | UK | visible; `owner_principal_id` = frank (revoked) |
| PA2 | A | US | tenant A is **not** permitted US: hidden from everyone in A (TL-08) |
| PB1 | B | US | cross-tenant target |
| PC1 | C | UK | project of the suspended tenant |

Market access: A = UK, B = US, C = UK.

## 5. Owner approval checklist (items 1-6 approved by the owner on 2026-11-19: "approve M0")

1. Is the role/operation table in s1 correct, especially: editors may **create** projects; admins may
   read private contacts and the audit log but **not** change memberships?
2. Do you accept **404** for every "not visible" case, including revoked members, and **403
   `tenant.suspended`** only for active members of a suspended tenant (D-06)?
3. Do you accept evaluating market scope **before** role (D-05), a deliberate deviation from the
   literal order in the shared standard?
4. Do you accept that pre-authentication failures write **no** audit row (log only) and that ordinary
   successful reads are not audited (D-10)?
5. JWT choice (D-03): PyJWT with EdDSA/Ed25519 only, 900 s maximum lifetime, 0 s leeway. Acceptable?
6. The three additions beyond the written spec: the `/me` probe (D-08), the nested invoice route
   (D-09), and fixture principal **gina** with suspended tenant C (D-07).
