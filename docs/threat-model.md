# Threat model

Scope: the Tenant Boundary Lab (an intentionally breakable lab, a patched implementation, an
independent oracle and a test runner), run **locally**, with **synthetic** data only. Out of scope:
production systems, third-party targets, real customer tenancy, credential attacks, Internet scanning.

Status at M2: the model was written before any route existed. Section 4a says which mitigations are
now built and tested; those marked *(planned Mx)* in section 4 are still only specified.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Tenant-owned data (projects, invoices) | The cross-tenant boundary is the product |
| Private contact fields | The BOPLA target; synthetic sentinels make leaks detectable |
| Membership / role / market state | The authority every decision rests on |
| Audit trail | Evidence; must be neither silenced nor polluted |
| The oracle (`gates.csv`, `capabilities.csv`, `field_policy.csv`) | If wrong or collusive, every test is meaningless |
| Test signing keys | Forgery capability for the lab token verifier |

## 2. Actors and capabilities

| Actor | Can | Cannot (assumed) |
|---|---|---|
| Anonymous client | Send arbitrary bytes to any route | Hold a valid token |
| Authenticated member | Valid token, one or more memberships | Read/write outside memberships |
| Authenticated non-member | Valid token for a real principal | Any tenant data |
| Revoked/disabled principal | Replay a still-unexpired token | Be authorised |
| Malicious tenant admin | Admin rights in *their* tenant only | Touch another tenant |
| Developer of the app under test | Write code that violates the policy | Edit the oracle unnoticed (review + independence test) |

Attacker model: black-box HTTP client with full knowledge of the API contract, supplying hostile
headers, bodies, query strings, claims and identifiers; **no** database or server access.

## 3. Trust boundaries

```text
  untrusted                         trusted (lab process)                      trusted data
 +-----------+   HTTP/ASGI   +-----------------------------+   SQL    +----------------------+
 | client /  | ------------> | FastAPI app                 | -------> | database (SQLite /   |
 | test      |  [B1]         |  gates 0..11 (deny-default) |  [B2]    | PostgreSQL)          |
 | runner    | <------------ |  authN -> membership -> ... |          | principals, tenants, |
 +-----------+   problem+json+-----------------------------+          | memberships, ...     |
       ^                                |  [B3] audit                 +----------------------+
       |                                v
       |                        audit_events (tenant-scoped, no secrets)
       |
  [B4] oracle (CSV/TOML data, NO imports of app code) --judges--> runner --> JSON/Markdown report
  [B5] vulnerable lab variant (LAB_MODE=1, loopback only, never in the default router)
```

* **B1** client to app: everything is hostile (headers, body, query, claims, identifiers).
* **B2** app to database: bound parameters only; tenant/membership re-read per request.
* **B3** app to audit: only authenticated, attributed events; no tenant pollution; no secrets.
* **B4** oracle to application: one-way independence. The oracle never imports the code it judges.
* **B5** the deliberately vulnerable variant: isolated from the default code path and from the network.

## 4. Threats

Mitigation columns reference gates (`gates.csv`) and cases (`case_catalog.toml`).

| ID | Threat | STRIDE | Mitigation | Verified by |
|---|---|---|---|---|
| T-01 | Forged, unsigned or algorithm-confused token spoofs a principal | S | EdDSA pinned, public key only, signature verified, strict claims (gate 1) | TL-01 |
| T-02 | Replay of expired / not-yet-valid / wrong-audience / over-long tokens | S | Required `iss aud iat nbf exp jti`, 0 s leeway, lifetime <= 900 s (gate 1) | TL-02 |
| T-03 | Client-supplied authority (`X-User`, `X-Role`, `X-Tenant-Id`, `X-Forwarded-For`, body/query/claim `role`) is honoured | E | Authority only from verified token + DB membership; unknown body/query keys rejected | TL-18 |
| T-04 | BOLA: guess another tenant's or object's UUID | I, E | Active membership in the **object's** tenant required before anything else (gate 3) | TL-04, TL-05, TL-08 |
| T-05 | Existence oracle: 403 vs 404, body/header differences, list totals, audit rows, timing reveal hidden objects | I | One 404 shape for every "not visible" case; counts scoped to readable objects; audit rows indistinguishable; timing only smoke-tested | TL-04, TL-19 |
| T-06 | Stale authority: revoked membership, disabled principal, suspended tenant, role downgrade honoured from a cache or token | E | Principal, membership, tenant state and role re-read from the DB on **every** request; no authorization cache | TL-03, TL-13, TL-14, TL-20 |
| T-07 | BFLA: lower role calls a higher-privilege operation | E | Capability gate (6) from the default-deny matrix | TL-06 |
| T-08 | BOPLA: private properties serialised on general surfaces | I | Private fields only on the `contacts.private` surface; no field-stripping fallback | TL-09 |
| T-09 | Mass assignment of `tenant_id`, `owner_principal_id`, `id`, `role` | T, E | Strict request models (`extra=forbid`), server-owned fields never read from input | TL-06, TL-15, TL-18 |
| T-10 | Parent/child confusion: project A with invoice B | I | Nested route resolves the invoice **through** the path project and tenant | TL-07 |
| T-11 | Write-then-deny: mutation committed, then a 403 is returned | T | Checks precede side effects; the runner compares DB state before/after, not just status | TL-17 |
| T-12 | Lost update / race on `row_version`, membership or market access | T | Optimistic `row_version`; transactional re-read; PostgreSQL row locks tested on PostgreSQL | TL-12, TL-20 *(planned M5)* |
| T-13 | Audit poisoning or flooding: attacker writes events into another tenant's log, or anonymous traffic fills the table | R, D | Pre-auth failures are log-only; denials for non-members carry tenant NULL; tenant audit endpoint filters on `tenant_id`. Authenticated-denial flooding is a **residual risk** (LIMITATIONS L-05) | TL-01, TL-03, TL-04 |
| T-14 | The intentionally vulnerable variant is reachable from a network or production | E, I | `LAB_MODE=1` + loopback + non-production env or hard startup failure; module never imported by the default app; container without egress *(planned M3)* | TL-16 |
| T-15 | Oracle collusion: expected results derived from the code under test | R | Declarative CSV/TOML, AST import guard, spec prose encoded a second time in contract tests | `test_oracle_independence.py`, matrix contract tests |
| T-16 | Secrets or real data committed (signing keys, tokens, real emails) | I | Keys generated in memory per run; `.gitignore` blocks keys/db/env; fixtures use the reserved `.invalid` TLD; fixture credential scan test | `test_fixtures_contract.py` |
| T-17 | Resource exhaustion: huge body, hostile pagination, deep input | D | 64 KiB body cap before auth, limit 1..100, cursor length cap, strict models, statement-count ceiling | TL-10, TL-15 |
| T-18 | Log injection through request ids / headers / titles | T, R | Server-generated UUID request ids only; structured logs; fixed `detail` strings | TL-18 |
| T-19 | Runner misreports an infrastructure failure as a clean result | R | Distinct exit codes 0 clean / 1 violation / 2 infrastructure error; unavailable DB is an error, never a pass | *(planned M4)* |
| T-20 | Dependency or supply-chain compromise | T | Lockfile with hashes, bounded ranges, `pip-audit`; CI pinning *(planned M5)* | `pip-audit` (run at M0) |

## 4a. Implementation status (M2)

| Threat | Status | Evidence |
|---|---|---|
| T-01, T-02 token forgery and replay | **Built** (gate 1) | TL-01, TL-02, `test_token_verifier.py`, mutation: signature/exp/nbf/iat/aud/iss/lifetime/leeway/required claims |
| T-03 client-supplied authority | **Built** | TL-18 (headers, query, body, token claims) |
| T-04, T-05 BOLA and existence oracle | **Built for tenants, projects, invoices** (gates 3, 5) | TL-03, TL-04, `test_m1_gate_pipeline.py` (market scope, invoice coherence, ghost-vs-hidden equality). Counts and timing: M2 / TL-19 |
| T-06 stale authority | **Built** (re-read every request) | TL-03, TL-05, TL-14, market-access test |
| T-07 BFLA | **Built** (gate 6 for every route, default deny; app table equals the oracle) | TL-05, TL-06, TL-11, TL-18, `test_app_policy_matches_oracle.py` |
| T-08 BOPLA | **Built** (private fields on one surface; 403 not a stripped 200; field sets equal the oracle) | TL-09 over every surface and role, `test_m2_operations.py` |
| T-09 mass assignment | **Built** (strict models, unknown keys 422, owner and tenant server-set) | TL-06 (every server-owned field on every body route), TL-15 |
| T-10 parent/child confusion | **Built** (invoice resolved through the path project and the same tenant) | TL-07, `test_m1_gate_pipeline.py` |
| T-11 write-then-deny | **Partly**: every check precedes the write and denials leave all business tables identical; the runner's before/after diff is M4 | TL-06, TL-08, TL-10, TL-15, TL-17 *(planned M4)* |
| T-12 lost update and races | **Built for SQLite**: version compare-and-set; authority, quota and last owner re-checked inside the write statement; PostgreSQL proof is M5 | TL-11, TL-12, `test_m2_races.py`, `test_patched_service.py` |
| T-13 audit poisoning, pre-auth flooding | **Built** (tenant NULL rule, no pre-auth rows, allow rows atomic with the change); authenticated flooding is residual (L-05) | TL-01..04, `test_m1_gate_pipeline.py`, `test_m2_operations.py` |
| T-15 oracle collusion | **Built both ways** (D-21, now including `lab/patched`) | `test_oracle_independence.py`, `test_app_independence.py` |
| T-16 committed secrets | **Built locally**: no key on disk; gitleaks finds nothing in history or tree, and a canary proves the scanner works; CI gate is M5 (L-12) | `tools/secret_scan.py`, `test_settings.py` |
| T-17 resource exhaustion | **Mostly**: body cap, limit 1..100, cursor cap, quota 1 000, embedded contacts 100, statement ceiling independent of data; no rate limit (L-19) | TL-10, TL-15, `test_m2_input.py` |
| T-18 log injection | **Built** (server-generated ids; fixed log fields; no token/body in logs) | TL-18, log tests |
| T-14, T-19, T-20 | Not yet (M3-M5) | n/a |

## 5. Explicit non-goals and caveats

* No claim that a status code is sufficient evidence: every no-mutation case also requires unchanged state.
* Timing side channels: a gross-difference smoke test only. Constant-time behaviour is **not** claimed.
* SQLite cannot represent PostgreSQL row-locking; concurrency conclusions require PostgreSQL (M5).
* In-process ASGI proves application logic, not network-layer defenses (TLS, proxies, WAF).
* A passing test suite shows the listed cases pass. It is not proof of security.

## 6. Open risks at M2

See `LIMITATIONS.md`. The most important: concurrency is proven only on SQLite (the statements are
written to be race-safe, but PostgreSQL row-lock behaviour is M5, L-08, L-22); there is no vulnerable
variant, runner or CI yet; the M2 decisions D-31, D-32, D-34, D-37 and D-38 in `DECISIONS.md` are
marked "owner approval" and are not yet approved; no SAST or secret scanner has been run (L-12).
