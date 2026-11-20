# `boundarycheck`: product design brief (v0.1) — FOR OWNER REVIEW

Status: **design only. Nothing in this file is implemented.** Every command, option, file name and
schema below is **proposed**. No repository has been created, nothing has been published, and no
package name is reserved. Source: `OPEN_SOURCE_TOOL_PRODUCTIZATION_ADDENDUM.md` s0, s1, s7, s8, read
together with `01_tenant_boundary_lab.md` and the shared standard.

Date: 2026-11-19. Review checkpoint required by the addendum (s8): this design decides **egress,
identity/token handling and report privacy**, so it stops here until you approve or amend s12.

## 1. What it is, in one paragraph

`boundarycheck` takes a description of an API that **you operate or are authorized to assess**: who
the principals are, what each is *supposed* to be allowed to do, which objects exist in which tenant,
which routes map to which actions. It then replays a bounded set of requests as each principal and
compares what **actually** happened with what the **independent, declared** policy says should
happen. Output is a reproducible matrix of expected versus observed access with every result in one
of six honest states (s7), as JSON and Markdown. It never infers "allowed" from a status code alone,
and "I saw nothing wrong" is a different state from "this is safe".

The existing `tenantlab` package stays what it is: an isolated lab and test fixture. The product is
the generalisation of the lab's **runner and oracle** (milestone M4) to *any* API, with the lab as the
first adapter and the reference fixture.

## 2. Target user and first useful task

* **User:** an AppSec engineer, or a backend engineer on a multi-tenant API, with fixture accounts in
  a staging or local copy of their own service.
* **First useful task (the 10-minute path):** "Here are my three test users and the two tenants
  they belong to. Tell me, route by route, whether user A can read tenant B's object, whether a
  viewer can reach an admin route, and whether a hidden-market object is distinguishable from a
  missing one."
* **Not the user:** someone assessing a third party. The tool cannot grant itself authorization and
  does not try to (s5).

## 3. Install and run experience (proposed commands)

```text
# from a trusted clone, in a virtual environment (editable, for development)
python -m pip install -e '.[dev]'
# or, once it is a real console script:
pipx install .            # or: uv tool install .

boundarycheck init --output boundarycheck.yaml      # writes an annotated, SAFE-by-default template
boundarycheck validate --config boundarycheck.yaml  # schema + scope + policy lint; no network
boundarycheck test --config boundarycheck.yaml --transport fixture
boundarycheck test --config boundarycheck.yaml --transport live --ack-authorization
boundarycheck report --run RUN_ID --format json|md
boundarycheck list-runs
boundarycheck purge --older-than 30d                 # bounded retention
```

`--ack-authorization` is a **human attestation that is recorded in the report**. It is not proof of
anyone's permission, and the report says so.

The offline demo (v0.1 acceptance) needs no network, no credentials and no external service: the
fixture transport drives an in-process ASGI app with ephemeral keys.

## 4. What v0.1 asserts, and what it does not

| It asserts (and can show) | It does **not** assert |
|---|---|
| Read-path authorization: BOLA across tenants, BFLA on read routes, hidden-market objects, nested-resource confusion, property exposure on responses | That writes are protected (live mode is read-only; write checks exist only on the **fixture** transport with a state-snapshot adapter, s9) |
| For each case, the expected decision came from the declared policy, never from the target | That the declared policy is *right*: the tool cannot invent the target's business rules (s0.7) |
| A 404 that is byte-for-byte identical for hidden vs missing objects (status, headers minus request id, body shape) | Constant-time behaviour or the absence of timing channels |
| Which cases were run, skipped or could not be decided | Coverage of routes that are not in the config |
| The run is reproducible from config + fixture | That an `no_issue_observed` result means "secure" |

## 5. Contracts (all proposed)

### 5.1 Typed model (Python API sketch)

```text
Principal            key, label, credential_source  (env var name | keychain item | fixture-minted)
MembershipAssertion  principal, tenant, role, status           # what the assessor says is true
ResourceRef          key, kind, tenant, attributes{market,...}, path_ids{param -> value}
Action               id, method, path_template, response_surface, mutating: bool
ExpectedDecision     outcome in {allow, deny_forbidden, deny_not_found, deny_unauthenticated},
                     visible_fields: set | None           # the declared projection, if any
RequestTemplate      action, principal, resource, params, body: None in live mode
BoundaryCase         id, family, principal, action, resource, expected, notes
RunResult            run_id, schema_version, tool_version, cases[], findings[], limitations[]
EvidenceRef          sha256, kind, redaction_version        # hash of the REDACTED blob
```

Python entry points (proposed, small on purpose): `boundarycheck.load_config(path)`,
`boundarycheck.plan(config) -> list[BoundaryCase]`, `boundarycheck.run(config, transport) -> RunResult`,
`boundarycheck.render(result, "json"|"md")`. The CLI is a thin Typer layer over these.

### 5.2 Config (YAML, proposed shape; secrets are never in it)

```yaml
version: 1
scope:
  id: staging-2026-11            # names this assessment in every report
  targets:
    - label: staging-api
      base_url: https://api.staging.example   # live only; the fixture transport ignores the host
      allowed_methods: [GET, HEAD]
      allowed_hosts: [api.staging.example]      # exact host allowlist, no wildcards
      rate_limit_rps: 2
      request_budget: 500
principals:
  alice: {label: "tenant A owner", credential: {env: BC_TOKEN_ALICE}}
  bob:   {label: "tenant A viewer", credential: {env: BC_TOKEN_BOB}}
memberships:
  - {principal: alice, tenant: A, role: owner,  status: active}
  - {principal: bob,   tenant: A, role: viewer, status: active}
resources:
  - {key: PA1, kind: project, tenant: A, attributes: {market: UK}, path_ids: {project_id: "5000..."}}
actions:
  - {id: project.read, method: GET, path: "/v1/projects/{project_id}", surface: project.detail}
policy:                           # the independent oracle: authored by the assessor
  capabilities: {project.read: [owner, admin, editor, viewer]}
  visibility: {hidden_is_not_found: true}
  fields: {project.detail: {viewer: [id, title, status]}}
```

Parsed with a **hardened** loader: `yaml.safe_load` only, a hard size cap, aliases and anchors
rejected (alias expansion is a denial-of-service vector), strict Pydantic schema with
`extra="forbid"`, duplicate keys refused, and every path/id validated before use.

### 5.3 Adapter protocols (so users map their own auth, routes and ids)

```text
IdentityAdapter   credential(principal) -> Credential           # fixture | env | keychain
Transport         send(RequestTemplate) -> Observation         # fixture-ASGI | restricted-HTTP
SnapshotAdapter   snapshot() -> Snapshot                        # OPTIONAL: only if the target supplies
                                                                #   a safe, read-only state snapshot
```

A missing `SnapshotAdapter` means state-delta claims are **not made**; the report lists that as a
limitation instead of silently omitting the check.

## 6. Identity and authorization model

1. **Identities under test are separate from the operator.** The tool holds only *test principals'*
   credentials, supplied at run time from environment variables or the OS keychain (an optional
   extra), never from the config file and never printed.
2. **Nothing the target returns about identity is authoritative.** Roles, tenants and memberships come
   from the assessor's `memberships:` block. A `tenant_id` or `role` in a response is *data to
   compare*, not truth.
3. **The tool does not decide who may be tested.** A scope file restricts what the tool will touch; it
   is not consent. Live mode requires `--ack-authorization`, which is logged with the run id and
   appears in the report header as "attested by the operator; not verified".
4. **Credentials in the fixture transport** are minted per run with an ephemeral Ed25519 key (the same
   technique as `tests/harness.py`) and never written to disk.

## 7. Status model and exit codes

Per-case status (the addendum's s0.8 vocabulary, nothing collapsed):

| Status | Meaning |
|---|---|
| `no_issue_observed` | Observed outcome equals the declared expectation. **Not** "secure". |
| `finding_candidate` | Observed differs from expected. A human reviews it (`review_state`). |
| `policy_denied` | The tool refused to send the request (out of scope, method not allowed, budget exhausted). |
| `not_run` | Skipped for a stated reason (for example no credential supplied). |
| `incomplete` | Started but did not finish (timeout, interrupted, partial response). |
| `error` | The tool or transport failed (including a redaction failure). |
| `inconclusive` | Ran fine but the response cannot be mapped to a decision (ambiguous 401/403/404 semantics, unparseable body). **The default whenever a status code is ambiguous.** |

Exit codes (same convention as the lab's runner): `0` only if **every** case is `no_issue_observed`;
`1` if any `finding_candidate`; `2` for anything else (any `error`, `incomplete`, `not_run`,
`policy_denied`, `inconclusive`, or a usage error). A failed or partial run can therefore never look
clean. A later option may let an operator *accept* a named `inconclusive` case with an owner and an
expiry, but never silently.

Report fields follow the shared schema: `id, tool_version, rule_id, status, severity, confidence,
scope_id, target_label, observed_at (UTC), expected, observed, redacted_evidence_refs (SHA-256),
limitations, remediation, review_state`. JSON is the source of truth; Markdown is presentation. SARIF
is **not** produced (a runtime observation has no honest source location).

## 8. Architecture

```text
CLI -> config loader + scope/policy validator -> case planner
    -> IdentityAdapter [fixture | env | keychain]
    -> Transport      [fixture-ASGI | restricted-HTTP]   <- budget, rate limit, allowlist, no proxy env
    -> Oracle         (declared policy; imports NOTHING from the target or its adapter)
    -> Comparator     (status + headers + body shape + declared field projection)
    -> [SnapshotAdapter -> state-delta verifier]          (optional, fixture only in v0.1)
    -> Redactor -> Evidence store (SHA-256 of the redacted blob) -> JSON / Markdown report
```

* **Independence is structural.** As in the lab, an AST test forbids the oracle and comparator from
  importing the target's code or the adapter that talks to it, so a bug in the thing being judged
  cannot be mirrored into the judge.
* **Package layout (proposed):** `src/boundarycheck/{cli.py, config.py, domain/, adapters/, services/,
  report/}`, plus `tests/{unit,integration,security_negative,packaging}` and `examples/`.

### 8.1 What carries over from `tenantlab` and what must change

| In `tenantlab` today | In `boundarycheck` |
|---|---|
| `oracle/data/` CSV and TOML files (the lab's policy) | Becomes the **example** policy for the lab adapter; the product reads the user's `policy:` block |
| `oracle/matrix.py` fail-closed loaders | Generalised into the policy loader (default deny, unknown role or operation denied) |
| `tests/harness.py` token mint, snapshot, `assert_problem` | Becomes the **fixture transport** and the evidence/diff helpers |
| Case catalog TL-01..20 | Becomes the first rule pack (`rule_id` per family) |
| Mutation tools, statement-count and timing helpers | Reused as the product's own test tooling |
| FastAPI app, fixtures, migrations | Stay in `tenantlab`; used only as the reference **target** |

## 9. Live transport: egress and request safety (proposed rules; needs your review)

All of these are properties of the **tool**. None replaces network-level controls the operator must
provide, and the documentation will say so plainly.

1. **Opt-in and attested.** Live mode only with `--ack-authorization`, an `allowed_hosts` list of
   exact hostnames and ports, and a request budget. Nothing is scanned because it "appears in a
   config".
2. **Methods:** `GET` and `HEAD` only in v0.1. A template with any other method on the live transport
   is `policy_denied` before a socket opens.
3. **Destination checks:** resolve the host, refuse private, loopback, link-local, reserved and
   cloud-metadata ranges (IPv4, IPv6 and IPv4-mapped IPv6) unless the operator sets
   `allow_private: true` **and** the host is on the allowlist; then verify the **connected peer** is
   the address that was checked (DNS rebinding); normalise IDN and refuse ambiguous hosts.
4. **No surprises:** `trust_env=False` (no proxy variables), redirects disabled by default (a
   redirect to another host is `policy_denied`), response and decompressed-body size caps, per-request
   and total timeouts, bounded concurrency, a global rate limit.
5. **Errors never become results:** a timeout, 429 or 5xx is `incomplete` or `inconclusive`, never
   `no_issue_observed`.
6. The tool states in its output that it cannot guarantee egress filtering; the supported way to
   contain it is a container or network ACL outside the process.

## 10. Redaction and the evidence store

* Raw response bodies, cookies, `Authorization` headers and token values are **never** stored in the
  default report. The evidence store keeps the **redacted** blob and its SHA-256. A hash proves byte
  integrity of what was stored; it does **not** prove where the bytes came from, and the docs say so.
* Redaction is pattern-based (tokens, JWT shapes, emails, long hex/base64) plus caller-supplied
  **field masks**. If redaction cannot complete, the case is `error` and the blob is discarded.
* Runs live under a configurable directory (`.boundarycheck/runs/RUN_ID/`), with bounded retention and
  `purge`. A permissions check refuses to write to a world-writable directory.
* A canary secret test runs on every release candidate: a fake token placed in a request must appear
  nowhere on disk or in either report format.

## 11. Threat model for the tool itself (summary)

| Threat | Control |
|---|---|
| A hostile or buggy target response (huge, compressed, malformed, instruction-laden) | size and decompression caps, strict parsing, no evaluation of response content, no model in v0.1 |
| Config as an attack vector (alias bomb, path traversal in ids, ambiguous hosts, duplicate keys) | hardened loader, schema, id and host validation, size cap |
| SSRF / out-of-scope requests via redirect, DNS rebinding, IPv6 tricks | s9 |
| Credential leakage (config, logs, reports, CLI history, crash output) | credentials only from env or keychain, never echoed, redaction + canary test, exceptions never include request headers |
| The operator mistaking `no_issue_observed` for "secure" | six-state vocabulary, exit codes, limitations section in every report |
| Oracle collusion (expected derived from the target) | structural independence test, policy comes only from the assessor |
| Tool failure reported as success | exit code `2` for everything that is not clean; infrastructure errors are never `0` |
| Supply chain (dependencies, release) | locked, hash-pinned dependencies, `pip-audit` and secret scan in CI, trusted publishing only after owner approval |

## 12. DECISIONS (answered by the owner on 2026-11-19)

| # | Decision | Answer |
|---|---|---|
| 1 | Repository shape | **Approved:** `boundarycheck` is its own repository, with `tenant-boundary-lab` as its reference target and fixture. Creating the GitHub repository still needs a separate "yes" at the moment it is created (addendum s8); work starts in a local directory. |
| 2 | M4 plan change | **Approved:** the lab's M4 runner and oracle engine is built once, as `boundarycheck`; the lab's demo becomes a thin client of it. |
| 3 | Ordering | **Approved:** lab milestone M3 (with isolation review) first, then the `boundarycheck` engine. |
| 4 | Live transport | **Resolved by me (the owner asked "what is best, I want it easy to use"):** v0.1 ships the fixture transport **plus a loopback-only live transport** (s12.1). Remote hosts are v0.2. The owner may overrule. |
| 5 | Config and credentials | **Approved:** YAML with the hardened loader (s5.2); credentials from environment variables always, OS keychain as an optional extra. |
| 6 | Exit semantics | **Approved:** `0` only when every case is `no_issue_observed`. |
| 7 | Name | **Approved:** `boundarycheck` (re-check availability before any publication). |
| 8 | Licence | **Still open** (D-16). Needed before any public release, not before development; the repositories stay private. |

### 12.1 Live transport, resolved: easy AND safe

The common case is a developer testing the API they run on their own machine or as a CI service
container, which is always on loopback. So v0.1 live mode is **loopback-only**:

* One command: `boundarycheck test --live` against `http://127.0.0.1:PORT` (or `[::1]`, or a name that
  resolves only to loopback). No per-run attestation flag, because the tool itself connects only to loopback addresses. *Correction (2026-11-19):* this does NOT mean the traffic cannot leave the machine. The tool cannot see where a loopback listener forwards (an `ssh -L` tunnel or a local proxy on 127.0.0.1 can reach a remote host), so the guarantee is about the tool's own sockets, and the operator stays responsible for what is behind the port (boundarycheck `LIMITATIONS.md` BL-11).
* Enforced by the tool, not by convention: the **connected peer** must be a loopback address (checked
  after connect, which also defeats DNS rebinding); a redirect to any other host is `policy_denied`;
  `GET`/`HEAD` only; request budget and rate limit; `trust_env=False` (no proxy variables); size and
  time caps.
* A remote host in the config is **refused with a message that says exactly what v0.2 will require**,
  not silently ignored and not allowed.
* Ease of use that stays safe: `boundarycheck plan` prints every request it would send (a dry run, the
  default for `init` output) and `boundarycheck init --from-openapi FILE` drafts the actions from an
  OpenAPI document the user already has, leaving the policy for the assessor to write.
* v0.2 adds allowlisted remote hosts with the attestation, DNS-rebinding, IPv6 and metadata-address
  rules of s9, and an interactive "this will contact these hosts as these users" confirmation
  (`--yes` for CI).

## 12a. The questions as originally asked


1. **Repository shape.** Recommended: start `boundarycheck` as its **own repository** (separate
   packaging, README, SECURITY.md, versioning, issue tracker), with `tenant-boundary-lab` as its
   reference target and test fixture, referenced by tag. Alternative: a second package inside this
   repository until v0.1. Creating a repository needs your separate approval.
2. **Plan change for M4.** The lab's M4 ("runner and oracle engine") and `boundarycheck` are the same
   engine. Recommended: build that engine **once**, as `boundarycheck`, and make the lab's
   `python -m tenantlab.cli demo --mode compare` a thin client of it. This changes the M4 deliverable
   and where its code lives.
3. **Ordering.** The addendum's acceptance needs a synthetic **vulnerable** fixture and a patched one
   (v0.1 acceptance above). That is lab milestone M3, whose isolation design you wanted to review.
   Recommended order: M3 (with isolation review) first, then the `boundarycheck` engine, with design
   and packaging work in parallel now.
4. **Live transport in v0.1 at all.** Recommended: ship v0.1 with the **fixture transport only** and
   add the restricted live transport in v0.2 after the egress rules in s9 are implemented and tested.
   The addendum permits live mode in v0.1; I am recommending the safer cut.
5. **Config format and credentials.** YAML with the hardened loader (s5.2) versus TOML (stdlib,
   smaller attack surface, no alias problem). Credentials from env vars always; OS keychain as an
   optional extra. Please confirm.
6. **Exit semantics.** `0` only when every case is `no_issue_observed` (s7), which makes any
   inconclusive case fail the run. Confirm this is wanted as the default.
7. **Name.** `boundarycheck` is free on PyPI today (all three spellings returned 404 on 2026-11-19);
   two unrelated GitHub repositories use similar names (a shot-boundary video project and an empty
   one). Availability can change and this is not a trademark search. Confirm or choose another.
8. **Licence** (still open, D-16). It must be chosen before any public release; it also decides whether
   the product can be Apache-2.0 or MIT while the lab stays separately licensed.

## 13. Vertical-slice backlog (priority order)

| Slice | Delivers | Needs |
|---|---|---|
| **S0** design (this file) | Reviewed contracts, boundaries, decisions | your answers to s12 |
| **S1** offline core | Config loader, typed model, oracle, comparator, fixture transport against the **patched** lab, JSON report, `validate` and `test --transport fixture`; negative tests for malformed config, duplicate ids, redaction canary | decisions 1, 2, 5, 6 |
| **S2** vulnerable fixture | Detects **specific** violations on the M3 lab and passes the patched lab; one documented false positive and one `inconclusive` example | lab milestone M3 |
| **S3** reports and runs | Markdown report, `list-runs`, `report`, `purge`, evidence store, retention, reproducibility test | S1 |
| **S4** distribution | Wheel and sdist, clean-environment install smoke test, `pipx` instructions, SECURITY.md, CHANGELOG, first tag (no PyPI until you approve) | S1-S3, decision 8 |
| **S5** (v0.2) restricted live transport | The s9 rules, with DNS-rebinding, redirect, IPv6-mapped and proxy tests | decision 4 |

Definition of done for v0.1 follows the addendum: a stranger clones, installs, runs `boundarycheck
--help`, executes the sample config offline, reads a report that distinguishes finding, inconclusive
and not-run, and the negative suite passes. No badge before its workflow has actually run.

## 14. Gaps and tensions I found in the addendum (so you can overrule me)

* It lists the **live** transport in v0.1 while also saying live mode is unavailable without network
  controls the tool cannot itself verify. I resolved that by recommending fixture-only for v0.1
  (decision 4); say if you want live in v0.1 anyway.
* The lab's most important cases (TL-06, TL-11, TL-12, TL-17) **write**. The addendum forbids writes in
  live mode, so those cases survive only on the fixture transport with a snapshot adapter. The product
  therefore proves read-path authorization everywhere and write-path behaviour only where the target
  supplies a snapshot. This is stated as a limitation, not hidden.
* The example `pyproject.toml` uses `hatchling`; the lab uses `uv_build`. Both are fine; I would keep
  one build backend per repository and decide when the repository shape is settled.
* "Python-first" with YAML configuration: the loader is the only place user-controlled structure is
  parsed, so it gets the most hardening and the most negative tests.

## 15. Not in v0.1

Write or destructive checks in live mode, credential attacks, discovery of routes or hosts, any model
or external API call, SARIF output, Internet-wide anything, GitHub Actions integration, PyPI publishing.
