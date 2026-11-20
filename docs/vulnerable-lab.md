# The deliberately vulnerable lab (milestone M3) and how it is isolated

Status: **contract written before any M3 test or code.** The owner reviews this isolation design
(spec M3: "Human review isolation"). Decisions: `DECISIONS.md` D-41..D-47.

The vulnerable variant exists for one reason: to be a **known-broken target** that the runner
(`boundarycheck`, the former M4) must detect, next to the patched app that it must pass. It is
synthetic, local and never a product. Spec M3, work order: "Never run tests against external hosts or
deploy the vulnerable router."

## 1. Isolation, layer by layer

Each layer is enforced by code and tested on its own. **The container is the real network boundary**:
an environment variable cannot enforce egress (TL-16), so the flags below are guardrails that fail
closed, not a substitute for the container.

| # | Layer | What enforces it | Tested by |
|---|---|---|---|
| 1 | **Code never reaches the default app** | Nothing outside `lab/vulnerable/` imports it. The default app, the patched layer, the oracle and the runner are checked in a **clean subprocess** (`python -I`) and by an AST scan | TL-16 import tests |
| 2 | **Code is not in the wheel** | `wheel-exclude` removes `tenantlab/lab/vulnerable/` from the built wheel, so installing the package cannot install the broken code; it exists only in a source checkout | a test that builds the wheel and lists it |
| 3 | **Small, one-way imports** | The package may import only `schemas`, `db`, `auth`, `ids`, `config` and the generic `api.middleware`/`api.problems`. It must **not** import the patched gates, handlers, service, routes, the oracle or the runner, and it contains **no network client** (socket, ssl, http.client, urllib.request, urllib3, requests, httpx, aiohttp, websockets, smtplib, ftplib, subprocess) | AST allow-list test |
| 4 | **Start-up guard (hard failure, no fallback)** | `create_vulnerable_app` raises `LabIsolationError` unless: `LAB_MODE` is exactly `1`; `TENANTLAB_ENV` is exactly `lab` or `test` (unset, `production`, `prod`, `staging`, anything else is refused); the bind host, if one is given, is a **literal loopback address**; the database is a SQLite **file**; and **every principal's e-mail ends in `@tenantlab.invalid`** (synthetic data only). It never returns the patched app instead | TL-16 guard tests |
| 5 | **Request guard (independent of how it was started)** | Middleware refuses (`403`) any request whose peer address is not loopback, or whose local server address is a non-loopback IP literal, even if the process was started with `--host 0.0.0.0`. A Unix-socket peer (no IP) is allowed | TL-16 request-guard tests, including IPv4-mapped IPv6 |
| 6 | **Process isolation** | The supported launcher (`python -m tenantlab.lab.vulnerable`) binds a **Unix domain socket** by default (no TCP listener exists) or a loopback TCP address; it refuses `0.0.0.0`, `::`, LAN and hostnames with exit status 2 | launcher tests; every exploit test talks to a **separate process** over the socket |
| 7 | **Container (the network boundary)** | `deploy/Dockerfile.vulnerable-lab` and `deploy/compose.vulnerable-lab.yaml`: `network_mode: none`, no published ports, non-root, read-only root filesystem, all capabilities dropped, `no-new-privileges`, tmpfs for state | compose-file test (no Docker needed) and Docker tests that **run** a self-check inside the container with and without a network (a control proves the check can fail) |
| 8 | **Visible marking** | Every response carries `X-Tenantlab-Vulnerable: deliberately-broken-lab` and the process logs a banner naming the enabled flaws | header and banner tests |

## 2. The four controlled flaws

Each flaw is a named switch (`Flaw`), enabled independently. With **no** flaw enabled the vulnerable
app must behave exactly like the patched app on the routes it implements (status and body, apart from
the request id): a **differential test** proves the flaws are the *only* differences.

| Flaw | OWASP API 2023 | What is broken | Attribution (exploit that works only with this flaw) |
|---|---|---|---|
| `TENANT_PREDICATE_OMITTED` | API1 BOLA | The membership lookup is **not filtered by the object's tenant**: it takes the principal's highest active role in *any* tenant | bob (viewer of A) reads tenant B's project, invoice and list; dave (editor of A, viewer of B) **writes** B's project because his A role applies |
| `ROLE_CHECK_MISSING` | API5 BFLA | The capability gate is skipped | bob (viewer) PATCHes his own tenant's project and reads its private contacts |
| `PRIVATE_PROPERTY_SERIALIZED` | API3 BOPLA | The general project JSON embeds each contact's `email_private` and `phone_private` | bob reads the private sentinel from `GET /v1/projects/{id}` |
| `MARKET_BOUNDARY_OMITTED` | API1 | The market-access gate is skipped | alice reads the hidden-market project PA2, its invoice IA2 and its contacts; the list and its total include PA2 |

The attribution matrix is a test: with exactly one flaw on, only that flaw's exploits succeed.

## 3. What the vulnerable app implements

A subset, enough to demonstrate the four flaws: `GET /v1/tenants/{t}/me` (never flawed: the probe),
`GET /v1/tenants/{t}/projects`, `GET /v1/projects/{id}`, `PATCH /v1/projects/{id}`,
`GET /v1/projects/{id}/contacts`, `GET /v1/invoices/{id}`. Any other route answers the generic `404`.
It writes **no audit rows** (it is a target for the runner, not an audit-faithful model). Authentication
is the real, strict verifier (authentication is not one of the flaws).

## 4. What isolation does **not** guarantee

* A process that runs with a network and a determined local user can be started without the launcher;
  the start-up and request guards then still refuse non-loopback peers, but only the **container**
  removes the network. Run it in the container.
* The guards are written by the same author as the flaws. They are tested and mutation-tested, not
  audited by a third party.
* Loopback is reachable by every process on the same machine; the Unix-socket default narrows that to
  the file permissions of the socket.

## 5. Review checklist for the owner

1. Is the vulnerable code **excluded from the wheel** the right call (it then exists only in a source
   checkout), given that `boundarycheck` will need it as a fixture by Git tag? (D-43)
2. Is **refusing non-synthetic data** (every e-mail `@tenantlab.invalid`) the right data guard? (D-44)
3. Docker tests **fail** (not skip) when Docker is absent; is that acceptable? (D-46)
4. Anything else you want enforced before any of this is used by another tool.
