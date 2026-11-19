# Tenant Boundary Lab

An isolated lab, an **independent policy oracle** and a Python runner for **API authorization
regression testing**: tenant isolation, BOLA, BFLA, BOPLA/property exposure, mass assignment, nested
resources, revocation and concurrency. It tests the *effects* (data disclosed, state changed), not just
status codes: a `403` that arrives after a database write is a failure.

> **Status: milestone M1 (identity and deny-by-default gates).** Authentication, tenant membership,
> tenant state, market scope and role checks are built and tested; only the context probe
> `GET /v1/tenants/{id}/me` has a real handler. The other routes pass the gates and then answer
> `501` until M2. There is no vulnerable variant, runner or report yet.
> See [LIMITATIONS.md](LIMITATIONS.md), [docs/milestones/M1.md](docs/milestones/M1.md) and
> [docs/milestones/M0.md](docs/milestones/M0.md).

OWASP terminology is API Security Top 10:2023 (API1 BOLA, API2 Broken Authentication, API3 BOPLA,
API4 Unrestricted Resource Consumption, API5 BFLA, API8 Security Misconfiguration).

## Safety

Local, synthetic, in-process only. Tests use `httpx.ASGITransport` (no sockets); all data is fictional
(`.invalid` e-mail domain); signing keys are generated in memory per run and never written to disk.
A deliberately vulnerable variant arrives in M3 and is designed to refuse to run outside
`LAB_MODE=1` on loopback. Never deploy it. Never aim any of this at systems you do not own. See
[SECURITY.md](SECURITY.md).

## Quick start

Requires [`uv`](https://docs.astral.sh/uv/) and Python 3.13 (`uv python install 3.13`).

```bash
uv sync                                # installs the locked dependency set into .venv
uv run pytest -q                       # everything: expected GREEN (no skips, no xfails)
uv run pytest -m milestone -q          # only the tests written red-first for M1 (now green)
uv run ruff check . && uv run ruff format --check . && uv run mypy
uv run python tools/mutation_m1.py     # optional, ~6 min: inject 69 security bugs, expect all caught
```

A test marked `milestone("M1")` was written *before* its code and failed with
`NOT IMPLEMENTED (milestone M1)` until M1 shipped; it was never skipped, xfailed or edited to pass.

## How it works (design)

```text
fixtures + token --> FastAPI app (patched | vulnerable) --> gates 0..11, deny by default --> audit
                                  ^
              httpx.ASGITransport |   in-process
oracle data (CSV/TOML, never imports app code) --> runner --> state diff --> JSON/Markdown, exit 0/1/2
```

The expected behaviour lives in declarative data under `src/tenantlab/oracle/data/`, written **before**
the application, so the thing that judges cannot inherit the bugs of the thing being judged. An AST
test enforces that the oracle imports no enforcement code.

## What exists today (M0 and M1)

| Area | Where |
|---|---|
| Role x operation matrix, ordered gates, property policy | `src/tenantlab/oracle/data/*.csv` |
| 20 test cases (TL-01..TL-20) with OWASP mapping and exact evidence | `src/tenantlab/oracle/data/case_catalog.toml` |
| Synthetic fixtures with trap rows | `src/tenantlab/lab/fixtures/fixtures.toml` |
| RFC 9457 error contract | `src/tenantlab/schemas/errors.py` |
| Settings, token verifier (EdDSA only), route registry, gate pipeline, `/me` | `src/tenantlab/{config,ids}.py`, `src/tenantlab/auth/`, `src/tenantlab/api/` |
| Schema, Alembic migration `0001`, deterministic seed | `src/tenantlab/db/` |
| Contract and unit tests | `tests/unit/` |
| Behavioural tests for TL-01..05, 14, 18 and the gate pipeline | `tests/negative/test_m1_*.py` |
| Mutation check of the M1 code | `tools/mutation_m1.py` |
| Design | [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md), [docs/authorization-matrix.md](docs/authorization-matrix.md), [docs/api-contract.md](docs/api-contract.md), [docs/test-matrix.md](docs/test-matrix.md) |
| Decisions and residual risk | [DECISIONS.md](DECISIONS.md), [LIMITATIONS.md](LIMITATIONS.md) |

## Roadmap

| Milestone | Delivers |
|---|---|
| **M0** (done, approved) | Contracts, oracle data, fixtures, threat model, failing tests. |
| **M1** (done, approved) | Schema and migrations, seeds, token verifier, deny-by-default gates (TL-01..05, 14, 18) |
| M2 | Patched API: projects, invoices, contacts, membership, field projection, audit (TL-06..13, 15, 19) |
| M3 | Deliberately vulnerable lab with four controlled flaws, isolation guard (TL-16) |
| M4 | Runner, oracle engine, state diff, reports, exit codes 0/1/2 (TL-17) |
| M5 | PostgreSQL concurrency, Hypothesis properties, pinned CI, dependency/secret/SAST gates (TL-12, TL-20) |
| M6 | Redacted sample reports, diagram, release |

License: not yet chosen (owner decision, see DECISIONS D-16).
