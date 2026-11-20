# Sample reports: broken versus fixed

Real output of [boundarycheck](https://github.com/MDPorsch/boundarycheck) run against this lab, kept as
evidence of what a report looks like and of the one claim this milestone exists to show: **a lab that
writes first and refuses afterwards returns exactly the right status codes, and only a state diff sees
it.**

| Report | Target | Result |
|---|---|---|
| [01-patched](01-patched.report.md) ([json](01-patched.report.json)) | the patched lab | 419 cases, all `no_issue_observed`, exit 0 |
| [02-role-check-missing](02-role-check-missing.report.md) ([json](02-role-check-missing.report.json)) | vulnerable, `ROLE_CHECK_MISSING` | 286 cases, 5 findings (`BC-ROLE-01`: three private-contact reads and two **write** exploits), exit 1 |
| [03-write-before-authorization](03-write-before-authorization.report.md) ([json](03-write-before-authorization.report.json)) | vulnerable, `WRITE_BEFORE_AUTHORIZATION` | 286 cases, 21 findings, **all `BC-MUTATION-01`**: the answer was the correct 403/404 and the row had changed, exit 1 |
| [04 reads only](04-write-before-authorization-reads-only.report.md) ([json](04-write-before-authorization-reads-only.report.json)) | the **same** flawed lab, writes left out (`--reads-only`) | 249 cases, **all clean, exit 0**. This is what a status-only runner reports about report 03's lab |

A [terminal transcript](terminal-transcript.md) shows the four commands and their output. It is a
**transcript, not a screencast**: nothing was recorded, so it has no timing.

## Provenance (so you can reproduce them)

| | |
|---|---|
| generated | 2026-11-20 |
| runner | boundarycheck at commit `7e83533` (version `0.1.0.dev0`), from a fresh `git clone --recurse-submodules` and `uv sync` |
| target | this repository at commit `c64f948` (the pinned submodule of that boundarycheck commit) |
| commands | `uv run boundarycheck test --config examples/lab.yaml --transport fixture`, and `examples/lab-vulnerable.yaml` with `--fixture-flaws NAME` (and `--reads-only` for report 04) |

Run ids, timestamps and the SHA-256 references to the stored evidence differ on every run; the case
table does not (the run is deterministic).

## Why they are safe to publish

* **Synthetic only.** Every identifier is a fixture id from `fixtures.toml`; every e-mail ends in
  `@tenantlab.invalid`; there are no credentials (the lab's tokens are minted in memory per run).
* **No response bodies.** A report holds statuses, rule ids, the *names* of fields and table/key/kind
  of each changed row, and SHA-256 references to evidence that is **not** included here.
* **Redaction before storage**, and a scan for every credential used in the run before anything is
  written (boundarycheck `docs/contract.md` s7).

## What they do not show

`no_issue_observed` is not "secure" (every report says so). Report 01 is clean against the declared
policy and the five flaws, nothing more. The state diff covers database rows, not side effects outside
the database. See [LIMITATIONS.md](../../LIMITATIONS.md).
