# Limitations and residual risk

Current state: **milestone M1 (identity and deny-by-default gates).** Stated plainly so nothing is
mistaken for more than it is.

| ID | Limitation |
|---|---|
| L-01 | **There is still no vulnerable variant, runner, report or CI** (M3, M4, M5). Everything the repository demonstrates is the patched side: a green suite shows the listed cases pass against the patched code, not that the runner can tell a broken service from a fixed one. |
| L-02 | **Mutation testing samples bug classes; it does not prove their absence.** `tools/mutation_m1.py` (69 bugs in the gates, verifier and middleware) and `tools/mutation_m2.py` (49 bugs in the handlers, write statements, parser and pager) are all caught by the suite, but they are the bugs I thought of. An equivalent mutant (`alg_confusion`) is caught only on the verifier's internal reason. |
| L-03 | The oracle is **data and a loader**. The evaluation engine, case generator and state-diff runner arrive in M4. Today the oracle is checked only by contract tests that encode the same spec prose a second time. |
| L-04 | A `pytest` pass shows that the listed cases pass. It is not proof of security. Coverage percentage is not proof either. |
| L-05 | **Audit flooding** by an authenticated principal who deliberately triggers denials remains possible after M1 (pre-authentication noise is log-only, but post-authentication denials write rows). Planned mitigation (per-actor rate limit / coalescing) is not designed yet. |
| L-06 | Ordinary successful reads are not audited (D-10): the audit trail shows denials and mutations, not who read what. |
| L-07 | **Timing side channels** are not eliminated and cannot be proven absent; only a gross-difference smoke check is planned (TL-19). |
| L-08 | **SQLite does not model PostgreSQL row locking.** Concurrency cases (TL-12, TL-20) are not trustworthy until run on PostgreSQL in M5. Docker is not installed on the development machine yet; a PostgreSQL instance must be provided for M5. |
| L-09 | In-process ASGI tests validate application logic only: not TLS, reverse proxies, header normalisation by a real proxy, or network exposure. |
| L-10 | `auth_version` exists in the schema but is **reserved and unused**: revocation is by principal status, membership and tenant state re-read per request, not by token versioning. There is no token revocation list; a token stays cryptographically valid until `exp` (at most 900 s) but is useless once the principal, membership or tenant state changes. |
| L-11 | All data is synthetic. The lab is not a model of any real system and is **not for production use**. The vulnerable variant (M3) must never be deployed. |
| L-12 | **Secret scanning is local, not yet a CI gate.** gitleaks 8.30.1 finds nothing in the whole git history or the working tree, and `tools/secret_scan.py` proves on every run that the scanner can detect a fake canary (exit 2 if it cannot). No SAST (Semgrep) has been run yet (not installed). `pip-audit` is run at each milestone. CI gating for all three is M5. |
| L-13 | The market model is simplified (a tenant either has a market or not); it does not model per-role or per-resource market grants. |
| L-14 | No `LICENSE` yet (owner decision D-16). Third-party dependency licences have not been reviewed. |
| L-15 | **A chunked body is capped only when it is read**, which is after the gates (D-23). An unauthenticated chunked request is answered 401 without its body being read, but a server in front of the app may still buffer it: a reverse proxy body limit is required in any real deployment. |
| L-16 | **Check-to-use gap, reduced not eliminated.** The gates read in separate `SELECT`s, so a read can answer from state that changed a moment later. Writes no longer have the gap on SQLite: each carries its authority, quota and version predicates (D-35) and is tested against races between pre-check and write. PostgreSQL `READ COMMITTED` evaluates such subqueries on the statement's snapshot, so the same claim is **not** made there until M5. |
| L-17 | `audit_events` is **append-only by convention only**: no code path updates or deletes a row, but nothing in the database forbids it. A trigger or revoked grants are planned with PostgreSQL in M5. |
| L-18 | **Log handling is not designed.** Records carry request ids, operation names and reason codes and never a token, body, e-mail or SQL (tested), but the package configures no handler, no redaction layer and no retention. The route template in a log line is a constant, not user input. |
| L-19 | **Replay and rate limits.** A token is replayable until it expires (at most 900 s); `jti` is verified to exist but not stored. Only the body size is bounded in M1: there is no rate limit, quota or pagination bound yet (M2). The thread pool that runs the blocking database calls bounds concurrency at the framework default. |
| L-20 | **Identity timing.** The unknown-principal path does one database lookup that an invalid-signature path does not, so response times differ slightly. Responses are byte-identical apart from the request id (tested); timing is covered by L-07. |
| L-21 | **No route creates a contact, tenant, principal or membership.** Contacts exist only through the seed, so a project detail embeds at most 100 of them (D-36) without any way for a client to grow the set. `PUT /members/{id}` changes existing memberships only (D-34). |
| L-22 | **The project quota is checked inside the insert statement, which is atomic on SQLite.** On PostgreSQL two concurrent inserts could both see 999 rows; the exact bound needs a lock or constraint and is part of M5. |
| L-23 | **Keyset paging is stable, not a snapshot.** A row inserted with a smaller id after page one is not shown on later pages; a row that becomes hidden mid-way simply disappears. Neither reveals anything about hidden data. |
| L-24 | **The timing smoke test (TL-19) is a best-of-three, factor-of-five comparison** of a hidden and a missing project. It can miss a real but small timing difference and cannot prove constant time (L-07); on a heavily loaded machine it could also fail spuriously. |
