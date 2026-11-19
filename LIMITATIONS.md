# Limitations and residual risk

Current state: **milestone M0 (contracts and tests only).** Stated plainly so nothing is mistaken for
more than it is.

| ID | Limitation |
|---|---|
| L-01 | **There is no application yet.** No route, authentication, database schema or runner exists. 96 behavioural tests fail by design until M1/M2. The repository does not demonstrate any control working. |
| L-02 | The red tests have been validated only against a **throwaway reference spike** (not committed) plus mutation testing of that spike. This shows the tests and contract are satisfiable and sensitive. It is not evidence about the eventual real implementation. |
| L-03 | The oracle is **data and a loader**. The evaluation engine, case generator and state-diff runner arrive in M4. Today the oracle is checked only by contract tests that encode the same spec prose a second time. |
| L-04 | A `pytest` pass shows that the listed cases pass. It is not proof of security. Coverage percentage is not proof either. |
| L-05 | **Audit flooding** by an authenticated principal who deliberately triggers denials remains possible after M1 (pre-authentication noise is log-only, but post-authentication denials write rows). Planned mitigation (per-actor rate limit / coalescing) is not designed yet. |
| L-06 | Ordinary successful reads are not audited (D-10): the audit trail shows denials and mutations, not who read what. |
| L-07 | **Timing side channels** are not eliminated and cannot be proven absent; only a gross-difference smoke check is planned (TL-19). |
| L-08 | **SQLite does not model PostgreSQL row locking.** Concurrency cases (TL-12, TL-20) are not trustworthy until run on PostgreSQL in M5. Docker is not installed on the development machine yet; a PostgreSQL instance must be provided for M5. |
| L-09 | In-process ASGI tests validate application logic only: not TLS, reverse proxies, header normalisation by a real proxy, or network exposure. |
| L-10 | `auth_version` exists in the schema but is **reserved and unused**: revocation is by principal status, membership and tenant state re-read per request, not by token versioning. There is no token revocation list; a token stays cryptographically valid until `exp` (at most 900 s) but is useless once the principal, membership or tenant state changes. |
| L-11 | All data is synthetic. The lab is not a model of any real system and is **not for production use**. The vulnerable variant (M3) must never be deployed. |
| L-12 | No SAST (Semgrep) or secret scanner has been run at M0. `pip-audit` was run once (result in `docs/milestones/M0.md`). Both are scheduled as CI gates in M5. |
| L-13 | The market model is simplified (a tenant either has a market or not); it does not model per-role or per-resource market grants. |
| L-14 | No `LICENSE` yet (owner decision D-16). Third-party dependency licences have not been reviewed. |
