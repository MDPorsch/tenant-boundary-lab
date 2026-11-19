# Changelog

All notable changes are recorded here. Pre-release; no version has been tagged.

## [Unreleased]

### M0: contracts (no application yet)

- Independent oracle data: `capabilities.csv`, `gates.csv`, `field_policy.csv`, `case_catalog.toml`
  (20 cases mapped to OWASP API Security Top 10:2023), with strict fail-closed loaders.
- Synthetic fixtures (7 principals, 3 tenants, 2 markets, 4 projects, 3 invoices, 4 contacts) with
  trap rows for ownership-vs-membership, hidden-market and suspended-tenant cases.
- RFC 9457 error contract (`ProblemDetail`, `ErrorCode`).
- Tests: contract suite (passes) and 96 behavioural red tests for TL-01..05, TL-14, TL-18 (fail by
  design until M1), with a harness that mints hostile tokens independently of the application.
- Documentation: architecture, threat model, authorization matrix, API contract, test matrix,
  DECISIONS, LIMITATIONS, SECURITY.
