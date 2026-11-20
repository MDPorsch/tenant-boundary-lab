# Contributing

Thanks for looking. This is a security-focused project, so the bar for changes is deliberately high.

## Set up (about two minutes)

```bash
git clone https://github.com/MDPorsch/tenant-boundary-lab && cd tenant-boundary-lab
uv sync --all-extras             # Python 3.13 and the locked dependency set
uv run pytest -q -m "not docker" # the whole suite except the container tests (needs no Docker)
```

The five container tests need a Docker daemon and **fail, not skip,** without one; deselect them
explicitly with `-m "not docker"`. Before a pull request, also run:

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy
uv run python tools/secret_scan.py   # needs gitleaks; also proves the scanner can detect a canary
```

## Rules that are not negotiable

1. **Tests first.** A change in behaviour starts with a failing test, and a security claim needs a test
   that would fail if the claim were false. Never skip or xfail a test to make a build green.
2. **Do not weaken a guard** (start-up guard, request guard, wheel exclusion, container settings) or an
   authorization control to make something easier. If you think one is wrong, open an issue first.
3. **Synthetic data only.** No real names, addresses, credentials, tokens, keys or customer data in code,
   tests, fixtures, issues or pull requests. E-mail addresses use the reserved `.invalid` domain.
4. **Be honest in docs and reports.** Distinguish "implemented" from "planned", and say what a test does
   not show. No badge before the workflow it points at has run.
5. **Keep it offline.** The code under test makes no network calls; CI is the only thing that does.

## Mutation checks (optional, slow)

`tools/mutation_m1.py`, `tools/mutation_m2.py` and `tools/mutation_m3.py` inject known security bugs into
a scratch copy and require the suite to catch every one. If you change code a mutant patches, a
"patch does not apply" result means the mutant is stale and must be updated, not ignored.

By contributing you agree your contribution is licensed under the Apache License 2.0.
