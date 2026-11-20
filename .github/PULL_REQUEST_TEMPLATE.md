## What and why

## Checklist
- [ ] A failing test came first (or this is docs only), and the suite passes: `uv run pytest -q -m "not docker"`
- [ ] `ruff check`, `ruff format --check` and `mypy` are clean
- [ ] No guard, authorization control or container setting was weakened (or the PR explains exactly why)
- [ ] Synthetic data only: no real credentials, personal data or third-party details
- [ ] Docs say what is implemented and what is not
