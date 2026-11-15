# Contributing

Thanks for helping. This is a Python project; issues and pull requests are welcome.

## Set up and check your change

Needs Python 3.11+. Caches and virtual environments stay in git-ignored folders inside the repo.

```bash
make setup   # install dependencies
make lint    # ruff, ruff format, mypy --strict
make test    # full test suite (no network)
make audit   # known-vulnerability check (as in CI)
make demo    # offline report on the fixtures
```

A pull request is ready when `make lint` and `make test` pass and CI is green.

## Adding an input format or ecosystem

- A new scanner format goes in `inputs.py` with detection, a fixture in `tests/fixtures/scans/`
  and tests for the happy path, skipped entries and malformed input.
- A new ecosystem needs a comparator in `versions.py` with an ordered-list test, and a purl or
  scanner-type mapping.
- Fixtures must be public data (with source and date in `tests/fixtures/SOURCES.md`) or
  hand-written for a fictional application. Never commit a scan of a real machine.

## Guidelines

- Keep each change focused; explain the problem it solves in the pull request.
- Add or update a test for every behaviour change, and update `docs/results/` when numbers change.
- Significant design changes need an ADR in `docs/adr/` (copy `0001` for the format).
- Keep function comments to one short phrase; let names and tests explain the rest.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).

By contributing you agree that your work is released under the [MIT License](LICENSE).
