# ADR 0002: Report from a local OSV database and dated feed files; live downloads are a separate, optional step

- **Status:** Accepted

## Context

M1 needs vulnerability details from OSV, EPSS scores and the KEV catalog. All three are public web
services that change daily. Reports must be reproducible, tests must run without a network, and
the project must never scan the author's machine or any host.

## Decision

- `vpe report` reads only local files: scanner reports, SBOMs, a folder of OSV records (or an
  osv.dev `all.zip`), an EPSS file and a KEV file. It makes no network call.
- `vpe fetch kev|epss|osv` is the only code that touches the network. Every request is HTTPS with a
  per-attempt timeout (default 30 s), retries only on network errors, 429 and 5xx, with exponential
  backoff (1 s, 2 s, ...) and at most 5 retries, a 32 MiB response cap, and validation before an
  atomic write.
- The repository ships a dated snapshot (OSV records and the OSV API's answer from 2026-11-14,
  EPSS score date 2026-11-13, KEV catalog 2026.11.13) with its source written down in
  `tests/fixtures/SOURCES.md`. The KEV file is trimmed to 8 entries and says so.
- Each report records the feed dates and the SHA-256 of every input, and warns when a feed is
  older than `--max-feed-age` days.

## Consequences

- Good: the same inputs give the same report; the tests run offline in about 4 s; the OSV API's
  own answer is kept as an oracle for the offline matcher.
- Good: the live path is exercised for real (the fixtures were downloaded with it) and by a CI job
  that is allowed to fail without blocking a merge.
- Cost: a user has to refresh the feeds (`make fetch-live` or their own schedule); a stale feed is
  only a warning.
- Cost: 560 KB of OSV JSON in the repository.
