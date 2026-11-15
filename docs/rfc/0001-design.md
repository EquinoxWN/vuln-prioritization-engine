# RFC 0001: vuln-prioritization-engine design

- **Status:** Accepted for M1 (normalization and enrichment built); M2 and M3 open
- **Author:** EquinoxWN
- **Created:** 2026-11-14

## Problem

A team that runs several scanners gets hundreds of findings in different formats: osv-scanner
names a Python advisory `GHSA-...` and `PYSEC-...`, Trivy names the same bug `CVE-...`, Grype
names a Java one `GHSA-...` with the CVE as a "related" id, and an SBOM lists packages with no
vulnerabilities at all. Before anyone can decide what to fix first, the findings have to be one
list: one entry per vulnerability per package version, with consistent details, and with the two
public signals that say whether a bug is being exploited (FIRST EPSS and the CISA KEV catalog).

Users: application security engineers and platform teams who own the scanner output for many
services, and developers who receive the resulting list.

## Goals (M1) and critical-to-quality measures

| Goal | CTQ measure | Target | M1 result |
|---|---|---|---|
| Read osv-scanner, Trivy and Grype JSON, CycloneDX and SPDX SBOMs | formats read by the fixtures and tests | 5 | 5 |
| Match SBOM packages against a local OSV database | ids per package equal to the OSV API's answer | 10 of 10 packages | 10 of 10 (86 ids) |
| One finding per vulnerability and package version | duplicates after merging 5 overlapping inputs | 0 | 0 (59 findings with or without the scanner reports) |
| Details from the OSV record when one exists | CVSS v3 base scores equal to published NVD values | all test vectors | 11 of 11 |
| EPSS and KEV on every finding with a CVE | findings with a CVE that lack EPSS in the fixture run | 0 | 0 of 59 |
| No silent bad input | malformed inputs that are accepted | 0 | 0 (each malformed case in the tests exits 2) |
| Stale feeds are visible | feed older than the limit produces a warning | always | tested at the boundary |

## Non-goals

- Running scanners. The engine reads their output; it never scans a host or a network.
- A risk score, ranking, fix deadlines, reachability and asset context (M2, M3).
- OS packages (Debian, RPM, Alpine): M1 reports them as skipped, because their version ordering
  differs per distribution.
- Running as a hosted service.

## Design

```
scanner JSON ─┐                       ┌─ OSV records (folder or osv.dev zip)
SBOM JSON  ───┼─ inputs.read_input ──▶ engine.normalize ──▶ engine.enrich ──▶ report (text, JSON)
              │   (detect, validate,     (match SBOMs,        (EPSS, KEV,         atomic write
              │    Observation /          union-find on ids    feed age)
              │    Component)             and OSV aliases)
              └─ vpe fetch (optional, live): KEV, EPSS API, OSV API; timeouts, bounded retries
```

- **Inputs** (`inputs.py`): the format is detected from the JSON shape. Each scanner entry becomes
  an `Observation` (package, the set of ids it carries, source, location, summary, CVSS vectors,
  severity word, fixed versions); each SBOM entry becomes a `Component`. Packages are identified by
  their purl when present (`purl.py`), otherwise by the scanner's package type; names are
  normalized as OSV indexes them (PEP 503 for PyPI, `group:artifact` for Maven, Go's leading `v`
  removed). Unsupported entries are counted and reported, never dropped silently.
- **OSV database** (`osvdb.py`): records are validated and indexed by id, alias and package. A
  package version is affected when it is in the record's `versions` list or inside a `SEMVER` or
  `ECOSYSTEM` range, evaluated with the OSV specification's algorithm (events sorted, `introduced`
  opens, `fixed` and `last_affected` close, `limit` caps). Version ordering (`versions.py`): SemVer
  2.0 for npm, Go and crates.io; PEP 440 for PyPI (the `packaging` library); a simplified Maven
  order. `GIT` ranges are ignored. Withdrawn records are skipped.
- **Merging** (`engine.normalize`): observations are grouped by package version; inside a group a
  union-find joins observations whose id sets overlap, after expanding each id with the aliases the
  OSV database knows. Each group becomes one `Finding`: display id (lowest CVE, else GHSA, else
  lowest id), every alias, summary and CVSS from the OSV record when one exists (else from the
  scanners), CVSS v3 base score computed from the vector (`cvss.py`), the lowest fixed version above
  the installed one, the sources and locations. If the OSV record does not list the scanner's
  version as affected, the finding keeps the scanner's claim and carries a note.
- **Enrichment** (`engine.enrich`): the highest EPSS score across the finding's CVE aliases and
  the KEV entry of any of them. A finding without a CVE gets a note. Feed dates are compared with
  the report date (UTC today, or `--as-of`) and a warning is added past `--max-feed-age` days.
- **Live downloads** (`fetch.py`, `vpe fetch`): optional. HTTPS only, a per-attempt timeout,
  retries only on network errors, 429 and 5xx with exponential backoff (at most 5 retries), a
  32 MiB response cap, validation before an atomic write. The tests use a fake opener; the shipped
  fixtures were produced by these commands.

## Alternatives considered

| Option | Why not (yet) |
|---|---|
| Query the OSV API at report time instead of a local database | Every report would depend on the network and on the day's data, so results would not be reproducible and tests could not run offline. The API is used to *build* the local database (`vpe fetch osv`) and as an oracle in the tests. |
| Merge findings by exact id only | Trivy reports `CVE-2023-39325`, the OSV Go database `GO-2023-2102`, GitHub `GHSA-4374-p667-p6c8`; exact-id merging lists the same bug three times. Union-find over ids plus OSV aliases removes these duplicates. |
| Take severity from the scanners | Scanners disagree (Trivy uses vendor severities, Grype its own words). Preferring the OSV record gives one source of truth; the scanner value is the fallback. |
| Use the full EPSS daily CSV in the fixtures | About 300,000 rows for 59 CVEs. The loader supports the CSV (and `.gz`), but the fixture keeps only the API answer for the CVEs in the report. |
| A dependency for SemVer and Maven ordering | Small, well-specified comparisons; written here and covered by ordered-list and property tests. PEP 440 uses `packaging` because its rules are long. |

## Measurement plan

- M1: the CTQ table above, measured by the test suite on the shipped fixtures
  ([results](../results/m1.md)).
- M3: backtest. Share of later-exploited CVEs (added to KEV after a cut-off date) ranked in the top
  10% by the engine, compared with ranking by CVSS alone, on historical EPSS and KEV snapshots.

## Milestones

- **M1 (done):** scanner results and SBOMs normalized, details from OSV; EPSS and KEV on each finding.
- **M2:** reachability analysis; asset context raises or lowers priority.
- **M3:** ranked list with fix deadlines and expiring suppressions; backtest on historical CVEs.

## Risks and open questions

- The simplified Maven order does not cover every corner of Maven's `ComparableVersion`
  (for example mixed `-` and `.` nesting); a wrong order could miss or add a match.
- Ecosystems without a comparator (RubyGems, NuGet, Packagist, OS packages) only match through
  enumerated `versions` lists; the report counts the ranges it could not compare.
- EPSS and KEV change daily; a report is only as current as its feed files, so the feed age is
  printed and checked.
- CVSS v4 vectors are kept but not scored in M1.
