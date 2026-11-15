# ADR 0003: Merge findings by alias groups per package version; OSV record details win over scanner details

- **Status:** Accepted

## Context

The same vulnerability arrives under different ids: a CVE from Trivy, a GHSA from Grype, a GO or
PYSEC id from OSV. Scanners also disagree on severity words, CVSS vectors and fixed versions.
M1 must produce one finding per vulnerability per package version, with one set of details.

## Decision

- Findings are keyed by package version (ecosystem, normalized name, version). Inside one package
  version, observations whose id sets overlap are joined with a union-find, after expanding each
  id with the aliases the local OSV database knows, in both directions.
- The display id is the lowest CVE in the group, else the lowest GHSA, else the lowest id; every id
  is kept in `aliases`.
- When the group contains ids of OSV records, the summary, CVSS vectors and fixed versions come from
  those records; the first CVSS v3 vector that parses is scored. Scanner values are used only when
  no OSV record is present, and the highest severity word wins when there is no vector.
- When the OSV records do not list the version as affected but a scanner does, the finding is kept
  with a note instead of being dropped.

## Consequences

- Good: three scanners and two SBOMs over the same service give 59 findings, the same count as the
  SBOM alone (tested); the GO, GHSA and CVE names of one bug end up in one finding.
- Good: details have one source of truth, named in `details_from`.
- Cost: two different CVEs can end up in one finding when an OSV record aliases both; the finding
  then lists both CVEs and takes the highest EPSS score.
- Cost: a scanner-only id that no OSV record links stays a separate finding, even if a person could
  tell it is the same bug.
