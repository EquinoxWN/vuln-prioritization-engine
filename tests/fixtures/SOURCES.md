# Fixture sources

Everything here describes a fictional application (`shop-api` and `billing-worker`). No scanner
was run against the author's machine or any network host to produce these files.

| Path | What | Source and date |
|---|---|---|
| `sbom/shop-api.cdx.json` | CycloneDX 1.5 SBOM, 10 components with a purl (one nested) and 1 without | Hand-written |
| `sbom/billing-worker.spdx.json` | SPDX 2.3 SBOM, 2 packages that overlap `shop-api`, 1 Debian package, 1 without a purl | Hand-written |
| `osv/*.json` | 86 OSV records, unmodified | Downloaded on 2026-11-14 with `vpe fetch osv --packages-from sbom/shop-api.cdx.json` from `https://api.osv.dev/v1` (querybatch, then `/vulns/<id>`). OSV data is published under the licences of its upstream databases (GitHub Advisory Database CC-BY 4.0, PyPA advisory database CC-BY 4.0, Go vulnerability database CC-BY 4.0) |
| `osv-api/querybatch-shop-api.json` | The OSV API's own answer (ids per package) for the 10 `shop-api` packages | Same API, same day; used as the oracle for the offline matcher |
| `feeds/epss-2026-11-13.json` | EPSS scores for the 59 CVEs in the report, score date 2026-11-13 | Downloaded on 2026-11-14 with `vpe fetch epss` from `https://api.first.org/data/v1/epss` (FIRST.org, EPSS) |
| `feeds/kev-2026.11.13-subset.json` | 8 of the 1781 entries of KEV catalog version 2026.11.13 (released 2026-11-13): the 3 CVEs in the report and the first 5 entries of the catalog; `count` set to 8, other fields unchanged | Downloaded on 2026-11-14 with `vpe fetch kev` from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (CISA) |
| `scans/osv-scanner.json` | osv-scanner JSON (`results[].packages[]` with embedded OSV records) for the four Python packages | Built by a script from the OSV records above in the documented osv-scanner layout; not produced by running osv-scanner |
| `scans/trivy.json` | Trivy JSON schema 2: npm and `gomod` results (CVE ids, GHSA ids as `VendorIDs`, 6 of the x/net vulnerabilities), one Debian result and one `null` result | Same; not produced by running Trivy |
| `scans/grype.json` | Grype JSON: the log4j GHSA matches with related CVEs, and one Debian artifact | Same; not produced by running Grype |

To refresh the live parts, run `make fetch-live` (writes to `.tmp/live/`, never into this folder).
