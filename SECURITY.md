# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository
(`https://github.com/EquinoxWN/vuln-prioritization-engine/security/advisories/new`). Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer
within 7 days. Fixes are released as soon as they are ready, and you are credited unless you ask
not to be.

## Supported versions

This project is pre-1.0. Only the latest commit on `main` receives fixes.

## Scope

- **In scope:** a crafted scanner report, SBOM, OSV record or feed file that crashes the tool
  without a clear error, exhausts memory, writes outside the chosen output folder or injects
  terminal escapes; a wrong match that hides a vulnerability (for example a version comparison
  that treats an affected version as fixed); a download that ignores its timeout or retry bound.
- **Out of scope:** the accuracy of OSV, EPSS or KEV data themselves (report those upstream), and
  vulnerabilities in the scanners that produced the input.

## How this repository protects itself

- `vpe report` makes no network call; downloads are a separate command, HTTPS only, with timeouts,
  bounded retries and a size cap. The tool never scans a host.
- Inputs are size-capped and validated (ids, CVE ids, dates, probabilities, purls, CVSS vectors);
  every file write is atomic.
- Every GitHub Action is pinned to a full commit SHA, and workflows run with read-only
  permissions and without persisted credentials.
- Dependabot update pull requests are paused (`open-pull-requests-limit: 0`) so the repository keeps a single `main` branch; dependencies are updated by hand and checked by the CI audit.
- CI runs lint, strict types, tests and a known-vulnerability check (pip-audit) on every push and pull request.
