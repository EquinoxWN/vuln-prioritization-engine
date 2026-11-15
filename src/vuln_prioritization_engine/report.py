"""JSON and text renderings of an enriched result."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .engine import Result
from .feeds import EpssFeed, KevFeed
from .inputs import Parsed
from .models import Finding
from .osvdb import Database

SORTS = ("id", "epss", "cvss")


def sort_findings(findings: Sequence[Finding], by: str) -> list[Finding]:
    """Display order: by package and id, by EPSS, or by CVSS score (highest first)."""
    if by == "id":
        return list(findings)
    if by == "epss":
        return sorted(findings, key=lambda f: -(f.epss.score if f.epss else -1.0))
    if by == "cvss":
        return sorted(findings, key=lambda f: -(f.cvss_score if f.cvss_score is not None else -1.0))
    raise ValueError(f"unknown sort {by!r}")


def summary(res: Result) -> dict[str, Any]:
    """Counts for the report header."""
    sev = Counter(f.severity for f in res.findings)
    return {
        "findings": len(res.findings),
        "packages": len({f.package.key() for f in res.findings}),
        "sbom_components": res.components,
        "by_severity": dict(sorted(sev.items())),
        "in_kev": sum(1 for f in res.findings if f.kev),
        "with_epss": sum(1 for f in res.findings if f.epss),
        "without_cve": sum(1 for f in res.findings if not f.cves),
        "details_from_osv_db": sum(1 for f in res.findings if f.details_from != "scanner"),
        "seen_by_more_than_one_source": sum(1 for f in res.findings if len(f.sources) > 1),
    }


def _sha256(path: str) -> str:
    """Hex digest of an input file, so a report names exactly what it read."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def to_json(
    res: Result,
    parsed: Sequence[Parsed],
    db: Database | None,
    epss: EpssFeed | None,
    kev: KevFeed | None,
    generated_at: datetime,
    sort: str,
) -> dict[str, Any]:
    """The full JSON report."""
    return {
        "tool": "vuln-prioritization-engine",
        "version": __version__,
        "generated_at": generated_at.isoformat(timespec="seconds"),
        "inputs": [{"path": p.path, "kind": p.kind, "sha256": _sha256(p.path)} for p in parsed],
        "feeds": {
            "osv_db": None
            if db is None
            else {"path": db.source, "records": len(db.records), "withdrawn_skipped": db.withdrawn},
            "epss": None
            if epss is None
            else {
                "path": epss.source,
                "score_date": epss.score_date,
                "model_version": epss.model_version,
                "cves": len(epss.scores),
            },
            "kev": None
            if kev is None
            else {
                "path": kev.source,
                "catalog_version": kev.catalog_version,
                "date_released": kev.date_released,
                "entries": len(kev.entries),
            },
        },
        "summary": summary(res),
        "warnings": list(res.warnings),
        "findings": [f.to_json() for f in sort_findings(res.findings, sort)],
    }


def _row(f: Finding) -> tuple[str, ...]:
    """One table row."""
    return (
        f.id,
        f"{f.package.ecosystem}/{f.package.label()}",
        f.severity,
        "-" if f.cvss_score is None else f"{f.cvss_score:.1f}",
        "-" if f.epss is None else f"{f.epss.score:.4f}",
        f.kev.date_added if f.kev else "-",
        f.upgrade_to or "-",
        "+".join(f.sources),
    )


def to_text(res: Result, sort: str) -> str:
    """A fixed-width table plus a one-line summary."""
    rows: list[tuple[str, ...]] = [
        ("ID", "PACKAGE", "SEV", "CVSS", "EPSS", "KEV", "UPGRADE TO", "SOURCES")
    ]
    rows += [_row(f) for f in sort_findings(res.findings, sort)]
    widths = [min(max(len(r[i]) for r in rows), 48) for i in range(len(rows[0]))]
    lines = [
        "  ".join(c[:48].ljust(w) for c, w in zip(r, widths, strict=True)).rstrip() for r in rows
    ]
    s = summary(res)
    lines += [f"warning: {w}" for w in res.warnings]
    lines.append(
        f"{s['findings']} findings on {s['packages']} packages: {s['in_kev']} in KEV, "
        f"{s['with_epss']} with EPSS, {s['without_cve']} without a CVE, "
        f"{s['seen_by_more_than_one_source']} seen by more than one source"
    )
    return "\n".join(lines) + "\n"
