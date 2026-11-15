"""Normalized observations (one per source and vulnerability) and merged findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .purl import Package


@dataclass(frozen=True)
class Observation:
    """One vulnerability on one package, as one source reported it."""

    package: Package
    ids: frozenset[str]
    source: str
    location: str
    summary: str = ""
    cvss_vectors: tuple[str, ...] = ()
    severity_label: str | None = None
    fixed: tuple[str, ...] = ()


@dataclass(frozen=True)
class Component:
    """A package listed in an SBOM, before any vulnerability matching."""

    package: Package
    source: str
    location: str


@dataclass(frozen=True)
class Epss:
    """EPSS probability for one CVE on one score date."""

    cve: str
    score: float
    percentile: float
    date: str


@dataclass(frozen=True)
class Kev:
    """A CISA KEV catalog entry."""

    cve: str
    date_added: str
    due_date: str
    ransomware: str
    name: str


@dataclass
class Finding:
    """One vulnerability on one package version after merging all sources."""

    package: Package
    id: str
    aliases: tuple[str, ...]
    cves: tuple[str, ...]
    summary: str
    cvss_vector: str | None
    cvss_score: float | None
    severity: str
    fixed_versions: tuple[str, ...]
    upgrade_to: str | None
    sources: tuple[str, ...]
    locations: tuple[str, ...]
    details_from: str
    epss: Epss | None = None
    kev: Kev | None = None
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        """Report form of the finding."""
        return {
            "id": self.id,
            "aliases": list(self.aliases),
            "cves": list(self.cves),
            "package": {
                "ecosystem": self.package.ecosystem,
                "name": self.package.name,
                "version": self.package.version,
                "purl": self.package.purl,
            },
            "summary": self.summary,
            "cvss": {"vector": self.cvss_vector, "base_score": self.cvss_score},
            "severity": self.severity,
            "fixed_versions": list(self.fixed_versions),
            "upgrade_to": self.upgrade_to,
            "sources": list(self.sources),
            "locations": list(self.locations),
            "details_from": self.details_from,
            "epss": None
            if self.epss is None
            else {
                "cve": self.epss.cve,
                "score": self.epss.score,
                "percentile": self.epss.percentile,
                "date": self.epss.date,
            },
            "kev": None
            if self.kev is None
            else {
                "cve": self.kev.cve,
                "date_added": self.kev.date_added,
                "due_date": self.kev.due_date,
                "known_ransomware_campaign_use": self.kev.ransomware,
                "name": self.kev.name,
            },
            "notes": list(self.notes),
        }
