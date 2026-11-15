"""Merge observations into findings, fill details from OSV, then add EPSS and KEV."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import date

from .cvss import SEVERITIES, normalize_label, score_v3, severity_of
from .errors import InputError, VersionError
from .feeds import CVE, EpssFeed, KevFeed
from .inputs import Parsed
from .models import Finding, Observation
from .osvdb import Database, MatchStats, Record, affects
from .purl import Package
from .versions import comparator, sort_versions

SOURCE_ORDER = ("osv-scanner", "trivy", "grype", "sbom+osv")


@dataclass
class Result:
    """Merged findings plus everything worth warning about."""

    findings: list[Finding]
    components: int
    stats: MatchStats = field(default_factory=MatchStats)
    warnings: list[str] = field(default_factory=list)


def canonical_id(ids: Iterable[str]) -> str:
    """Preferred display id of an alias group: lowest CVE, else GHSA, else lowest id."""
    pool = sorted(ids)
    for prefix in ("CVE-", "GHSA-"):
        hits = [i for i in pool if i.startswith(prefix)]
        if hits:
            return hits[0]
    return pool[0]


def _groups(observations: Sequence[Observation], db: Database | None) -> list[set[int]]:
    """Union-find of observations whose id sets overlap (through OSV aliases too)."""
    parent = list(range(len(observations)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for idx, obs in enumerate(observations):
        ids: set[str] = set()
        for vid in obs.ids:
            ids |= db.related(vid) if db else {vid}
        for vid in ids:
            if vid in owner:
                a, b = find(owner[vid]), find(idx)
                if a != b:
                    parent[max(a, b)] = min(a, b)
            else:
                owner[vid] = idx
    groups: dict[int, set[int]] = {}
    for idx in range(len(observations)):
        groups.setdefault(find(idx), set()).add(idx)
    return list(groups.values())


def _sbom_observations(
    parsed: Sequence[Parsed], db: Database | None, res: Result
) -> list[Observation]:
    """Match each distinct SBOM component against the OSV database (all its locations kept)."""
    first: dict[tuple[str, str, str], Package] = {}
    where: dict[tuple[str, str, str], set[str]] = {}
    for p in parsed:
        if p.components and db is None:
            raise InputError(f"{p.path}: an SBOM needs --osv-db to find vulnerabilities")
        for comp in p.components:
            first.setdefault(comp.package.key(), comp.package)
            where.setdefault(comp.package.key(), set()).add(comp.location)
    res.components = len(first)
    if db is None:
        return []
    return [
        Observation(
            package=pkg,
            ids=frozenset({rec.id, *rec.aliases}),
            source="sbom+osv",
            location=", ".join(sorted(where[key])),
            summary=rec.summary,
            cvss_vectors=rec.cvss_vectors,
            severity_label=rec.severity_label,
            fixed=rec.fixed_for(pkg),
        )
        for key, pkg in sorted(first.items())
        for rec in db.match(pkg, res.stats)
    ]


def _pick_cvss(vectors: Iterable[str], notes: list[str]) -> tuple[str | None, float | None]:
    """First CVSS v3 vector that parses, with its base score."""
    other = None
    for vec in vectors:
        if vec.startswith("CVSS:3"):
            try:
                c = score_v3(vec)
            except InputError as exc:
                notes.append(f"ignored CVSS vector: {exc}")
                continue
            return c.vector, c.base_score
        other = other or vec
    if other:
        notes.append(f"only a non-v3 CVSS vector is available ({other.split('/')[0]}); not scored")
        return other, None
    return None, None


def _ordered_fixed(pkg: Package, versions: Iterable[str]) -> tuple[str, ...]:
    """Unique fixed versions, in version order when the ecosystem allows."""
    uniq = sorted(set(versions))
    cmp = comparator(pkg.ecosystem)
    if cmp is not None:
        try:
            return tuple(sort_versions(uniq, cmp))
        except VersionError:
            return tuple(uniq)  # a version the ecosystem cannot order: lexical order instead
    return tuple(uniq)


def nearest_fix(pkg: Package, fixed: Sequence[str]) -> str | None:
    """Lowest fixed version above the installed one, or None when unknown."""
    cmp = comparator(pkg.ecosystem)
    if cmp is None:
        return None
    try:
        above = [v for v in fixed if cmp(v, pkg.version) > 0]
        return sort_versions(above, cmp)[0] if above else None
    except VersionError:
        return None  # a fixed version this ecosystem cannot order: no suggestion


def _finding(pkg: Package, group: list[Observation], db: Database | None) -> Finding:
    """Merge one alias group on one package into a finding."""
    ids: set[str] = set()
    for obs in group:
        for vid in obs.ids:
            ids |= db.related(vid) if db else {vid}
    group = sorted(group, key=lambda o: (SOURCE_ORDER.index(o.source), o.location))
    notes: list[str] = []
    records: list[Record] = sorted(
        (db.records[i] for i in ids if db and i in db.records), key=lambda r: r.id
    )
    vectors: list[str] = []
    fixed: list[str] = []
    labels = [o.severity_label for o in group]
    if records:
        details_from = "osv-db:" + ",".join(r.id for r in records)
        summary = next((r.summary for r in records if r.summary), "")
        for r in records:
            vectors += r.cvss_vectors
            fixed += r.fixed_for(pkg)
            labels.append(r.severity_label)
        if not any(affects(r, pkg) for r in records):
            notes.append(
                f"the OSV database does not list {pkg.label()} as affected; check the scanner"
            )
    else:
        details_from = "scanner"
        summary = next((o.summary for o in group if o.summary), "")
    for obs in group:
        vectors += obs.cvss_vectors
        fixed += obs.fixed
    vector, score = _pick_cvss(vectors, notes)
    if score is not None:
        severity = severity_of(score)
    else:
        ranked = [s for s in (normalize_label(x) for x in labels) if s]
        severity = max(ranked, key=SEVERITIES.index) if ranked else "UNKNOWN"
    purl = next((o.package.purl for o in group if o.package.purl), None)
    return Finding(
        package=Package(pkg.ecosystem, pkg.name, pkg.version, purl),
        id=canonical_id(ids),
        aliases=tuple(sorted(ids)),
        cves=tuple(sorted(i for i in ids if CVE.fullmatch(i))),
        summary=re.sub(r"\s+", " ", summary).strip(),
        cvss_vector=vector,
        cvss_score=score,
        severity=severity,
        fixed_versions=_ordered_fixed(pkg, fixed),
        upgrade_to=nearest_fix(pkg, fixed),
        sources=tuple(dict.fromkeys(o.source for o in group)),
        locations=tuple(sorted({o.location for o in group})),
        details_from=details_from,
        notes=notes,
    )


def normalize(parsed: Sequence[Parsed], db: Database | None) -> Result:
    """Turn every input into one finding per (package version, vulnerability)."""
    res = Result(findings=[], components=0)
    observations = [o for p in parsed for o in p.observations]
    observations += _sbom_observations(parsed, db, res)
    by_pkg: dict[tuple[str, str, str], list[Observation]] = {}
    for obs in observations:
        by_pkg.setdefault(obs.package.key(), []).append(obs)
    for key in sorted(by_pkg):
        obs_list = by_pkg[key]
        for idx_set in _groups(obs_list, db):
            group = [obs_list[i] for i in sorted(idx_set)]
            res.findings.append(_finding(group[0].package, group, db))
    res.findings.sort(key=lambda f: (f.package.key(), f.id))
    for p in parsed:
        for reason, n in sorted(p.skipped.items()):
            res.warnings.append(f"{p.path}: skipped {n} {reason}")
    for eco, n in sorted(res.stats.unsupported.items()):
        res.warnings.append(f"{n} OSV ranges in ecosystem {eco} could not be compared (not in M1)")
    res.warnings += [f"version not comparable: {e}" for e in res.stats.version_errors[:20]]
    return res


def enrich(
    res: Result,
    epss: EpssFeed | None,
    kev: KevFeed | None,
    as_of: date,
    max_age_days: int,
) -> None:
    """Attach the highest EPSS score and any KEV entry across each finding's CVE aliases."""
    for f in res.findings:
        if not f.cves:
            f.notes.append("no CVE alias, so EPSS and KEV do not apply")
            continue
        if epss is not None:
            hits = [epss.scores[c] for c in f.cves if c in epss.scores]
            if hits:
                f.epss = max(hits, key=lambda e: (e.score, e.cve))
            else:
                f.notes.append("no EPSS score for " + ", ".join(f.cves))
        if kev is not None:
            f.kev = next((kev.entries[c] for c in f.cves if c in kev.entries), None)
    for label, day in (
        ("EPSS score date", epss.score_date if epss else None),
        ("KEV release date", kev.date_released if kev else None),
    ):
        if day is None:
            continue
        age = (as_of - date.fromisoformat(day)).days
        if age > max_age_days:
            res.warnings.append(f"{label} {day} is {age} days old (limit {max_age_days})")
        elif age < 0:
            res.warnings.append(f"{label} {day} is after the report date {as_of.isoformat()}")
