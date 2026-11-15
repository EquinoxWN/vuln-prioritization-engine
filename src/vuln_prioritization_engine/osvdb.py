"""A local OSV database (folder or osv.dev zip of OSV-schema JSON records) and version matching."""

from __future__ import annotations

import re
import zipfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from functools import cmp_to_key
from pathlib import Path
from typing import Any

from .errors import InputError, VersionError
from .jsonio import MAX_FILE_BYTES, load_json, parse_json
from .purl import Package, canonical_version, normalize_name
from .versions import comparator

VULN_ID = re.compile(r"[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._-]{1,96}")
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 500_000
MAX_ZIP_BYTES = 2 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class Range:
    """One OSV range: its type and ordered events."""

    type: str
    events: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class Affected:
    """One affected[] entry of a record."""

    ecosystem: str
    name: str
    versions: frozenset[str]
    ranges: tuple[Range, ...]


@dataclass(frozen=True)
class Record:
    """The fields of an OSV record this tool uses."""

    id: str
    aliases: tuple[str, ...]
    summary: str
    modified: str
    published: str
    withdrawn: str | None
    cvss_vectors: tuple[str, ...]
    severity_label: str | None
    affected: tuple[Affected, ...]

    def fixed_for(self, pkg: Package) -> tuple[str, ...]:
        """Fixed versions named by this record's version ranges (not git commits) for one package."""
        out: list[str] = []
        for aff in self.affected:
            if _same_package(aff, pkg):
                for rng in aff.ranges:
                    if rng.type == "GIT":
                        continue
                    out += [v for kind, v in rng.events if kind == "fixed" and v not in out]
        return tuple(out)


@dataclass
class MatchStats:
    """Counts of matching outcomes worth reporting."""

    unsupported: dict[str, int] = field(default_factory=dict)
    version_errors: list[str] = field(default_factory=list)


def check_id(value: Any, label: str) -> str:
    """Validate an advisory id such as CVE-2021-44228, GHSA-..., GO-2023-2102, PYSEC-..."""
    if not isinstance(value, str) or not VULN_ID.fullmatch(value):
        raise InputError(f"{label}: invalid vulnerability id {str(value)[:80]!r}")
    return value


def _str(obj: Mapping[str, Any], key: str, label: str, default: str | None = None) -> str:
    """A string field, or the default when absent."""
    val = obj.get(key, default)
    if not isinstance(val, str):
        raise InputError(f"{label}: field {key!r} must be a string")
    return val


def _list(obj: Mapping[str, Any], key: str, label: str) -> list[Any]:
    """A list field, empty when absent."""
    val = obj.get(key, [])
    if not isinstance(val, list):
        raise InputError(f"{label}: field {key!r} must be a list")
    return val


def parse_record(data: Any, label: str) -> Record:
    """Validate one OSV-schema record."""
    if not isinstance(data, dict):
        raise InputError(f"{label}: OSV record must be a JSON object")
    rid = check_id(data.get("id"), label)
    aliases = tuple(check_id(a, f"{label} aliases") for a in _list(data, "aliases", label))
    vectors: list[str] = []
    for sev in _list(data, "severity", label):
        if not isinstance(sev, dict):
            raise InputError(f"{label}: severity entries must be objects")
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            vectors.append(_str(sev, "score", label))
    db_specific = data.get("database_specific")
    sev_label = None
    if isinstance(db_specific, dict) and isinstance(db_specific.get("severity"), str):
        sev_label = db_specific["severity"]
    affected: list[Affected] = []
    for aff in _list(data, "affected", label):
        if not isinstance(aff, dict) or not isinstance(aff.get("package"), dict):
            raise InputError(f"{label}: affected entries need a package object")
        pkg = aff["package"]
        eco = _str(pkg, "ecosystem", label)
        name = _str(pkg, "name", label)
        versions = _list(aff, "versions", label)
        if not all(isinstance(v, str) for v in versions):
            raise InputError(f"{label}: affected versions must be strings")
        ranges: list[Range] = []
        for rng in _list(aff, "ranges", label):
            if not isinstance(rng, dict):
                raise InputError(f"{label}: ranges must be objects")
            events: list[tuple[str, str]] = []
            for ev in _list(rng, "events", label):
                if not isinstance(ev, dict) or len(ev) != 1:
                    raise InputError(f"{label}: each range event must have exactly one key")
                ((kind, ver),) = ev.items()
                if kind not in ("introduced", "fixed", "last_affected", "limit"):
                    raise InputError(f"{label}: unknown range event {kind!r}")
                if not isinstance(ver, str) or not ver:
                    raise InputError(f"{label}: range event {kind} needs a version string")
                events.append((kind, ver))
            ranges.append(Range(type=_str(rng, "type", label), events=tuple(events)))
        base = eco.split(":", 1)[0]
        affected.append(
            Affected(
                ecosystem=base,
                name=normalize_name(base, name),
                versions=frozenset(canonical_version(base, v) for v in versions),
                ranges=tuple(ranges),
            )
        )
    withdrawn = data.get("withdrawn")
    return Record(
        id=rid,
        aliases=aliases,
        summary=_str(data, "summary", label, "") or _str(data, "details", label, "")[:200],
        modified=_str(data, "modified", label, ""),
        published=_str(data, "published", label, ""),
        withdrawn=withdrawn if isinstance(withdrawn, str) and withdrawn else None,
        cvss_vectors=tuple(vectors),
        severity_label=sev_label,
        affected=tuple(affected),
    )


def _same_package(aff: Affected, pkg: Package) -> bool:
    """True when an affected entry names this package."""
    return aff.ecosystem == pkg.ecosystem and aff.name == pkg.name


def in_range(version: str, rng: Range, cmp: Callable[[str, str], int]) -> bool:
    """OSV range evaluation: introduced opens, fixed/last_affected/limit close (spec algorithm)."""

    def at_or_after(v: str) -> bool:
        return v == "0" or cmp(version, v) >= 0

    affected = False
    for kind, v in _sorted_events(rng.events, cmp):
        if kind == "introduced" and at_or_after(v):
            affected = True
        elif v != "0" and _closes(kind, cmp(version, v)):
            affected = False
    limits = [v for kind, v in rng.events if kind == "limit" and v != "*"]
    return affected and all(cmp(version, v) < 0 for v in limits)


def _closes(kind: str, order: int) -> bool:
    """A fixed event closes at its version; last_affected closes just after it."""
    return (kind == "fixed" and order >= 0) or (kind == "last_affected" and order > 0)


def _sorted_events(
    events: Iterable[tuple[str, str]], cmp: Callable[[str, str], int]
) -> list[tuple[str, str]]:
    """Events ordered by version, "0" first."""

    def order(a: tuple[str, str], b: tuple[str, str]) -> int:
        if a[1] == b[1]:
            return 0
        if a[1] == "0":
            return -1
        if b[1] == "0":
            return 1
        return cmp(a[1], b[1])

    return sorted(events, key=cmp_to_key(order))


def affects(record: Record, pkg: Package, stats: MatchStats | None = None) -> bool:
    """Whether a record affects one package version."""
    cmp = comparator(pkg.ecosystem)
    for aff in record.affected:
        if not _same_package(aff, pkg):
            continue
        if pkg.version in aff.versions:
            return True
        for rng in aff.ranges:
            if rng.type == "GIT":
                continue
            if rng.type not in ("SEMVER", "ECOSYSTEM"):
                continue
            use = cmp
            if rng.type == "SEMVER":
                use = comparator("npm")
            if use is None:
                if stats is not None:
                    stats.unsupported[pkg.ecosystem] = stats.unsupported.get(pkg.ecosystem, 0) + 1
                continue
            try:
                if in_range(pkg.version, rng, use):
                    return True
            except VersionError as exc:
                if stats is not None:
                    stats.version_errors.append(f"{record.id} / {pkg.label()}: {exc}")
    return False


class Database:
    """OSV records indexed by id, alias and package."""

    def __init__(self, records: Iterable[Record], source: str = "") -> None:
        self.source = source
        self.records: dict[str, Record] = {}
        self.withdrawn = 0
        self._by_alias: dict[str, list[str]] = {}
        self._by_package: dict[tuple[str, str], list[str]] = {}
        for rec in records:
            if rec.withdrawn:
                self.withdrawn += 1
                continue
            if rec.id in self.records:
                raise InputError(f"{source}: duplicate OSV record {rec.id}")
            self.records[rec.id] = rec
            for alias in rec.aliases:
                self._by_alias.setdefault(alias, []).append(rec.id)
            for aff in rec.affected:
                ids = self._by_package.setdefault((aff.ecosystem, aff.name), [])
                if rec.id not in ids:
                    ids.append(rec.id)

    def related(self, vuln_id: str) -> set[str]:
        """The id plus aliases known to the database, in both directions."""
        out = {vuln_id}
        rec = self.records.get(vuln_id)
        if rec:
            out.update(rec.aliases)
        for rid in self._by_alias.get(vuln_id, []):
            out.add(rid)
            out.update(self.records[rid].aliases)
        return out

    def match(self, pkg: Package, stats: MatchStats | None = None) -> list[Record]:
        """Records that affect a package version, ordered by id."""
        ids = self._by_package.get((pkg.ecosystem, pkg.name), [])
        return sorted(
            (self.records[i] for i in ids if affects(self.records[i], pkg, stats)),
            key=lambda r: r.id,
        )


def load_database(path: Path) -> Database:
    """Load a folder of *.json records or an osv.dev all.zip."""
    if path.is_dir():
        files = sorted(path.glob("*.json"))
        if len(files) > MAX_RECORDS:
            raise InputError(f"{path}: more than {MAX_RECORDS} records")
        return Database(
            (parse_record(load_json(f, MAX_RECORD_BYTES), str(f)) for f in files), str(path)
        )
    if path.is_file() and path.suffix == ".zip":
        return Database(_zip_records(path), str(path))
    raise InputError(f"{path}: OSV database must be a folder of .json files or a .zip")


def _zip_records(path: Path) -> Iterable[Record]:
    """Yield records from an OSV zip, with caps on members and sizes."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES * 16:
            raise InputError(f"{path}: zip too large")
        with zipfile.ZipFile(path) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            if len(infos) > MAX_RECORDS:
                raise InputError(f"{path}: more than {MAX_RECORDS} records")
            if sum(i.file_size for i in infos) > MAX_ZIP_BYTES:
                raise InputError(f"{path}: zip expands past {MAX_ZIP_BYTES} bytes")
            for info in infos:
                if not info.filename.endswith(".json"):
                    continue
                if info.file_size > MAX_RECORD_BYTES:
                    raise InputError(f"{path}:{info.filename}: record too large")
                with zf.open(info) as fh:
                    raw = fh.read(MAX_RECORD_BYTES + 1)
                if len(raw) > MAX_RECORD_BYTES:
                    raise InputError(f"{path}:{info.filename}: record too large")
                label = f"{path}:{info.filename}"
                yield parse_record(parse_json(raw, label), label)
    except zipfile.BadZipFile as exc:
        raise InputError(f"{path}: not a valid zip ({exc})") from exc
    except OSError as exc:
        raise InputError(f"{path}: cannot read ({exc})") from exc
