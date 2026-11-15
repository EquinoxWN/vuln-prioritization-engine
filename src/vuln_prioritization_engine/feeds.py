"""EPSS scores (FIRST API JSON or daily CSV) and the CISA KEV catalog, validated on load."""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .errors import InputError
from .jsonio import parse_json, read_bytes
from .models import Epss, Kev

CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_CSV_META = re.compile(r"#model_version:([^,]+),score_date:(\d{4}-\d{2}-\d{2})(T[0-9:.+Z-]*)?")


@dataclass(frozen=True)
class EpssFeed:
    """EPSS scores keyed by CVE, with the score date and model version."""

    scores: dict[str, Epss]
    score_date: str
    model_version: str
    source: str


@dataclass(frozen=True)
class KevFeed:
    """KEV entries keyed by CVE, with catalog version and release date."""

    entries: dict[str, Kev]
    catalog_version: str
    date_released: str
    source: str


def parse_date(value: Any, label: str) -> str:
    """Validate a YYYY-MM-DD date (or the date part of an ISO timestamp)."""
    if not isinstance(value, str) or not _DATE.match(value):
        raise InputError(f"{label}: expected a YYYY-MM-DD date, got {str(value)[:40]!r}")
    day = value[:10]
    try:
        date.fromisoformat(day)
    except ValueError as exc:
        raise InputError(f"{label}: invalid date {day!r}") from exc
    return day


def _probability(value: Any, label: str) -> float:
    """A number in [0, 1], given as a JSON number or numeric string."""
    try:
        num = float(value)
    except (TypeError, ValueError) as exc:
        raise InputError(f"{label}: not a number: {str(value)[:40]!r}") from exc
    if not 0.0 <= num <= 1.0:
        raise InputError(f"{label}: {num} is outside 0..1")
    return num


def _cve(value: Any, label: str) -> str:
    """Validate a CVE id."""
    if not isinstance(value, str) or not CVE.fullmatch(value):
        raise InputError(f"{label}: invalid CVE id {str(value)[:40]!r}")
    return value


def load_epss(path: Path) -> EpssFeed:
    """Load EPSS from the FIRST API JSON or the daily CSV (optionally .gz)."""
    raw = read_bytes(path)
    label = str(path)
    if raw.lstrip()[:1] == b"{":
        return parse_epss(parse_json(raw, label), label)
    return _epss_csv(raw, label)


def parse_epss(data: Any, label: str) -> EpssFeed:
    """FIRST API shape: {"data": [{"cve", "epss", "percentile", "date"}]}."""
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        raise InputError(f"{label}: EPSS JSON needs a 'data' array")
    scores: dict[str, Epss] = {}
    dates: set[str] = set()
    for i, row in enumerate(data["data"]):
        where = f"{label} data[{i}]"
        if not isinstance(row, dict):
            raise InputError(f"{where}: expected an object")
        cve = _cve(row.get("cve"), where)
        if cve in scores:
            raise InputError(f"{where}: duplicate {cve}")
        day = parse_date(row.get("date"), where)
        dates.add(day)
        scores[cve] = Epss(
            cve=cve,
            score=_probability(row.get("epss"), where),
            percentile=_probability(row.get("percentile"), where),
            date=day,
        )
    if not scores:
        raise InputError(f"{label}: EPSS file has no scores")
    model = data.get("model_version")
    return EpssFeed(
        scores=scores,
        score_date=min(dates),
        model_version=model if isinstance(model, str) else "unknown",
        source=label,
    )


def _epss_csv(raw: bytes, label: str) -> EpssFeed:
    """Daily file: '#model_version:...,score_date:...' then 'cve,epss,percentile' rows."""
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputError(f"{label}: not UTF-8") from exc
    lines = text.splitlines()
    if not lines:
        raise InputError(f"{label}: empty EPSS file")
    meta = _CSV_META.fullmatch(lines[0].strip())
    if not meta:
        raise InputError(f"{label}: first line must be '#model_version:...,score_date:...'")
    day = parse_date(meta.group(2), label)
    reader = csv.reader(io.StringIO("\n".join(lines[1:])))
    header = next(reader, None)
    if header != ["cve", "epss", "percentile"]:
        raise InputError(f"{label}: header must be cve,epss,percentile")
    scores: dict[str, Epss] = {}
    for n, row in enumerate(reader, start=3):
        where = f"{label}:{n}"
        if len(row) != 3:
            raise InputError(f"{where}: expected 3 columns")
        cve = _cve(row[0], where)
        if cve in scores:
            raise InputError(f"{where}: duplicate {cve}")
        scores[cve] = Epss(cve, _probability(row[1], where), _probability(row[2], where), day)
    if not scores:
        raise InputError(f"{label}: EPSS file has no scores")
    return EpssFeed(scores=scores, score_date=day, model_version=meta.group(1), source=label)


def load_kev(path: Path) -> KevFeed:
    """Load and validate the CISA KEV JSON catalog."""
    return parse_kev(parse_json(read_bytes(path), str(path)), str(path))


def parse_kev(data: Any, label: str) -> KevFeed:
    """Validate a decoded KEV catalog."""
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise InputError(f"{label}: KEV JSON needs a 'vulnerabilities' array")
    vulns = data["vulnerabilities"]
    count = data.get("count")
    if not isinstance(count, int) or count != len(vulns):
        raise InputError(
            f"{label}: 'count' is {count!r} but {len(vulns)} entries are present (truncated file?)"
        )
    version = data.get("catalogVersion")
    if not isinstance(version, str) or not version:
        raise InputError(f"{label}: missing catalogVersion")
    released = parse_date(data.get("dateReleased"), f"{label} dateReleased")
    entries: dict[str, Kev] = {}
    for i, v in enumerate(vulns):
        where = f"{label} vulnerabilities[{i}]"
        if not isinstance(v, dict):
            raise InputError(f"{where}: expected an object")
        cve = _cve(v.get("cveID"), where)
        if cve in entries:
            raise InputError(f"{where}: duplicate {cve}")
        ransom = v.get("knownRansomwareCampaignUse", "Unknown")
        name = v.get("vulnerabilityName", "")
        entries[cve] = Kev(
            cve=cve,
            date_added=parse_date(v.get("dateAdded"), f"{where} dateAdded"),
            due_date=parse_date(v.get("dueDate"), f"{where} dueDate"),
            ransomware=ransom if isinstance(ransom, str) else "Unknown",
            name=name if isinstance(name, str) else "",
        )
    return KevFeed(entries=entries, catalog_version=version, date_released=released, source=label)
