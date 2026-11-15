"""Readers for scanner reports (osv-scanner, Trivy, Grype) and SBOMs (CycloneDX, SPDX)."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import InputError
from .jsonio import load_json
from .models import Component, Observation
from .osvdb import check_id, parse_record
from .purl import Package, make_package, parse_purl

MAX_ENTRIES = 200_000

TRIVY_TYPES = {
    "pip": "PyPI",
    "pipenv": "PyPI",
    "poetry": "PyPI",
    "uv": "PyPI",
    "python-pkg": "PyPI",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "node-pkg": "npm",
    "gomod": "Go",
    "gobinary": "Go",
    "cargo": "crates.io",
    "rust-binary": "crates.io",
    "bundler": "RubyGems",
    "gemspec": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
}
GRYPE_TYPES = {
    "python": "PyPI",
    "npm": "npm",
    "go-module": "Go",
    "rust-crate": "crates.io",
    "gem": "RubyGems",
    "dotnet": "NuGet",
    "php-composer": "Packagist",
}


@dataclass
class Parsed:
    """What one input file contributed."""

    path: str
    kind: str
    observations: list[Observation] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    skipped: Counter[str] = field(default_factory=Counter)


def detect(data: Any) -> str:
    """Name the format of a decoded JSON document."""
    if isinstance(data, dict):
        if data.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        if isinstance(data.get("spdxVersion"), str):
            return "spdx"
        if "SchemaVersion" in data and "Results" in data:
            return "trivy"
        if isinstance(data.get("matches"), list) and isinstance(data.get("descriptor"), dict):
            return "grype"
        if isinstance(data.get("results"), list):
            return "osv-scanner"
    raise InputError(
        "unrecognized input: expected osv-scanner, Trivy or Grype JSON, CycloneDX or SPDX JSON"
    )


def read_input(path: Path) -> Parsed:
    """Load one scanner report or SBOM and normalize it."""
    data = load_json(path)
    kind = detect(data)
    parsed = Parsed(path=path.as_posix(), kind=kind)
    reader = {
        "osv-scanner": _osv_scanner,
        "trivy": _trivy,
        "grype": _grype,
        "cyclonedx": _cyclonedx,
        "spdx": _spdx,
    }[kind]
    reader(data, parsed)
    if len(parsed.observations) + len(parsed.components) > MAX_ENTRIES:
        raise InputError(f"{path}: more than {MAX_ENTRIES} entries")
    return parsed


def _obj(value: Any, label: str) -> dict[str, Any]:
    """Require a JSON object."""
    if not isinstance(value, dict):
        raise InputError(f"{label}: expected a JSON object")
    return value


def _arr(value: Any, label: str) -> list[Any]:
    """Require a JSON array; null counts as empty (Trivy writes null)."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise InputError(f"{label}: expected a JSON array")
    if len(value) > MAX_ENTRIES:
        raise InputError(f"{label}: more than {MAX_ENTRIES} entries")
    return value


def _text(value: Any, label: str) -> str:
    """Require a non-empty string."""
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{label}: expected a non-empty string")
    return value


def _dict_or_empty(value: Any) -> dict[str, Any]:
    """An optional JSON object, empty when absent or not an object."""
    return value if isinstance(value, dict) else {}


def _opt_text(value: Any) -> str:
    """A string or empty."""
    return value if isinstance(value, str) else ""


def _osv_scanner(data: dict[str, Any], out: Parsed) -> None:
    """osv-scanner --format json: results[].packages[] with embedded OSV records."""
    for i, res in enumerate(_arr(data["results"], "results")):
        res = _obj(res, f"results[{i}]")
        src = _obj(res.get("source", {}), f"results[{i}].source")
        location = _opt_text(src.get("path")) or out.path
        for j, entry in enumerate(_arr(res.get("packages"), f"results[{i}].packages")):
            label = f"results[{i}].packages[{j}]"
            entry = _obj(entry, label)
            p = _obj(entry.get("package"), f"{label}.package")
            pkg = make_package(
                _text(p.get("ecosystem"), f"{label}.ecosystem"),
                _text(p.get("name"), f"{label}.name"),
                _text(p.get("version"), f"{label}.version"),
            )
            for k, raw in enumerate(_arr(entry.get("vulnerabilities"), f"{label}.vulnerabilities")):
                rec = parse_record(raw, f"{out.path} {label}.vulnerabilities[{k}]")
                out.observations.append(
                    Observation(
                        package=pkg,
                        ids=frozenset({rec.id, *rec.aliases}),
                        source="osv-scanner",
                        location=location,
                        summary=rec.summary,
                        cvss_vectors=rec.cvss_vectors,
                        severity_label=rec.severity_label,
                        fixed=rec.fixed_for(pkg),
                    )
                )


def _package_from(purl: Any, eco: str | None, name: Any, version: Any, label: str) -> Package:
    """Prefer the package URL; fall back to the scanner's type, name and version."""
    if isinstance(purl, str) and purl:
        return parse_purl(purl)
    if eco is None:
        raise InputError(f"{label}: unsupported package type")
    return make_package(eco, _text(name, f"{label}.name"), _text(version, f"{label}.version"))


def _trivy(data: dict[str, Any], out: Parsed) -> None:
    """trivy --format json (schema 2): Results[].Vulnerabilities[]."""
    for i, res in enumerate(_arr(data["Results"], "Results")):
        res = _obj(res, f"Results[{i}]")
        target = _opt_text(res.get("Target")) or out.path
        if res.get("Class") == "os-pkgs":
            out.skipped["OS packages (not in M1)"] += len(_arr(res.get("Vulnerabilities"), "v"))
            continue
        eco = TRIVY_TYPES.get(_opt_text(res.get("Type")))
        for j, v in enumerate(_arr(res.get("Vulnerabilities"), f"Results[{i}].Vulnerabilities")):
            label = f"Results[{i}].Vulnerabilities[{j}]"
            v = _obj(v, label)
            ident = _dict_or_empty(v.get("PkgIdentifier"))
            try:
                pkg = _package_from(
                    ident.get("PURL"), eco, v.get("PkgName"), v.get("InstalledVersion"), label
                )
            except InputError:
                out.skipped[f"unsupported Trivy type {res.get('Type')!r}"] += 1
                continue
            ids = {check_id(v.get("VulnerabilityID"), label)}
            ids.update(check_id(x, label) for x in _arr(v.get("VendorIDs"), f"{label}.VendorIDs"))
            vectors = []
            cvss = _dict_or_empty(v.get("CVSS"))
            for src in sorted(cvss):
                entry = cvss[src]
                if isinstance(entry, dict) and isinstance(entry.get("V3Vector"), str):
                    vectors.append(entry["V3Vector"])
            fixed = tuple(
                f.strip() for f in _opt_text(v.get("FixedVersion")).split(",") if f.strip()
            )
            out.observations.append(
                Observation(
                    package=pkg,
                    ids=frozenset(ids),
                    source="trivy",
                    location=target,
                    summary=_opt_text(v.get("Title")),
                    cvss_vectors=tuple(vectors),
                    severity_label=_opt_text(v.get("Severity")) or None,
                    fixed=fixed,
                )
            )


def _grype(data: dict[str, Any], out: Parsed) -> None:
    """grype -o json: matches[] with vulnerability, relatedVulnerabilities and artifact."""
    for i, m in enumerate(_arr(data["matches"], "matches")):
        label = f"matches[{i}]"
        m = _obj(m, label)
        vuln = _obj(m.get("vulnerability"), f"{label}.vulnerability")
        art = _obj(m.get("artifact"), f"{label}.artifact")
        try:
            pkg = _package_from(
                art.get("purl"),
                GRYPE_TYPES.get(_opt_text(art.get("type"))),
                art.get("name"),
                art.get("version"),
                label,
            )
        except InputError:
            out.skipped[f"unsupported Grype artifact type {art.get('type')!r}"] += 1
            continue
        ids = {check_id(vuln.get("id"), label)}
        for rel in _arr(m.get("relatedVulnerabilities"), f"{label}.relatedVulnerabilities"):
            ids.add(check_id(_obj(rel, label).get("id"), label))
        vectors = tuple(
            c["vector"]
            for c in _arr(vuln.get("cvss"), f"{label}.cvss")
            if isinstance(c, dict) and str(c.get("vector", "")).startswith("CVSS:3")
        )
        fix = _dict_or_empty(vuln.get("fix"))
        fixed = tuple(x for x in _arr(fix.get("versions"), f"{label}.fix") if isinstance(x, str))
        locs = _arr(art.get("locations"), f"{label}.locations")
        location = out.path
        if locs and isinstance(locs[0], dict) and isinstance(locs[0].get("path"), str):
            location = locs[0]["path"]
        out.observations.append(
            Observation(
                package=pkg,
                ids=frozenset(ids),
                source="grype",
                location=location,
                summary=_opt_text(vuln.get("description"))[:200],
                cvss_vectors=vectors,
                severity_label=_opt_text(vuln.get("severity")) or None,
                fixed=fixed,
            )
        )


def _cyclonedx(data: dict[str, Any], out: Parsed) -> None:
    """CycloneDX JSON: components[] (nested components included) with a purl."""
    stack = deque(_arr(data.get("components"), "components"))
    seen = 0
    while stack:
        seen += 1
        if seen > MAX_ENTRIES:
            raise InputError(f"{out.path}: more than {MAX_ENTRIES} components")
        comp = _obj(stack.popleft(), "component")
        stack.extend(_arr(comp.get("components"), "components"))
        purl = comp.get("purl")
        if not isinstance(purl, str) or not purl:
            out.skipped["components without a purl"] += 1
            continue
        try:
            pkg = parse_purl(purl)
        except InputError:
            out.skipped["components with an unsupported purl"] += 1
            continue
        out.components.append(Component(package=pkg, source="cyclonedx", location=out.path))


def _spdx(data: dict[str, Any], out: Parsed) -> None:
    """SPDX 2.x JSON: packages[] with a PACKAGE-MANAGER purl external reference."""
    for i, p in enumerate(_arr(data.get("packages"), "packages")):
        p = _obj(p, f"packages[{i}]")
        purls = [
            r.get("referenceLocator")
            for r in _arr(p.get("externalRefs"), f"packages[{i}].externalRefs")
            if isinstance(r, dict) and r.get("referenceType") == "purl"
        ]
        if not purls or not isinstance(purls[0], str):
            out.skipped["packages without a purl"] += 1
            continue
        try:
            pkg = parse_purl(purls[0])
        except InputError:
            out.skipped["packages with an unsupported purl"] += 1
            continue
        out.components.append(Component(package=pkg, source="spdx", location=out.path))
