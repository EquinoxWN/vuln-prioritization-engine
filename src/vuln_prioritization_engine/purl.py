"""Package URL parsing and package-name normalization per OSV ecosystem."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

from .errors import InputError

PURL_TYPES = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "maven": "Maven",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
}
_TYPE = re.compile(r"[a-z][a-z0-9.+-]*")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
MAX_PURL = 2048


@dataclass(frozen=True)
class Package:
    """One package version in OSV terms."""

    ecosystem: str
    name: str
    version: str
    purl: str | None = None

    def key(self) -> tuple[str, str, str]:
        """Identity used to merge findings from different sources."""
        return (self.ecosystem, self.name, canonical_version(self.ecosystem, self.version))

    def label(self) -> str:
        """Readable name@version."""
        return f"{self.name}@{self.version}"


def normalize_name(ecosystem: str, name: str) -> str:
    """Name as OSV indexes it (PEP 503 for PyPI, lower-case npm, group:artifact for Maven)."""
    name = name.strip()
    if not name:
        raise InputError("empty package name")
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "npm":
        return name.lower()
    return name


def canonical_version(ecosystem: str, version: str) -> str:
    """Version text without cosmetic differences (Go's leading v)."""
    version = version.strip()
    if ecosystem == "Go" and version.startswith("v"):
        return version[1:]
    return version


def make_package(ecosystem: str, name: str, version: str, purl: str | None = None) -> Package:
    """Build a validated, normalized Package."""
    if not version or not version.strip():
        raise InputError(f"{ecosystem}/{name[:40]!r}: missing version")
    if len(name) > 512 or len(version) > 256:
        raise InputError(f"{ecosystem}/{name[:40]!r}: name or version too long")
    if _CONTROL.search(name) or _CONTROL.search(version) or _CONTROL.search(ecosystem):
        raise InputError(f"{ecosystem!r}/{name[:40]!r}: control characters in package fields")
    return Package(
        ecosystem=ecosystem,
        name=normalize_name(ecosystem, name),
        version=canonical_version(ecosystem, version),
        purl=purl,
    )


def parse_purl(purl: str) -> Package:
    """Parse pkg:type/namespace/name@version into a Package (qualifiers and subpath ignored)."""
    if len(purl) > MAX_PURL:
        raise InputError("package URL too long")
    if not purl.startswith("pkg:"):
        raise InputError(f"not a package URL: {purl[:80]!r}")
    body = purl[4:].lstrip("/")
    body = body.split("#", 1)[0].split("?", 1)[0]
    ptype, sep, rest = body.partition("/")
    ptype = ptype.lower()
    if not sep or not _TYPE.fullmatch(ptype):
        raise InputError(f"package URL has no valid type: {purl[:80]!r}")
    ecosystem = PURL_TYPES.get(ptype)
    if ecosystem is None:
        raise InputError(f"unsupported package URL type {ptype!r}")
    path, at, version = rest.rpartition("@")
    if not at or not version:
        raise InputError(f"package URL has no version: {purl[:80]!r}")
    segments = [unquote(s) for s in path.strip("/").split("/") if s]
    if not segments:
        raise InputError(f"package URL has no name: {purl[:80]!r}")
    version = unquote(version)
    if ecosystem == "Maven":
        if len(segments) != 2:
            raise InputError(f"Maven package URL needs namespace/name: {purl[:80]!r}")
        name = f"{segments[0]}:{segments[1]}"
    else:
        name = "/".join(segments)
    return make_package(ecosystem, name, version, purl)
