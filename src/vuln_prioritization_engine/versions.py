"""Version ordering per ecosystem: SemVer (npm, Go, crates.io), PEP 440 (PyPI), Maven."""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import cmp_to_key
from typing import Any

from packaging.version import InvalidVersion, Version

from .errors import VersionError

_SEMVER = re.compile(
    r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_MAVEN_QUALIFIERS = {
    "alpha": 0,
    "a": 0,
    "beta": 1,
    "b": 1,
    "milestone": 2,
    "m": 2,
    "rc": 3,
    "cr": 3,
    "snapshot": 4,
    "": 5,
    "ga": 5,
    "final": 5,
    "release": 5,
    "sp": 6,
}
_MAVEN_TOKEN = re.compile(r"\d+|[a-z]+")

SEMVER_ECOSYSTEMS = frozenset({"npm", "Go", "crates.io"})
SUPPORTED_ECOSYSTEMS = SEMVER_ECOSYSTEMS | {"PyPI", "Maven"}


def compare_semver(a: str, b: str) -> int:
    """Compare two SemVer 2.0 strings (leading v allowed, build metadata ignored)."""
    ka, kb = _semver_key(a), _semver_key(b)
    if ka[:3] != kb[:3]:
        return -1 if ka[:3] < kb[:3] else 1
    pa, pb = ka[3], kb[3]
    if pa == pb:
        return 0
    if not pa:
        return 1
    if not pb:
        return -1
    for x, y in zip(pa, pb, strict=False):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, int):
            return -1
        if isinstance(y, int):
            return 1
        return -1 if str(x) < str(y) else 1
    return -1 if len(pa) < len(pb) else 1


def _semver_key(v: str) -> tuple[int, int, int, tuple[int | str, ...]]:
    """Parse SemVer into comparable parts."""
    m = _SEMVER.fullmatch(v.strip())
    if not m:
        raise VersionError(f"not a SemVer version: {v!r}")
    pre: tuple[int | str, ...] = ()
    if m.group(4):
        pre = tuple(int(p) if p.isdigit() else p for p in m.group(4).split("."))
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre


def compare_pypi(a: str, b: str) -> int:
    """Compare two PEP 440 versions."""
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion as exc:
        raise VersionError(f"not a PEP 440 version: {exc}") from exc
    return (va > vb) - (va < vb)


def _maven_tokens(v: str) -> list[int | str]:
    """Split a Maven version into numbers and lower-case qualifiers, trailing nulls dropped."""
    text = v.strip().lower()
    if not text or not re.fullmatch(r"[0-9a-z][0-9a-z.\-_]*", text):
        raise VersionError(f"not a Maven version: {v!r}")
    tokens: list[int | str] = [int(t) if t.isdigit() else t for t in _MAVEN_TOKEN.findall(text)]
    while tokens and tokens[-1] in (0, "", "ga", "final", "release"):
        tokens.pop()
    return tokens


def _maven_item(t: int | str | None) -> tuple[int, int, str]:
    """Sort key of one Maven token: pre-release < release (missing, 0) < sp < other words < 1."""
    if t is None:
        return (1, 0, "")
    if isinstance(t, int):
        return (1, t, "")
    rank = _MAVEN_QUALIFIERS.get(t)
    if rank is None:
        return (1, 0, "~" + t)
    if rank == 6:
        return (1, 0, "sp")
    if rank == 5:
        return (1, 0, "")
    return (0, rank, "")


def compare_maven(a: str, b: str) -> int:
    """Compare Maven versions: numbers numerically, standard qualifiers in Maven's order."""
    ta, tb = _maven_tokens(a), _maven_tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = _maven_item(ta[i] if i < len(ta) else None)
        y = _maven_item(tb[i] if i < len(tb) else None)
        if x != y:
            return -1 if x < y else 1
    return 0


def comparator(ecosystem: str) -> Callable[[str, str], int] | None:
    """The version comparison for an OSV ecosystem, or None when unsupported."""
    base = ecosystem.split(":", 1)[0]
    if base in SEMVER_ECOSYSTEMS:
        return compare_semver
    if base == "PyPI":
        return compare_pypi
    if base == "Maven":
        return compare_maven
    return None


def sort_versions(versions: list[str], cmp: Callable[[str, str], int]) -> list[str]:
    """Sort version strings with a comparator."""
    key: Callable[[str], Any] = cmp_to_key(cmp)
    return sorted(versions, key=key)
