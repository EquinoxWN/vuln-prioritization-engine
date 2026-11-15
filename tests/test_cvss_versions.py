"""CVSS v3 base scores against published values, and version ordering per ecosystem."""

from __future__ import annotations

import random

import pytest

from vuln_prioritization_engine.cvss import (
    normalize_label,
    roundup_31,
    score_v3,
    severity_of,
)
from vuln_prioritization_engine.errors import InputError, VersionError
from vuln_prioritization_engine.versions import (
    comparator,
    compare_maven,
    compare_pypi,
    compare_semver,
    sort_versions,
)


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # CVE-2021-44228 (NVD)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),  # CVE-2023-44487 (NVD)
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N", 6.1),  # CVE-2023-32681 (NVD)
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),  # CVE-2021-23337 (NVD)
        ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.6),  # CVE-2021-44832 (NVD)
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.3),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O", 9.8),
    ],
)
def test_base_scores_match_published_values(vector: str, score: float) -> None:
    assert score_v3(vector).base_score == score


def test_roundup_is_float_safe() -> None:
    assert roundup_31(4.000000000001) == 4.0
    assert roundup_31(4.02) == 4.1
    assert roundup_31(4.0) == 4.0


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # duplicate
        "CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # bad value
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:X",  # unknown metric
        "CVSS:3.1/AV:N/AC/PR:N/UI:N/S:U/C:H/I:H/A:H",  # no colon
        "",
    ],
)
def test_invalid_vectors_are_rejected(vector: str) -> None:
    with pytest.raises(InputError):
        score_v3(vector)


@pytest.mark.parametrize(
    ("score", "sev"),
    [(0.0, "NONE"), (0.1, "LOW"), (3.9, "LOW"), (4.0, "MEDIUM"), (6.9, "MEDIUM"),
     (7.0, "HIGH"), (8.9, "HIGH"), (9.0, "CRITICAL"), (10.0, "CRITICAL")],
)  # fmt: skip
def test_severity_buckets_at_boundaries(score: float, sev: str) -> None:
    assert severity_of(score) == sev


def test_severity_rejects_out_of_range_and_labels_normalize() -> None:
    with pytest.raises(InputError):
        severity_of(10.1)
    assert normalize_label("moderate") == "MEDIUM"
    assert normalize_label("Negligible") == "LOW"
    assert normalize_label("weird") is None
    assert normalize_label(None) is None


def test_semver_precedence_follows_the_spec() -> None:
    ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
               "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.10.0", "2.0.0"]  # fmt: skip
    shuffled = ordered[:]
    random.Random(7).shuffle(shuffled)
    assert sort_versions(shuffled, compare_semver) == ordered
    assert compare_semver("v0.7.0", "0.7.0") == 0
    assert compare_semver("1.0.0+build.5", "1.0.0") == 0


@pytest.mark.parametrize("bad", ["1.0", "01.0.0", "1.0.0-", "x.y.z", ""])
def test_semver_rejects_invalid(bad: str) -> None:
    with pytest.raises(VersionError):
        compare_semver(bad, "1.0.0")


def test_pypi_uses_pep440() -> None:
    ordered = ["1.0.dev1", "1.0a1", "1.0b2", "1.0rc1", "1.0", "1.0.post1", "1.0.1", "1.10"]
    assert sort_versions(list(reversed(ordered)), compare_pypi) == ordered
    assert compare_pypi("2.0", "2.0.0") == 0
    with pytest.raises(VersionError):
        compare_pypi("not a version", "1.0")


def test_maven_numbers_and_qualifiers() -> None:
    ordered = ["2.0-alpha1", "2.0-beta9", "2.0-rc1", "2.0", "2.0-sp1", "2.0.1", "2.3.1",
               "2.12.2", "2.14.1", "2.15.0", "2.17.1"]  # fmt: skip
    assert sort_versions(list(reversed(ordered)), compare_maven) == ordered
    assert compare_maven("2.15", "2.15.0") == 0
    assert compare_maven("1.0-final", "1.0") == 0
    with pytest.raises(VersionError):
        compare_maven("", "1.0")


def test_comparator_by_ecosystem() -> None:
    assert comparator("npm") is compare_semver
    assert comparator("Go") is compare_semver
    assert comparator("PyPI") is compare_pypi
    assert comparator("Maven") is compare_maven
    assert comparator("Debian:12") is None
