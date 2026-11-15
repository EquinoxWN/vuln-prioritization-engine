"""Merging sources into findings, OSV details, EPSS/KEV enrichment and feed-age warnings."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from helpers import (
    EPSS,
    GRYPE,
    KEV,
    OSV_DIR,
    OSV_SCANNER,
    SBOM_CDX,
    SBOM_SPDX,
    TRIVY,
    record,
    write_json,
)

from vuln_prioritization_engine.engine import canonical_id, enrich, nearest_fix, normalize
from vuln_prioritization_engine.errors import InputError
from vuln_prioritization_engine.feeds import load_epss, load_kev
from vuln_prioritization_engine.inputs import Parsed, read_input
from vuln_prioritization_engine.models import Component, Observation
from vuln_prioritization_engine.osvdb import Database, load_database, parse_record
from vuln_prioritization_engine.purl import make_package

ALL = [OSV_SCANNER, TRIVY, GRYPE, SBOM_CDX, SBOM_SPDX]


@pytest.fixture(scope="module")
def db() -> Database:
    return load_database(OSV_DIR)


def _obs(ids: set[str], source: str = "trivy", version: str = "1.0", **kw: object) -> Observation:
    return Observation(make_package("PyPI", "demo", version), frozenset(ids), source, "f", **kw)  # type: ignore[arg-type]


def test_canonical_id_prefers_cve_then_ghsa() -> None:
    assert (
        canonical_id({"GO-2023-2102", "GHSA-qppj-fm5r-hxr3", "CVE-2023-44487"}) == "CVE-2023-44487"
    )
    assert canonical_id({"PYSEC-2020-1", "GHSA-b"}) == "GHSA-b"
    assert canonical_id({"PYSEC-2020-2", "PYSEC-2020-1"}) == "PYSEC-2020-1"


def test_all_inputs_merge_into_one_finding_per_package_and_vulnerability(db: Database) -> None:
    sbom_only = normalize([read_input(SBOM_CDX)], db)
    full = normalize([read_input(p) for p in ALL], db)
    assert len(sbom_only.findings) == 59
    assert len(full.findings) == 59  # three scanner reports add sources, not duplicates
    assert full.components == 10
    keys = [(f.package.key(), f.id) for f in full.findings]
    assert len(keys) == len(set(keys))
    l4 = next(f for f in full.findings if f.id == "CVE-2021-44228")
    assert l4.sources == ("grype", "sbom+osv")
    assert l4.upgrade_to == "2.15.0"
    assert l4.cvss_score == 10.0
    assert l4.severity == "CRITICAL"
    assert l4.details_from == "osv-db:GHSA-jfh8-c2jp-5v3q"
    go = next(f for f in full.findings if f.id == "CVE-2023-39325")
    assert set(go.aliases) >= {"GO-2023-2102", "GHSA-4374-p667-p6c8"}  # GO and GHSA merged
    assert go.sources == ("trivy", "sbom+osv")
    assert len(go.details_from.split(",")) == 2
    req = next(f for f in full.findings if f.id == "CVE-2023-32681")
    assert req.sources == ("osv-scanner", "sbom+osv")
    assert "src/shop-api/requirements.txt" in " ".join(req.locations)
    assert len(req.details_from.split(",")) == 2  # GHSA and PYSEC records


def test_normalize_is_idempotent_for_repeated_inputs(db: Database) -> None:
    once = normalize([read_input(TRIVY)], db)
    twice = normalize([read_input(TRIVY), read_input(TRIVY)], db)
    assert [f.to_json() for f in once.findings] == [f.to_json() for f in twice.findings]


def test_findings_are_split_by_package_version() -> None:
    res = normalize([Parsed("a", "trivy", [_obs({"CVE-2020-0001"}), _obs({"CVE-2020-0001"}, version="1.1")])], None)  # fmt: skip
    assert [f.package.version for f in res.findings] == ["1.0", "1.1"]


def test_scanner_only_details_and_label_fallback() -> None:
    res = normalize(
        [Parsed("a", "trivy", [
            _obs({"CVE-2020-0001", "GHSA-aaaa"}, summary="from trivy", severity_label="moderate"),
            _obs({"GHSA-aaaa"}, source="grype", summary="from grype", severity_label="HIGH",
                 fixed=("1.2", "1.10")),
        ])],
        None,
    )  # fmt: skip
    (f,) = res.findings
    assert f.details_from == "scanner"
    assert f.summary == "from trivy"
    assert f.severity == "HIGH"  # highest label when no CVSS vector
    assert f.cvss_score is None
    assert f.fixed_versions == ("1.2", "1.10")  # PEP 440 order, not lexical
    assert f.upgrade_to == "1.2"


def test_osv_record_wins_over_scanner_details_and_flags_disagreement() -> None:
    rec = parse_record(record(aliases=["CVE-2020-0001"],
                              vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), "r")  # fmt: skip
    db = Database([rec])
    obs = _obs({"CVE-2020-0001"}, version="3.0", summary="scanner text",
               cvss_vectors=("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",))  # fmt: skip
    (f,) = normalize([Parsed("a", "trivy", [obs])], db).findings
    assert f.summary == "summary of GHSA-aaaa-bbbb-cccc"
    assert f.cvss_score == 9.8
    assert any("does not list demo@3.0 as affected" in n for n in f.notes)
    assert f.upgrade_to is None  # 2.0.0 is below the installed 3.0


def test_invalid_and_v4_only_vectors_are_noted_not_fatal() -> None:
    bad = _obs({"CVE-2020-0001"}, cvss_vectors=("CVSS:3.1/AV:X", "CVSS:4.0/AV:N/AC:L"))
    (f,) = normalize([Parsed("a", "trivy", [bad])], None).findings
    assert f.cvss_score is None
    assert f.cvss_vector == "CVSS:4.0/AV:N/AC:L"
    assert f.severity == "UNKNOWN"
    assert len(f.notes) == 2


def test_sbom_without_database_is_an_input_error() -> None:
    comp = Component(make_package("PyPI", "demo", "1.0"), "cyclonedx", "s")
    with pytest.raises(InputError, match="--osv-db"):
        normalize([Parsed("s", "cyclonedx", components=[comp])], None)


def test_enrich_takes_highest_epss_any_kev_and_notes_missing(db: Database) -> None:
    res = normalize([read_input(p) for p in ALL], db)
    enrich(res, load_epss(EPSS), load_kev(KEV), date(2026, 11, 14), 7)
    kev = sorted(f.id for f in res.findings if f.kev)
    assert kev == ["CVE-2021-44228", "CVE-2021-45046", "CVE-2023-44487"]
    assert all(f.epss for f in res.findings)
    assert res.warnings == [
        "tests/fixtures/scans/trivy.json: skipped 1 OS packages (not in M1)".replace(
            "tests/fixtures/scans/trivy.json", TRIVY.as_posix()
        ),
        f"{GRYPE.as_posix()}: skipped 1 unsupported Grype artifact type 'deb'",
        f"{SBOM_CDX.as_posix()}: skipped 1 components without a purl",
        f"{SBOM_SPDX.as_posix()}: skipped 1 packages with an unsupported purl",
        f"{SBOM_SPDX.as_posix()}: skipped 1 packages without a purl",
    ]


def test_enrich_without_cve_and_without_score() -> None:
    res = normalize([Parsed("a", "trivy", [_obs({"GHSA-aaaa"}), _obs({"CVE-2099-0001"}, version="2")])], None)  # fmt: skip
    enrich(res, load_epss(EPSS), load_kev(KEV), date(2026, 11, 14), 7)
    no_cve, unscored = res.findings
    assert no_cve.notes == ["no CVE alias, so EPSS and KEV do not apply"]
    assert unscored.notes == ["no EPSS score for CVE-2099-0001"]
    assert unscored.kev is None


@pytest.mark.parametrize(
    ("as_of", "warn"),
    [(date(2026, 11, 20), False), (date(2026, 11, 21), True), (date(2026, 11, 12), True)],
)
def test_feed_age_warnings(tmp_path: Path, as_of: date, warn: bool) -> None:
    res = normalize([], None)
    enrich(res, load_epss(EPSS), None, as_of, 7)
    assert bool(res.warnings) is warn


def test_nearest_fix_handles_unordered_and_unknown() -> None:
    pkg = make_package("npm", "x", "1.0.0")
    assert nearest_fix(pkg, ["2.0.0", "1.5.0", "0.9.0"]) == "1.5.0"
    assert nearest_fix(pkg, ["garbage"]) is None
    assert nearest_fix(make_package("RubyGems", "x", "1"), ["2"]) is None


def test_osv_aliases_merge_reports_that_share_no_id() -> None:
    """Trivy says CVE-2020-0001, Grype says GHSA-aaaa-bbbb-cccc; only the OSV record links them."""
    db = Database([parse_record(record(aliases=["CVE-2020-0001"]), "r")])
    obs = [_obs({"CVE-2020-0001"}), _obs({"GHSA-aaaa-bbbb-cccc"}, source="grype")]
    (f,) = normalize([Parsed("a", "trivy", obs)], db).findings
    assert f.sources == ("trivy", "grype")
    assert len(normalize([Parsed("a", "trivy", obs)], None).findings) == 2


def test_enrich_uses_the_highest_epss_across_cve_aliases(tmp_path: Path) -> None:
    rows = [{"cve": c, "epss": s, "percentile": "0.5", "date": "2026-11-13"}
            for c, s in (("CVE-2020-0001", "0.2"), ("CVE-2020-0002", "0.7"), ("CVE-2020-0003", "0.1"))]  # fmt: skip
    epss = load_epss(write_json(tmp_path / "e.json", {"data": rows}))
    res = normalize([Parsed("a", "trivy", [_obs({"CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"})])], None)  # fmt: skip
    enrich(res, epss, None, date(2026, 11, 14), 7)
    assert res.findings[0].epss is not None
    assert res.findings[0].epss.cve == "CVE-2020-0002"


def test_nearest_fix_never_suggests_the_installed_version() -> None:
    assert nearest_fix(make_package("npm", "x", "1.0.0"), ["1.0.0", "1.5.0"]) == "1.5.0"
    assert nearest_fix(make_package("npm", "x", "1.5.0"), ["1.0.0", "1.5.0"]) is None
