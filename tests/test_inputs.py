"""Scanner reports and SBOMs: format detection, normalization, skips and malformed input."""

from __future__ import annotations

from pathlib import Path

import pytest
from helpers import GRYPE, OSV_SCANNER, SBOM_CDX, SBOM_SPDX, TRIVY, record, write_json

from vuln_prioritization_engine.errors import InputError
from vuln_prioritization_engine.inputs import detect, read_input
from vuln_prioritization_engine.jsonio import read_bytes
from vuln_prioritization_engine.purl import make_package, parse_purl


def test_detects_every_supported_format() -> None:
    assert [read_input(p).kind for p in (OSV_SCANNER, TRIVY, GRYPE, SBOM_CDX, SBOM_SPDX)] == [
        "osv-scanner",
        "trivy",
        "grype",
        "cyclonedx",
        "spdx",
    ]
    unknown: object
    for unknown in ({}, [], {"results": "x"}, "text"):
        with pytest.raises(InputError, match="unrecognized"):
            detect(unknown)


def test_osv_scanner_report_carries_full_records() -> None:
    p = read_input(OSV_SCANNER)
    req = [o for o in p.observations if o.package.name == "requests"]
    assert len(req) == 8  # each advisory appears as a GHSA and a PYSEC record
    leak = next(o for o in req if "GHSA-j8r2-6x86-q33q" in o.ids)
    assert "CVE-2023-32681" in leak.ids
    assert leak.fixed == ("2.31.0",)
    assert leak.location == "/src/shop-api/requirements.txt"


def test_trivy_uses_type_when_no_purl_and_skips_os_packages() -> None:
    p = read_input(TRIVY)
    go = [o for o in p.observations if o.package.ecosystem == "Go"]
    assert go
    assert {o.package.version for o in go} == {"0.7.0"}  # Trivy's v0.7.0 normalized
    lodash = next(o for o in p.observations if "CVE-2021-23337" in o.ids)
    assert "GHSA-35jh-r3h4-6jhm" in lodash.ids
    assert lodash.package.purl == "pkg:npm/lodash@4.17.20"
    assert p.skipped == {"OS packages (not in M1)": 1}


def test_grype_merges_related_ids_and_skips_os_artifacts() -> None:
    p = read_input(GRYPE)
    l4 = next(o for o in p.observations if "GHSA-jfh8-c2jp-5v3q" in o.ids)
    assert "CVE-2021-44228" in l4.ids
    assert l4.package.name == "org.apache.logging.log4j:log4j-core"
    assert l4.location == "/opt/app/lib/log4j-core-2.14.1.jar"
    assert p.skipped == {"unsupported Grype artifact type 'deb'": 1}


def test_sboms_list_components_including_nested_ones() -> None:
    cdx = read_input(SBOM_CDX)
    names = {c.package.name for c in cdx.components}
    assert "org.apache.logging.log4j:log4j-core" in names  # nested component
    assert len(cdx.components) == 10
    assert cdx.skipped == {"components without a purl": 1}
    spdx = read_input(SBOM_SPDX)
    assert {c.package.label() for c in spdx.components} == {"requests@2.25.1", "lodash@4.17.20"}
    assert spdx.skipped == {"packages with an unsupported purl": 1, "packages without a purl": 1}


@pytest.mark.parametrize(
    ("purl", "eco", "name", "version"),
    [
        ("pkg:pypi/Jinja2@2.11.2", "PyPI", "jinja2", "2.11.2"),
        ("pkg:pypi/zope.interface@5.0", "PyPI", "zope-interface", "5.0"),
        ("pkg:npm/%40angular/core@16.0.0", "npm", "@angular/core", "16.0.0"),
        ("pkg:golang/golang.org/x/net@v0.7.0?type=module#sub", "Go", "golang.org/x/net", "0.7.0"),
        ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar", "Maven",
         "org.apache.logging.log4j:log4j-core", "2.14.1"),
        ("pkg:cargo/smallvec@1.6.0", "crates.io", "smallvec", "1.6.0"),
    ],
)  # fmt: skip
def test_purl_parsing(purl: str, eco: str, name: str, version: str) -> None:
    pkg = parse_purl(purl)
    assert (pkg.ecosystem, pkg.name, pkg.version) == (eco, name, version)


@pytest.mark.parametrize(
    "purl",
    ["npm/lodash@1", "pkg:npm/lodash", "pkg:npm/@1.0.0", "pkg:deb/debian/libc6@2.36",
     "pkg:maven/log4j-core@2.14.1", "pkg:/x@1", "pkg:" + "a" * 3000],
)  # fmt: skip
def test_bad_purls_are_rejected(purl: str) -> None:
    with pytest.raises(InputError):
        parse_purl(purl)


def test_package_validation() -> None:
    with pytest.raises(InputError):
        make_package("PyPI", "x", " ")
    with pytest.raises(InputError):
        make_package("PyPI", " ", "1.0")
    assert make_package("Go", "m", "v1.2.3").key() == ("Go", "m", "1.2.3")
    with pytest.raises(InputError, match="control characters"):
        make_package("npm", "evil\x1b[2J", "1.0.0")  # terminal escape in a scanner report
    with pytest.raises(InputError, match="control characters"):
        parse_purl("pkg:npm/x@1.0.0%0A")


@pytest.mark.parametrize(
    "doc",
    [
        {"results": [{"packages": [{"package": {"name": "x", "ecosystem": "PyPI"}}]}]},
        {"results": [{"packages": [{"package": {"name": "x", "version": "1", "ecosystem": "PyPI"},
                                    "vulnerabilities": [{"id": "bad id"}]}]}]},
        {"SchemaVersion": 2, "Results": [{"Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": "../x", "PkgName": "x", "InstalledVersion": "1.0.0"}]}]},
        {"SchemaVersion": 2, "Results": {"not": "a list"}},
        {"matches": [{"vulnerability": {"id": "GHSA-x-y"}, "artifact": "nope"}], "descriptor": {}},
        {"bomFormat": "CycloneDX", "components": [{"components": "x"}]},
        {"spdxVersion": "SPDX-2.3", "packages": ["x"]},
    ],
)  # fmt: skip
def test_malformed_reports_are_rejected(tmp_path: Path, doc: object) -> None:
    with pytest.raises(InputError):
        read_input(write_json(tmp_path / "r.json", doc))


def test_unreadable_and_oversized_files(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(InputError, match="invalid JSON"):
        read_input(tmp_path / "bad.json")
    with pytest.raises(InputError, match="not a regular file"):
        read_input(tmp_path / "missing.json")
    (tmp_path / "deep.json").write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
    with pytest.raises(InputError):
        read_input(tmp_path / "deep.json")
    (tmp_path / "latin.json").write_bytes(b'{"results": ["\xe9"]}')
    with pytest.raises(InputError, match="UTF-8"):
        read_input(tmp_path / "latin.json")


def test_osv_scanner_with_a_scanner_only_record(tmp_path: Path) -> None:
    doc = {"results": [{"source": {"path": "req.txt"}, "packages": [{
        "package": {"name": "demo", "version": "1.0", "ecosystem": "PyPI"},
        "vulnerabilities": [record(aliases=["CVE-2020-0001"])]}]}]}  # fmt: skip
    p = read_input(write_json(tmp_path / "r.json", doc))
    assert p.observations[0].ids == {"GHSA-aaaa-bbbb-cccc", "CVE-2020-0001"}


def test_files_over_the_size_limit_are_refused_before_reading(tmp_path: Path) -> None:
    big = tmp_path / "big.json"
    big.write_bytes(b" " * 2048)
    with pytest.raises(InputError, match="over the 1024-byte limit"):
        read_bytes(big, limit=1024)
    assert read_bytes(big, limit=2048) == b" " * 2048
