"""OSV records: validation, range evaluation, database loading, and agreement with the OSV API."""

from __future__ import annotations

import json
import random
import zipfile
from pathlib import Path

import pytest
from helpers import ORACLE, OSV_DIR, record, write_json

from vuln_prioritization_engine.errors import InputError
from vuln_prioritization_engine.osvdb import (
    Database,
    MatchStats,
    Range,
    affects,
    in_range,
    load_database,
    parse_record,
)
from vuln_prioritization_engine.purl import make_package
from vuln_prioritization_engine.versions import compare_semver


def _rng(*events: tuple[str, str]) -> Range:
    return Range("SEMVER", tuple(events))


@pytest.mark.parametrize(
    ("version", "expected"),
    [("0.9.0", False), ("1.0.0", True), ("1.5.0", True), ("2.0.0", False), ("2.5.0", False),
     ("3.0.0", True), ("3.1.0", True), ("3.1.1", False)],
)  # fmt: skip
def test_range_introduced_fixed_reintroduced_last_affected(version: str, expected: bool) -> None:
    rng = _rng(("introduced", "1.0.0"), ("fixed", "2.0.0"), ("introduced", "3.0.0"),
               ("last_affected", "3.1.0"))  # fmt: skip
    assert in_range(version, rng, compare_semver) is expected


def test_range_introduced_zero_and_limit() -> None:
    assert in_range("0.0.1", _rng(("introduced", "0")), compare_semver)
    assert not in_range("5.0.0", _rng(("introduced", "0"), ("limit", "5.0.0")), compare_semver)
    assert in_range("4.9.9", _rng(("introduced", "0"), ("limit", "5.0.0")), compare_semver)


def test_range_events_are_sorted_before_evaluation() -> None:
    rng = _rng(("fixed", "2.0.0"), ("introduced", "1.0.0"))
    assert in_range("1.2.0", rng, compare_semver)
    assert not in_range("2.1.0", rng, compare_semver)


def test_random_ranges_agree_with_a_brute_force_model() -> None:
    rnd = random.Random(20261114)
    for _ in range(300):
        cuts = sorted(rnd.sample(range(1, 40), 4))
        intro, fixed, intro2, last = cuts
        rng = _rng(("introduced", f"{intro}.0.0"), ("fixed", f"{fixed}.0.0"),
                   ("introduced", f"{intro2}.0.0"), ("last_affected", f"{last}.0.0"))  # fmt: skip
        v = rnd.randrange(0, 45)
        model = intro <= v < fixed or intro2 <= v <= last
        assert in_range(f"{v}.0.0", rng, compare_semver) is model, (cuts, v)


def test_enumerated_versions_match_even_without_ranges() -> None:
    rec = parse_record(record(ecosystem="Debian:12", name="x", versions=["1.2-3"]), "t")
    assert affects(rec, make_package("Debian", "x", "1.2-3"))


def test_unsupported_ecosystem_ranges_are_counted_not_guessed() -> None:
    rec = parse_record(record(ecosystem="RubyGems", name="rack"), "t")
    stats = MatchStats()
    assert not affects(rec, make_package("RubyGems", "rack", "1.0.0"), stats)
    assert stats.unsupported == {"RubyGems": 1}


def test_unparsable_versions_are_reported() -> None:
    rec = parse_record(record(ecosystem="npm", name="x"), "t")
    stats = MatchStats()
    assert not affects(rec, make_package("npm", "x", "not-semver"), stats)
    assert len(stats.version_errors) == 1


def test_git_ranges_are_ignored_for_matching_and_fixed_versions() -> None:
    raw = record(name="demo")
    raw["affected"][0]["ranges"].append(
        {"type": "GIT", "repo": "https://example.invalid/r", "events": [{"fixed": "abc123"}]}
    )
    rec = parse_record(raw, "t")
    assert rec.fixed_for(make_package("PyPI", "demo", "1.0")) == ("2.0.0",)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(id="../etc/passwd"),
        lambda r: r.update(id=""),
        lambda r: r.update(aliases=["CVE 2021"]),
        lambda r: r.update(affected="x"),
        lambda r: r["affected"][0]["ranges"][0]["events"].append({"bogus": "1"}),
        lambda r: r["affected"][0]["ranges"][0]["events"].append({"fixed": "1", "introduced": "0"}),
        lambda r: r["affected"][0]["ranges"][0]["events"].append({"fixed": ""}),
        lambda r: r["affected"][0].update(versions=[1, 2]),
        lambda r: r.update(severity=["x"]),
        lambda r: r["affected"][0].pop("package"),
    ],
)
def test_malformed_records_are_rejected(mutate: object) -> None:
    raw = record()
    mutate(raw)  # type: ignore[operator]
    with pytest.raises(InputError):
        parse_record(raw, "t")
    with pytest.raises(InputError):
        parse_record(["not", "an", "object"], "t")


def test_database_aliases_withdrawn_and_duplicates() -> None:
    a = parse_record(record("GHSA-aaaa-bbbb-cccc", aliases=["CVE-2020-0001"]), "a")
    b = parse_record(record("PYSEC-2020-1", aliases=["CVE-2020-0001"]), "b")
    gone = record("GHSA-dddd-eeee-ffff")
    gone["withdrawn"] = "2025-01-01T00:00:00Z"
    db = Database([a, b, parse_record(gone, "c")])
    assert db.withdrawn == 1
    assert db.related("CVE-2020-0001") == {"CVE-2020-0001", "GHSA-aaaa-bbbb-cccc", "PYSEC-2020-1"}
    assert [r.id for r in db.match(make_package("PyPI", "Demo", "1.0"))] == [
        "GHSA-aaaa-bbbb-cccc",
        "PYSEC-2020-1",
    ]
    with pytest.raises(InputError, match="duplicate"):
        Database([a, a])


def test_zip_database_matches_folder(tmp_path: Path) -> None:
    zpath = tmp_path / "all.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for f in sorted(OSV_DIR.glob("*.json"))[:10]:
            zf.writestr(f.name, f.read_bytes())
    assert len(load_database(zpath).records) == 10


def test_bad_database_inputs(tmp_path: Path) -> None:
    (tmp_path / "x.zip").write_bytes(b"not a zip")
    with pytest.raises(InputError, match="zip"):
        load_database(tmp_path / "x.zip")
    with pytest.raises(InputError):
        load_database(tmp_path / "missing")
    bad = tmp_path / "db"
    write_json(bad / "a.json", {"id": "nope"})
    with pytest.raises(InputError):
        load_database(bad)
    big = tmp_path / "big.zip"
    with zipfile.ZipFile(big, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge.json", b" " * (5 * 1024 * 1024))
    with pytest.raises(InputError, match="too large"):
        load_database(big)


def test_local_matching_agrees_with_the_osv_api_for_every_package() -> None:
    """The OSV querybatch answer saved on 2026-11-14 equals our offline match on each package."""
    db = load_database(OSV_DIR)
    oracle = json.loads(ORACLE.read_text(encoding="utf-8"))
    assert len(oracle["results"]) == 10
    total = 0
    for res in oracle["results"]:
        q = res["query"]
        pkg = make_package(q["package"]["ecosystem"], q["package"]["name"], q["version"])
        ours = sorted(r.id for r in db.match(pkg))
        assert ours == res["ids"], pkg.label()
        assert res["next_page_token"] is None
        total += len(ours)
    assert total == 86
    clean = make_package("PyPI", "attrs", "23.2.0")
    assert db.match(clean) == []


def test_fixed_version_is_not_affected_in_real_records() -> None:
    db = load_database(OSV_DIR)
    assert db.match(make_package("Maven", "org.apache.logging.log4j:log4j-core", "2.25.3")) != []
    log4j_fixed = {r.id for r in db.match(make_package("Maven", "org.apache.logging.log4j:log4j-core", "2.17.1"))}  # fmt: skip
    assert "GHSA-jfh8-c2jp-5v3q" not in log4j_fixed  # CVE-2021-44228 fixed in 2.15.0
    assert {r.id for r in db.match(make_package("npm", "minimist", "1.2.6"))} == set()
