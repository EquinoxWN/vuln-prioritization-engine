"""EPSS and KEV loading: the dated fixtures, the CSV format, and every validation failure."""

from __future__ import annotations

import gzip
from pathlib import Path
from typing import Any

import pytest
from helpers import EPSS, KEV, write_json

from vuln_prioritization_engine.errors import InputError
from vuln_prioritization_engine.feeds import load_epss, load_kev, parse_kev


def test_epss_snapshot_fixture() -> None:
    feed = load_epss(EPSS)
    assert feed.score_date == "2026-11-13"
    assert len(feed.scores) == 59
    l4 = feed.scores["CVE-2021-44228"]
    assert l4.score > 0.99
    assert 0 <= l4.percentile <= 1


def test_kev_subset_fixture() -> None:
    feed = load_kev(KEV)
    assert feed.catalog_version == "2026.11.13"
    assert feed.date_released == "2026-11-13"
    assert len(feed.entries) == 8
    assert {"CVE-2021-44228", "CVE-2021-45046", "CVE-2023-44487"} <= set(feed.entries)


CSV = "#model_version:v2025.03.14,score_date:2026-11-13T00:00:00+0000\ncve,epss,percentile\n"


def test_epss_daily_csv_plain_and_gzip(tmp_path: Path) -> None:
    body = CSV + "CVE-2021-44228,0.94358,0.99957\nCVE-2020-14343,0.06,0.9\n"
    (tmp_path / "e.csv").write_text(body, encoding="utf-8")
    (tmp_path / "e.csv.gz").write_bytes(gzip.compress(body.encode()))
    for name in ("e.csv", "e.csv.gz"):
        feed = load_epss(tmp_path / name)
        assert feed.model_version == "v2025.03.14"
        assert feed.score_date == "2026-11-13"
        assert feed.scores["CVE-2021-44228"].score == 0.94358


@pytest.mark.parametrize(
    "body",
    [
        "",
        "cve,epss,percentile\nCVE-2021-44228,0.9,0.9\n",
        CSV.replace("cve,epss,percentile", "cve,score"),
        CSV + "CVE-2021-44228,1.5,0.9\n",
        CSV + "CVE-2021-44228,-0.1,0.9\n",
        CSV + "CVE-2021-44228,abc,0.9\n",
        CSV + "CVE-21-1,0.1,0.9\n",
        CSV + "CVE-2021-44228,0.1\n",
        CSV + "CVE-2021-44228,0.1,0.2\nCVE-2021-44228,0.1,0.2\n",
        CSV,
        CSV.replace("2026-11-13", "2026-13-45"),
    ],
)
def test_bad_epss_csv(tmp_path: Path, body: str) -> None:
    (tmp_path / "e.csv").write_text(body, encoding="utf-8")
    with pytest.raises(InputError):
        load_epss(tmp_path / "e.csv")


@pytest.mark.parametrize(
    "doc",
    [
        {"data": "x"},
        {"data": []},
        {"data": [{"cve": "CVE-2021-44228", "epss": "0.5", "percentile": "0.5"}]},
        {"data": [{"cve": "nope", "epss": "0.5", "percentile": "0.5", "date": "2026-11-13"}]},
        {
            "data": [
                {"cve": "CVE-2021-44228", "epss": "2", "percentile": "0.5", "date": "2026-11-13"}
            ]
        },
    ],
)
def test_bad_epss_json(tmp_path: Path, doc: Any) -> None:
    with pytest.raises(InputError):
        load_epss(write_json(tmp_path / "e.json", doc))


def _kev(**over: Any) -> dict[str, Any]:
    entry = {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
             "knownRansomwareCampaignUse": "Known", "vulnerabilityName": "Log4j"}  # fmt: skip
    doc: dict[str, Any] = {"catalogVersion": "1", "dateReleased": "2026-11-13T00:00:00Z",
                           "count": 1, "vulnerabilities": [entry]}  # fmt: skip
    doc.update(over)
    return doc


def test_kev_minimal_valid_catalog() -> None:
    feed = parse_kev(_kev(), "t")
    assert feed.entries["CVE-2021-44228"].ransomware == "Known"


@pytest.mark.parametrize(
    "over",
    [
        {"count": 2},
        {"count": "1"},
        {"catalogVersion": ""},
        {"dateReleased": "yesterday"},
        {
            "vulnerabilities": [
                {"cveID": "CVE-2021-44228", "dateAdded": "x", "dueDate": "2021-12-24"}
            ]
        },
        {"vulnerabilities": "x"},
        {"vulnerabilities": [{"cveID": "bad", "dateAdded": "2021-12-10", "dueDate": "2021-12-24"}]},
        {"count": 2, "vulnerabilities": [_kev()["vulnerabilities"][0]] * 2},
    ],
)
def test_bad_kev_catalogs(over: dict[str, Any]) -> None:
    with pytest.raises(InputError):
        parse_kev(_kev(**over), "t")
