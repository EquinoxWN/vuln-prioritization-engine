"""`vpe report` end to end on the fixtures, the JSON report, and bad input exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from helpers import EPSS, GRYPE, KEV, OSV_DIR, OSV_SCANNER, SBOM_CDX, SBOM_SPDX, TRIVY

from vuln_prioritization_engine.cli import main

FULL = [str(p) for p in (OSV_SCANNER, TRIVY, GRYPE, SBOM_CDX, SBOM_SPDX)]
FEEDS = ["--osv-db", str(OSV_DIR), "--epss", str(EPSS), "--kev", str(KEV), "--as-of", "2026-11-14"]


def test_report_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "r.json"
    assert main(["report", *FULL, *FEEDS, "--json", str(out), "--sort", "epss"]) == 0
    text = capsys.readouterr().out
    assert text.splitlines()[-1] == (
        "59 findings on 9 packages: 3 in KEV, 59 with EPSS, 0 without a CVE, "
        "41 seen by more than one source"
    )
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["summary"]["findings"] == 59
    assert doc["summary"]["in_kev"] == 3
    assert doc["summary"]["by_severity"]["CRITICAL"] == 4
    assert doc["feeds"]["osv_db"]["records"] == 86
    assert doc["feeds"]["kev"]["catalog_version"] == "2026.11.13"
    assert doc["generated_at"].endswith("+00:00")
    assert len(doc["inputs"]) == 5
    assert all(len(i["sha256"]) == 64 for i in doc["inputs"])
    scores = [f["epss"]["score"] for f in doc["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_json_report_rewrite_is_identical_apart_from_time(tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    docs = []
    for _ in range(2):
        assert main(["report", str(TRIVY), *FEEDS, "--json", str(out)]) == 0
        doc = json.loads(out.read_text(encoding="utf-8"))
        doc.pop("generated_at")
        docs.append(doc)
    assert docs[0] == docs[1]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["r.json"]


def test_sort_by_cvss(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["report", str(SBOM_CDX), "--osv-db", str(OSV_DIR), "--sort", "cvss"]) == 0
    first = capsys.readouterr().out.splitlines()[1]
    assert first.startswith("CVE-2021-44228")


@pytest.mark.parametrize(
    "args",
    [
        ["report", str(SBOM_CDX)],  # SBOM without --osv-db
        ["report", "missing.json"],
        ["report", str(TRIVY), "--epss", str(KEV)],  # wrong feed file
        ["report", str(TRIVY), "--kev", str(EPSS)],
        ["report", str(TRIVY), "--as-of", "14/11/2026"],
        ["report", str(TRIVY), "--max-feed-age", "-1"],
        ["report", str(TRIVY), "--osv-db", str(KEV)],
        ["fetch", "osv", "--out-dir", "x"],  # nothing to fetch
        ["fetch", "kev", "--out", "x", "--timeout", "0"],
    ],
)
def test_bad_input_exits_2(args: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(args) == 2
    assert capsys.readouterr().err.startswith("error: ")


def test_fetch_epss_from_a_non_report_is_refused(tmp_path: Path) -> None:
    assert main(["fetch", "epss", "--from-report", str(TRIVY), "--out", str(tmp_path / "e")]) == 2
