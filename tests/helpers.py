"""Shared fixture paths and small builders for the tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent / "fixtures"
OSV_DIR = ROOT / "osv"
SBOM_CDX = ROOT / "sbom" / "shop-api.cdx.json"
SBOM_SPDX = ROOT / "sbom" / "billing-worker.spdx.json"
OSV_SCANNER = ROOT / "scans" / "osv-scanner.json"
TRIVY = ROOT / "scans" / "trivy.json"
GRYPE = ROOT / "scans" / "grype.json"
EPSS = ROOT / "feeds" / "epss-2026-11-13.json"
KEV = ROOT / "feeds" / "kev-2026.11.13-subset.json"
ORACLE = ROOT / "osv-api" / "querybatch-shop-api.json"


def record(
    rid: str = "GHSA-aaaa-bbbb-cccc",
    *,
    aliases: list[str] | None = None,
    ecosystem: str = "PyPI",
    name: str = "demo",
    events: list[dict[str, str]] | None = None,
    versions: list[str] | None = None,
    range_type: str = "ECOSYSTEM",
    vector: str | None = None,
) -> dict[str, Any]:
    """A minimal valid OSV record."""
    rec: dict[str, Any] = {
        "id": rid,
        "aliases": aliases or [],
        "summary": f"summary of {rid}",
        "modified": "2026-01-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": name},
                "ranges": [
                    {
                        "type": range_type,
                        "events": events or [{"introduced": "0"}, {"fixed": "2.0.0"}],
                    }
                ],
                "versions": versions or [],
            }
        ],
    }
    if vector:
        rec["severity"] = [{"type": "CVSS_V3", "score": vector}]
    return rec


def write_json(path: Path, value: Any) -> Path:
    """Write a JSON file for a test and return its path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path
