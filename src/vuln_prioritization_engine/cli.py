"""Command line: `vpe report` (offline) and `vpe fetch` (optional live downloads)."""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence
from datetime import UTC, date, datetime
from pathlib import Path

from . import __version__
from .engine import enrich, normalize
from .errors import FetchError, InputError
from .feeds import CVE, load_epss, load_kev
from .fetch import Client, fetch_epss, fetch_kev, fetch_osv_records, osv_ids_for
from .inputs import read_input
from .jsonio import atomic_write, dump_json, load_json
from .osvdb import load_database
from .purl import Package
from .report import SORTS, to_json, to_text

EXIT_OK, EXIT_INPUT, EXIT_FETCH = 0, 2, 3


def _parser() -> argparse.ArgumentParser:
    """Argument definitions."""
    ap = argparse.ArgumentParser(prog="vpe", description=__doc__)
    ap.add_argument("--version", action="version", version=f"vpe {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    rp = sub.add_parser("report", help="normalize scans and SBOMs, add OSV details, EPSS and KEV")
    rp.add_argument("inputs", nargs="+", type=Path, help="scanner JSON reports and SBOMs")
    rp.add_argument("--osv-db", type=Path, help="folder of OSV JSON records or an osv.dev zip")
    rp.add_argument("--epss", type=Path, help="EPSS file (FIRST API JSON or daily CSV[.gz])")
    rp.add_argument("--kev", type=Path, help="CISA KEV JSON catalog")
    rp.add_argument("--json", type=Path, dest="json_out", help="write the JSON report here")
    rp.add_argument("--sort", choices=SORTS, default="id", help="display order")
    rp.add_argument(
        "--as-of", help="report date YYYY-MM-DD for feed-age checks (default: today, UTC)"
    )
    rp.add_argument("--max-feed-age", type=int, default=7, help="warn when a feed is older (days)")

    fp = sub.add_parser("fetch", help="optional live download of KEV, EPSS or OSV records")
    fsub = fp.add_subparsers(dest="feed", required=True)
    for name in ("kev", "epss", "osv"):
        p = fsub.add_parser(name)
        p.add_argument("--timeout", type=float, default=30.0, help="seconds per attempt")
        p.add_argument("--retries", type=int, default=2, help="retries on network errors, 429, 5xx")
        if name == "osv":
            p.add_argument("--out-dir", type=Path, required=True)
            p.add_argument(
                "--id", action="append", default=[], help="OSV record id to fetch (repeatable)"
            )
            p.add_argument(
                "--packages-from",
                type=Path,
                action="append",
                default=[],
                help="SBOM or scanner report whose packages are queried",
            )
        else:
            p.add_argument("--out", type=Path, required=True)
        if name == "epss":
            p.add_argument("--cve", action="append", default=[], help="CVE id (repeatable)")
            p.add_argument("--from-report", type=Path, help="take the CVEs of a vpe JSON report")
    return ap


def _report(args: argparse.Namespace) -> int:
    """Run `vpe report`."""
    started = time.perf_counter()
    as_of = date.fromisoformat(args.as_of) if args.as_of else datetime.now(UTC).date()
    if not 0 <= args.max_feed_age <= 3650:
        raise InputError("--max-feed-age must be in 0..3650")
    parsed = [read_input(p) for p in args.inputs]
    db = load_database(args.osv_db) if args.osv_db else None
    epss = load_epss(args.epss) if args.epss else None
    kev = load_kev(args.kev) if args.kev else None
    res = normalize(parsed, db)
    enrich(res, epss, kev, as_of, args.max_feed_age)
    sys.stdout.write(to_text(res, args.sort))
    if args.json_out:
        doc = to_json(res, parsed, db, epss, kev, datetime.now(UTC), args.sort)
        atomic_write(args.json_out, dump_json(doc))
    elapsed = time.perf_counter() - started
    sys.stderr.write(f"done in {elapsed:.2f} s\n")
    return EXIT_OK


def _report_cves(path: Path) -> list[str]:
    """CVE ids listed in a vpe JSON report."""
    doc = load_json(path)
    if not isinstance(doc, dict) or doc.get("tool") != "vuln-prioritization-engine":
        raise InputError(f"{path}: not a vpe JSON report")
    out: list[str] = []
    for f in doc.get("findings", []):
        if isinstance(f, dict):
            out += [c for c in f.get("cves", []) if isinstance(c, str) and CVE.fullmatch(c)]
    return out


def _fetch(args: argparse.Namespace) -> int:
    """Run `vpe fetch kev|epss|osv`."""
    client = Client(timeout=args.timeout, retries=args.retries)
    if args.feed == "kev":
        n = fetch_kev(client, args.out)
        print(f"KEV: {n} entries written to {args.out}")
    elif args.feed == "epss":
        cves = list(args.cve) + (_report_cves(args.from_report) if args.from_report else [])
        n = fetch_epss(client, cves, args.out)
        print(f"EPSS: {n} scores for {len(set(cves))} CVEs written to {args.out}")
    else:
        ids = list(args.id)
        pkgs: dict[tuple[str, str, str], Package] = {}
        for path in args.packages_from:
            parsed = read_input(path)
            for c in parsed.components:
                pkgs.setdefault(c.package.key(), c.package)
            for o in parsed.observations:
                pkgs.setdefault(o.package.key(), o.package)
        if pkgs:
            ids += osv_ids_for(client, [pkgs[k] for k in sorted(pkgs)])
        if not ids:
            raise InputError("give --id or --packages-from")
        n = fetch_osv_records(client, ids, args.out_dir)
        print(f"OSV: {n} records written to {args.out_dir}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the exit code (0 ok, 2 bad input, 3 download failed)."""
    args = _parser().parse_args(argv)
    try:
        return _report(args) if args.cmd == "report" else _fetch(args)
    except (InputError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_INPUT
    except FetchError as exc:
        sys.stderr.write(f"download failed: {exc}\n")
        return EXIT_FETCH


if __name__ == "__main__":
    raise SystemExit(main())
