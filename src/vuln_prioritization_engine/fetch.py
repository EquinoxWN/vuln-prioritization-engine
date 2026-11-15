"""Optional live downloads (CISA KEV, FIRST EPSS API, OSV API) with timeouts and bounded retries."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

from .errors import FetchError, InputError
from .feeds import CVE, parse_epss, parse_kev
from .jsonio import atomic_write, dump_json, parse_json
from .osvdb import check_id, parse_record
from .purl import Package

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
OSV_API = "https://api.osv.dev/v1"
USER_AGENT = (
    "vuln-prioritization-engine/0.1 (+https://github.com/EquinoxWN/vuln-prioritization-engine)"
)
MAX_RESPONSE = 32 * 1024 * 1024
MAX_RETRIES = 5
EPSS_BATCH = 50
OSV_BATCH = 500
OSV_MAX_PAGES = 10


class Response(Protocol):
    """The part of an HTTP response the fetcher reads."""

    status: int

    def read(self, n: int = -1) -> bytes:
        """Read up to n bytes."""
        ...

    def close(self) -> None:
        """Release the connection."""
        ...


Opener = Callable[[urllib.request.Request, float], Response]


def _default_open(req: urllib.request.Request, timeout: float) -> Response:
    """urllib with a timeout (proxy settings come from the standard *_PROXY variables)."""
    resp: Response = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 - https only, checked
    return resp


class Client:
    """HTTPS GET/POST with a per-attempt timeout, bounded retries, backoff and a size cap."""

    def __init__(
        self,
        timeout: float = 30.0,
        retries: int = 2,
        backoff: float = 1.0,
        max_bytes: int = MAX_RESPONSE,
        opener: Opener | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not 0 < timeout <= 300:
            raise InputError("timeout must be in (0, 300] seconds")
        if not 0 <= retries <= MAX_RETRIES:
            raise InputError(f"retries must be in 0..{MAX_RETRIES}")
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.max_bytes = max_bytes
        self.opener = opener or _default_open
        self.sleep = sleep

    def request(self, url: str, body: Any = None) -> bytes:
        """Fetch a URL, retrying network errors, 429 and 5xx; other errors fail at once."""
        if not url.startswith("https://"):
            raise InputError(f"only https URLs are fetched: {url[:80]!r}")
        data = None if body is None else json.dumps(body).encode()
        last = ""
        for attempt in range(self.retries + 1):
            if attempt:
                self.sleep(self.backoff * 2 ** (attempt - 1))
            req = urllib.request.Request(  # noqa: S310 - scheme checked above
                url,
                data=data,
                method="GET" if data is None else "POST",
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
                | ({} if data is None else {"Content-Type": "application/json"}),
            )
            try:
                resp = self.opener(req, self.timeout)
                try:
                    return self._read(resp, url)
                finally:
                    resp.close()
            except urllib.error.HTTPError as exc:
                if exc.code != 429 and exc.code < 500:
                    raise FetchError(f"{url}: HTTP {exc.code}") from exc
                last = f"HTTP {exc.code}"
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
        raise FetchError(f"{url}: gave up after {self.retries + 1} attempts ({last})")

    def _read(self, resp: Response, url: str) -> bytes:
        """Read the body in chunks, refusing more than max_bytes."""
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = resp.read(64 * 1024)
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > self.max_bytes:
                raise FetchError(f"{url}: response is over {self.max_bytes} bytes")
            chunks.append(chunk)


def fetch_kev(client: Client, out: Path, url: str = KEV_URL) -> int:
    """Download the KEV catalog, validate it, write it atomically; returns the entry count."""
    raw = client.request(url)
    feed = parse_kev(parse_json(raw, url), url)
    atomic_write(out, raw)
    return len(feed.entries)


def fetch_epss(client: Client, cves: Iterable[str], out: Path) -> int:
    """Query the FIRST EPSS API for CVEs in batches; write one API-shaped JSON file."""
    wanted = sorted(set(cves))
    for c in wanted:
        if not CVE.fullmatch(c):
            raise InputError(f"invalid CVE id {c[:40]!r}")
    if not wanted:
        raise InputError("no CVE ids to look up")
    rows: list[Any] = []
    for i in range(0, len(wanted), EPSS_BATCH):
        batch = wanted[i : i + EPSS_BATCH]
        url = f"{EPSS_API}?cve={quote(','.join(batch), safe=',')}&limit={EPSS_BATCH}"
        data = parse_json(client.request(url), url)
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            raise FetchError(f"{url}: unexpected EPSS API response")
        rows += data["data"]
    doc = {
        "source": EPSS_API,
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "requested": wanted,
        "data": sorted(rows, key=lambda r: str(r.get("cve")) if isinstance(r, dict) else ""),
    }

    parse_epss(doc, EPSS_API)
    atomic_write(out, dump_json(doc))
    return len(rows)


def osv_ids_for(client: Client, packages: Sequence[Package]) -> list[str]:
    """Ask the OSV querybatch API which vulnerability ids affect each package version."""
    ids: set[str] = set()
    for i in range(0, len(packages), OSV_BATCH):
        batch = packages[i : i + OSV_BATCH]
        queries: list[dict[str, Any]] = [
            {"package": {"ecosystem": p.ecosystem, "name": p.name}, "version": p.version}
            for p in batch
        ]
        for _page in range(OSV_MAX_PAGES):
            data = parse_json(client.request(f"{OSV_API}/querybatch", {"queries": queries}), "osv")
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list) or len(results) != len(queries):
                raise FetchError("OSV querybatch: unexpected response shape")
            follow: list[dict[str, Any]] = []
            for q, r in zip(queries, results, strict=True):
                r = r if isinstance(r, dict) else {}
                for v in r.get("vulns", []) or []:
                    ids.add(check_id(v.get("id") if isinstance(v, dict) else None, "OSV API"))
                token = r.get("next_page_token")
                if isinstance(token, str) and token:
                    follow.append(q | {"page_token": token})
            if not follow:
                break
            queries = follow
        else:
            raise FetchError(f"OSV querybatch: more than {OSV_MAX_PAGES} pages")
    return sorted(ids)


def fetch_osv_records(client: Client, ids: Iterable[str], out_dir: Path) -> int:
    """Download OSV records by id into out_dir/<id>.json (validated, atomic, re-runnable)."""
    n = 0
    for vid in sorted(set(ids)):
        check_id(vid, "id")
        url = f"{OSV_API}/vulns/{quote(vid, safe='')}"
        raw = client.request(url)
        rec = parse_record(parse_json(raw, url), url)
        if rec.id != vid:
            raise FetchError(f"{url}: returned record {rec.id}")
        atomic_write(out_dir / f"{vid}.json", raw)
        n += 1
    return n
