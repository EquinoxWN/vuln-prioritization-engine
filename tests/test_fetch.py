"""Live-download client with a fake opener: timeouts, bounded retries, size caps, atomic writes."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from helpers import KEV, OSV_DIR

from vuln_prioritization_engine.errors import FetchError, InputError
from vuln_prioritization_engine.feeds import load_epss
from vuln_prioritization_engine.fetch import (
    Client,
    fetch_epss,
    fetch_kev,
    fetch_osv_records,
    osv_ids_for,
)
from vuln_prioritization_engine.purl import make_package


class FakeResponse(io.BytesIO):
    status = 200


class FakeOpener:
    """Replays queued outcomes (bytes or exceptions) and records each request."""

    def __init__(self, *outcomes: Any) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[urllib.request.Request, float]] = []

    def __call__(self, req: urllib.request.Request, timeout: float) -> FakeResponse:
        self.calls.append((req, timeout))
        out = self.outcomes.pop(0)
        if isinstance(out, BaseException):
            raise out
        return FakeResponse(out)


def _http(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x", code, "err", {}, None)  # type: ignore[arg-type]


def _client(opener: FakeOpener, sleeps: list[float], **kw: Any) -> Client:
    return Client(opener=opener, sleep=sleeps.append, **kw)


def test_retries_transient_failures_with_backoff_then_succeeds() -> None:
    sleeps: list[float] = []
    op = FakeOpener(urllib.error.URLError("dns"), _http(503), TimeoutError(), b"ok")
    assert _client(op, sleeps, retries=3, timeout=5).request("https://x/y") == b"ok"
    assert sleeps == [1.0, 2.0, 4.0]
    assert all(t == 5 for _, t in op.calls)
    assert op.calls[0][0].get_header("User-agent", "").startswith("vuln-prioritization-engine")


def test_gives_up_after_bounded_attempts() -> None:
    sleeps: list[float] = []
    op = FakeOpener(*[_http(429)] * 3)
    with pytest.raises(FetchError, match="gave up after 3 attempts"):
        _client(op, sleeps, retries=2).request("https://x")
    assert len(op.calls) == 3


def test_client_errors_are_not_retried() -> None:
    op = FakeOpener(_http(404))
    with pytest.raises(FetchError, match="HTTP 404"):
        _client(op, []).request("https://x")
    assert len(op.calls) == 1


def test_size_cap_https_only_and_parameter_bounds() -> None:
    with pytest.raises(FetchError, match="over 10 bytes"):
        _client(FakeOpener(b"x" * 11), [], max_bytes=10).request("https://x")
    with pytest.raises(InputError, match="https"):
        _client(FakeOpener(), []).request("http://x")
    with pytest.raises(InputError):
        Client(timeout=0)
    with pytest.raises(InputError):
        Client(retries=6)


def test_fetch_kev_validates_before_writing(tmp_path: Path) -> None:
    out = tmp_path / "kev.json"
    assert fetch_kev(_client(FakeOpener(KEV.read_bytes()), []), out) == 8
    assert out.read_bytes() == KEV.read_bytes()
    truncated = json.loads(KEV.read_text(encoding="utf-8"))
    truncated["vulnerabilities"].pop()
    with pytest.raises(InputError, match="truncated"):
        fetch_kev(_client(FakeOpener(json.dumps(truncated).encode()), []), tmp_path / "bad.json")
    assert not (tmp_path / "bad.json").exists()
    assert [p.name for p in tmp_path.iterdir()] == ["kev.json"]  # no temp files left


def test_fetch_epss_batches_and_writes_a_loadable_file(tmp_path: Path) -> None:
    cves = [f"CVE-2020-{i:04d}" for i in range(60)]

    def page(n: int) -> bytes:
        rows = [{"cve": c, "epss": "0.1", "percentile": "0.5", "date": "2026-11-13"} for c in cves[n:n + 50]]  # fmt: skip
        return json.dumps({"status": "OK", "data": rows}).encode()

    op = FakeOpener(page(0), page(50))
    out = tmp_path / "e.json"
    assert fetch_epss(_client(op, []), cves + cves[:3], out) == 60
    assert len(op.calls) == 2
    assert "cve=CVE-2020-0000,CVE-2020-0001" in op.calls[0][0].full_url
    assert len(load_epss(out).scores) == 60
    with pytest.raises(InputError):
        fetch_epss(_client(FakeOpener(), []), ["CVE-2020-0001&x=1"], out)
    with pytest.raises(InputError):
        fetch_epss(_client(FakeOpener(), []), [], out)


def test_osv_querybatch_follows_bounded_pages() -> None:
    pkgs = [make_package("PyPI", "a", "1.0"), make_package("npm", "b", "1.0.0")]
    first = {"results": [{"vulns": [{"id": "GHSA-a"}], "next_page_token": "t1"}, {}]}
    second = {"results": [{"vulns": [{"id": "PYSEC-1"}]}]}
    op = FakeOpener(json.dumps(first).encode(), json.dumps(second).encode())
    assert osv_ids_for(_client(op, []), pkgs) == ["GHSA-a", "PYSEC-1"]
    sent = json.loads(op.calls[1][0].data)  # type: ignore[arg-type]
    assert sent["queries"][0]["page_token"] == "t1"  # noqa: S105 - a paging token, not a secret
    endless = json.dumps({"results": [{"next_page_token": "t"}]}).encode()
    with pytest.raises(FetchError, match="pages"):
        osv_ids_for(_client(FakeOpener(*[endless] * 10), []), pkgs[:1])
    with pytest.raises(FetchError, match="shape"):
        osv_ids_for(_client(FakeOpener(b'{"results": []}'), []), pkgs[:1])


def test_fetch_osv_records_checks_ids_and_is_rerunnable(tmp_path: Path) -> None:
    body = (OSV_DIR / "GHSA-jfh8-c2jp-5v3q.json").read_bytes()
    for _ in range(2):
        assert (
            fetch_osv_records(_client(FakeOpener(body), []), ["GHSA-jfh8-c2jp-5v3q"], tmp_path) == 1
        )
    assert [p.name for p in tmp_path.iterdir()] == ["GHSA-jfh8-c2jp-5v3q.json"]
    with pytest.raises(FetchError, match="returned record"):
        fetch_osv_records(_client(FakeOpener(body), []), ["GHSA-aaaa-bbbb-cccc"], tmp_path)
    with pytest.raises(InputError):
        fetch_osv_records(_client(FakeOpener(), []), ["../../etc"], tmp_path)
