.PHONY: setup lint test demo bench audit fetch-live ci

PY ?= python
REPORT = vpe report tests/fixtures/scans/osv-scanner.json tests/fixtures/scans/trivy.json \
	tests/fixtures/scans/grype.json tests/fixtures/sbom/shop-api.cdx.json \
	tests/fixtures/sbom/billing-worker.spdx.json --osv-db tests/fixtures/osv \
	--epss tests/fixtures/feeds/epss-2026-11-13.json \
	--kev tests/fixtures/feeds/kev-2026.11.13-subset.json --as-of 2026-11-14

setup:
	$(PY) -m pip install --upgrade pip && $(PY) -m pip install -e ".[dev]"

# ruff, ruff format and mypy --strict.
lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check . && $(PY) -m mypy

# Unit, property, fixture and end-to-end tests; no network.
test:
	$(PY) -m pytest -q -rs

# Offline report on the shipped scanner reports, SBOMs and dated feed snapshots.
demo:
	$(REPORT) --sort epss --json .tmp/demo-report.json

bench:
	@echo "M3: backtest of later-exploited CVEs ranked in the top 10% against CVSS-only ranking"

# Known vulnerabilities in the installed Python dependencies.
audit:
	$(PY) -m pip_audit --skip-editable --cache-dir .tmp/pip-audit

# Optional live downloads (network, timeouts, bounded retries) into .tmp/, never into the fixtures.
fetch-live:
	vpe fetch kev --out .tmp/live/kev.json
	vpe fetch osv --packages-from tests/fixtures/sbom/shop-api.cdx.json --out-dir .tmp/live/osv
	$(REPORT) --json .tmp/live/report.json > /dev/null
	vpe fetch epss --from-report .tmp/live/report.json --out .tmp/live/epss.json

ci: setup lint test
