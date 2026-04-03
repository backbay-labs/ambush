"""
EPSSClient - FIRST EPSS (Exploit Prediction Scoring System) API client.

Fetches exploit probability scores from the FIRST EPSS API.
Supports single CVE lookup, bulk lookup, and daily feed refresh.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog

logger = structlog.get_logger()

EPSS_BASE_URL = "https://api.first.org/data/v1/epss"


@dataclass
class EPSSRecord:
    """A single EPSS score record."""

    cve_id: str
    epss_score: float       # 0.0-1.0 probability of exploitation
    percentile: float        # 0.0-1.0 percentile rank
    fetched_at: str          # ISO timestamp
    source: str = "first.org/epss"


class EPSSClient:
    """Client for FIRST EPSS API (https://api.first.org/data/v1/epss)."""

    BASE_URL = EPSS_BASE_URL
    source_name = "epss"
    requires_api_key = False

    def __init__(self, timeout: int = 30) -> None:
        self._timeout = timeout
        self._cache: dict[str, EPSSRecord] = {}

    def lookup(self, cve_id: str) -> EPSSRecord | None:
        """Point lookup for a single CVE."""
        if cve_id in self._cache:
            return self._cache[cve_id]

        params = urllib.parse.urlencode({"cve": cve_id})
        url = f"{self.BASE_URL}?{params}"

        logger.debug("osint.epss.lookup", cve_id=cve_id)

        data = self._fetch(url)
        if data is None:
            return None

        records = self._parse_response(data)
        for rec in records:
            self._cache[rec.cve_id] = rec

        return self._cache.get(cve_id)

    def bulk_lookup(self, cve_ids: list[str]) -> list[EPSSRecord]:
        """Batch lookup for multiple CVEs."""
        if not cve_ids:
            return []

        # Check cache first
        uncached = [c for c in cve_ids if c not in self._cache]
        if uncached:
            cve_param = ",".join(uncached)
            params = urllib.parse.urlencode({"cve": cve_param})
            url = f"{self.BASE_URL}?{params}"

            logger.debug("osint.epss.bulk_lookup", count=len(uncached))

            data = self._fetch(url)
            if data is not None:
                records = self._parse_response(data)
                for rec in records:
                    self._cache[rec.cve_id] = rec

        return [self._cache[c] for c in cve_ids if c in self._cache]

    def fetch_daily(self) -> list[EPSSRecord]:
        """Bulk daily refresh of all EPSS scores (first page)."""
        logger.debug("osint.epss.fetch_daily")

        data = self._fetch(self.BASE_URL)
        if data is None:
            return []

        records = self._parse_response(data)
        for rec in records:
            self._cache[rec.cve_id] = rec

        logger.info("osint.epss.daily_fetched", count=len(records))
        return records

    def get_cached(self, cve_id: str) -> EPSSRecord | None:
        """Return cached record without network call."""
        return self._cache.get(cve_id)

    def _fetch(self, url: str) -> dict | None:
        """Fetch JSON from the EPSS API."""
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Hellcat-OSINT/1.0")
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            logger.warning("osint.epss.http_error", status=exc.code)
            return None
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            logger.warning("osint.epss.request_error", error=str(exc))
            return None

        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("osint.epss.json_error", error=str(exc))
            return None

    @staticmethod
    def _parse_response(data: dict) -> list[EPSSRecord]:
        """Parse EPSS API JSON response into EPSSRecord list."""
        if not isinstance(data, dict):
            return []

        status = data.get("status")
        if status != "OK":
            logger.warning("osint.epss.bad_status", status=status)
            return []

        items = data.get("data", [])
        if not isinstance(items, list):
            return []

        now = datetime.now(UTC).isoformat()
        records: list[EPSSRecord] = []
        for item in items:
            cve_id = item.get("cve", "")
            if not cve_id:
                continue
            try:
                epss_score = float(item.get("epss", 0.0))
                percentile = float(item.get("percentile", 0.0))
            except (TypeError, ValueError):
                continue
            records.append(EPSSRecord(
                cve_id=cve_id,
                epss_score=epss_score,
                percentile=percentile,
                fetched_at=now,
            ))

        return records
