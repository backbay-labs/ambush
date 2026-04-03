"""
KevClient - CISA Known Exploited Vulnerabilities catalog client.

Fetches the CISA KEV JSON feed and provides lookup utilities for
determining if a CVE is actively exploited in the wild. No API key required.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

import structlog

logger = structlog.get_logger()

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


@dataclass
class KevEntry:
    """A single entry from the CISA KEV catalog."""

    cve_id: str
    date_added: str = ""
    due_date: str = ""
    vendor: str = ""
    product: str = ""
    vulnerability_name: str = ""
    short_description: str = ""
    required_action: str = ""


class KevClient:
    """Query the CISA Known Exploited Vulnerabilities catalog."""

    source_name = "kev"
    requires_api_key = False

    def fetch_catalog(self, timeout: int = 30) -> list[KevEntry]:
        """Fetch and parse the full KEV JSON feed.

        Returns:
            List of KevEntry items, or empty list on error.
        """
        logger.debug("osint.kev.fetch", url=KEV_FEED_URL)

        try:
            req = urllib.request.Request(KEV_FEED_URL)
            req.add_header("User-Agent", "Hellcat-OSINT/1.0")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            logger.warning("osint.kev.http_error", status=exc.code)
            return []
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            logger.warning("osint.kev.request_error", error=str(exc))
            return []

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("osint.kev.json_error", error=str(exc))
            return []

        vulns = data.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            logger.warning("osint.kev.unexpected_response")
            return []

        entries = [
            KevEntry(
                cve_id=v.get("cveID", ""),
                date_added=v.get("dateAdded", ""),
                due_date=v.get("dueDate", ""),
                vendor=v.get("vendorProject", ""),
                product=v.get("product", ""),
                vulnerability_name=v.get("vulnerabilityName", ""),
                short_description=v.get("shortDescription", ""),
                required_action=v.get("requiredAction", ""),
            )
            for v in vulns
            if v.get("cveID")
        ]

        logger.info("osint.kev.fetched", count=len(entries))
        return entries

    @staticmethod
    def is_kev(cve_id: str, catalog: list[KevEntry]) -> bool:
        """Check whether a CVE ID appears in the given KEV catalog."""
        return any(e.cve_id == cve_id for e in catalog)
