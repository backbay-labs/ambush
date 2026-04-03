"""
NvdClient - NIST National Vulnerability Database API v2 client.

Queries the NVD REST API for CVE records matching keyword searches.
Supports optional API key for higher rate limits. Returns OsintFinding
items and can convert results directly to CveEntry objects for
VulnKnowledgeBase ingestion.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import structlog

from hellcat.offensive.knowledge.vuln_db import CveEntry
from hellcat.offensive.tools.osint.base import OsintFinding

logger = structlog.get_logger()

# CWE -> vuln_type mapping for classification
_CWE_VULN_TYPE_MAP: dict[str, str] = {
    "CWE-89": "sqli",
    "CWE-79": "xss",
    "CWE-918": "ssrf",
    "CWE-287": "auth_bypass",
    "CWE-639": "idor",
    "CWE-22": "path_traversal",
    "CWE-78": "command_injection",
    "CWE-94": "code_injection",
    "CWE-502": "deserialization",
    "CWE-611": "xxe",
    "CWE-352": "csrf",
    "CWE-862": "missing_authz",
    "CWE-863": "incorrect_authz",
    "CWE-434": "file_upload",
    "CWE-306": "missing_auth",
    "CWE-798": "hardcoded_credentials",
}


class NvdClient:
    """Query NIST NVD API v2 for CVE intelligence."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    source_name = "nvd"
    requires_api_key = False  # optional key for higher rate limits

    def __init__(self, api_key: str = "", timeout: int = 30) -> None:
        self._api_key = api_key
        self._timeout = timeout

    def query(self, target: str, **kwargs: Any) -> list[OsintFinding]:
        """Search NVD for CVEs matching keyword(s).

        Args:
            target: Keyword to search (e.g. "express 4.17", "nginx").
            max_results: Maximum results to return (default 20).

        Returns:
            List of OsintFinding items for each CVE found.
        """
        max_results = kwargs.get("max_results", 20)
        vulns = self._fetch_vulnerabilities(target, max_results)

        findings: list[OsintFinding] = []
        for vuln_wrapper in vulns:
            cve_data = vuln_wrapper.get("cve", {})
            finding = self._parse_cve_finding(cve_data)
            if finding:
                findings.append(finding)

        logger.info(
            "osint.nvd.results",
            target=target,
            cve_count=len(findings),
        )
        return findings

    def query_cve_entries(self, target: str, **kwargs: Any) -> list[CveEntry]:
        """Query NVD and return results as CveEntry objects for VulnKnowledgeBase ingestion."""
        max_results = kwargs.get("max_results", 20)
        vulns = self._fetch_vulnerabilities(target, max_results)

        entries: list[CveEntry] = []
        for vuln_wrapper in vulns:
            cve_data = vuln_wrapper.get("cve", {})
            entry = self._parse_cve_entry(cve_data)
            if entry:
                entries.append(entry)

        return entries

    def fetch_cve_by_id(self, cve_id: str) -> dict[str, Any] | None:
        """Fetch a single CVE record by exact ID (e.g. 'CVE-2024-1234').

        Returns the raw vulnerability wrapper dict, or None if not found.
        """
        params = urllib.parse.urlencode({"cveId": cve_id})
        url = f"{self.BASE_URL}?{params}"

        headers: dict[str, str] = {"User-Agent": "Hellcat-OSINT/1.0"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            vulns = data.get("vulnerabilities", [])
            return vulns[0] if vulns else None
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            OSError,
            TimeoutError,
            json.JSONDecodeError,
            ValueError,
            IndexError,
        ):
            return None

    def _fetch_vulnerabilities(
        self, target: str, max_results: int,
    ) -> list[dict[str, Any]]:
        """Fetch vulnerability records from NVD API via keyword search."""
        params = urllib.parse.urlencode({
            "keywordSearch": target,
            "resultsPerPage": str(min(max_results, 100)),
        })
        url = f"{self.BASE_URL}?{params}"

        logger.debug("osint.nvd.fetch", target=target, url=url)

        headers: dict[str, str] = {
            "User-Agent": "Hellcat-OSINT/1.0",
        }
        if self._api_key:
            headers["apiKey"] = self._api_key

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                logger.warning("osint.nvd.rate_limited", target=target)
            else:
                logger.warning(
                    "osint.nvd.http_error",
                    target=target,
                    status=exc.code,
                )
            return []
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            logger.warning(
                "osint.nvd.request_error",
                target=target,
                error=str(exc),
            )
            return []

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning(
                "osint.nvd.json_error",
                target=target,
                error=str(exc),
            )
            return []

        vulns: list[dict[str, Any]] = data.get("vulnerabilities", [])
        total = data.get("totalResults", len(vulns))

        logger.debug(
            "osint.nvd.fetched_page",
            target=target,
            returned=len(vulns),
            total=total,
        )

        # Paginate if needed and there are more results
        if len(vulns) < min(total, max_results):
            vulns = self._paginate(
                target, vulns, total, max_results, headers,
            )

        return vulns[:max_results]

    def _paginate(
        self,
        target: str,
        vulns: list[dict[str, Any]],
        total: int,
        max_results: int,
        headers: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Fetch additional pages from NVD, respecting rate limits."""
        page_size = min(max_results, 100)
        sleep_time = 0.6 if self._api_key else 6.0

        while len(vulns) < min(total, max_results):
            time.sleep(sleep_time)
            start_index = len(vulns)
            params = urllib.parse.urlencode({
                "keywordSearch": target,
                "resultsPerPage": str(page_size),
                "startIndex": str(start_index),
            })
            url = f"{self.BASE_URL}?{params}"

            logger.debug(
                "osint.nvd.paginate",
                target=target,
                start_index=start_index,
            )

            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                data = json.loads(raw)
                page_vulns = data.get("vulnerabilities", [])
                if not page_vulns:
                    break
                vulns.extend(page_vulns)
            except (
                urllib.error.HTTPError,
                urllib.error.URLError,
                OSError,
                TimeoutError,
                json.JSONDecodeError,
                ValueError,
            ) as exc:
                logger.warning(
                    "osint.nvd.pagination_error",
                    target=target,
                    error=str(exc),
                )
                break

        return vulns

    def _parse_cve_finding(self, cve_data: dict[str, Any]) -> OsintFinding | None:
        """Parse a single NVD CVE record into an OsintFinding."""
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None

        description = self._extract_description(cve_data)
        cvss_score = self._extract_cvss(cve_data)
        vuln_type = self._classify_vuln_type(cve_data)
        published = cve_data.get("published", "")

        return OsintFinding(
            source=self.source_name,
            finding_type="cve",
            value=cve_id,
            confidence=1.0,
            metadata={
                "description": description,
                "cvss": cvss_score,
                "vuln_type": vuln_type,
                "published_date": published,
                "affected_products": self._extract_affected_products(cve_data),
            },
        )

    def _parse_cve_entry(self, cve_data: dict[str, Any]) -> CveEntry | None:
        """Parse a single NVD CVE record into a CveEntry for VulnKnowledgeBase."""
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None

        description = self._extract_description(cve_data)
        cvss_score = self._extract_cvss(cve_data)
        vuln_type = self._classify_vuln_type(cve_data)
        published = cve_data.get("published", "")
        affected = self._extract_affected_products(cve_data)
        refs = self._extract_references(cve_data)

        return CveEntry(
            cve_id=cve_id,
            description=description,
            cvss=cvss_score,
            affected_products=affected,
            references=refs,
            vuln_type=vuln_type,
            published_date=published,
        )

    @staticmethod
    def _extract_description(cve_data: dict[str, Any]) -> str:
        """Extract English description from CVE data."""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        if descriptions:
            return descriptions[0].get("value", "")
        return ""

    @staticmethod
    def _extract_cvss(cve_data: dict[str, Any]) -> float:
        """Extract CVSS v3.1 base score, falling back to v3.0 then v2."""
        metrics = cve_data.get("metrics", {})

        # Try CVSS v3.1 first
        v31 = metrics.get("cvssMetricV31", [])
        if v31:
            cvss_data = v31[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            if score:
                return float(score)

        # Fall back to v3.0
        v30 = metrics.get("cvssMetricV30", [])
        if v30:
            cvss_data = v30[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            if score:
                return float(score)

        # Fall back to v2
        v2 = metrics.get("cvssMetricV2", [])
        if v2:
            cvss_data = v2[0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            if score:
                return float(score)

        return 0.0

    @staticmethod
    def extract_cvss_v4(cve_data: dict[str, Any]) -> dict[str, Any]:
        """Extract CVSS v4.0 metrics when present in NVD response.

        Returns dict with cvss_v4_score (float) and cvss_v4_vector (str),
        or empty dict if v4 metrics are not available.
        """
        metrics = cve_data.get("metrics", {})
        v40 = metrics.get("cvssMetricV40", [])
        if not v40:
            return {}
        cvss_data = v40[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        vector = cvss_data.get("vectorString", "")
        if score is None:
            return {}
        return {
            "cvss_v4_score": float(score),
            "cvss_v4_vector": vector,
        }

    @staticmethod
    def _classify_vuln_type(cve_data: dict[str, Any]) -> str:
        """Classify vulnerability type from CWE IDs in the CVE data."""
        weaknesses = cve_data.get("weaknesses", [])
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "")
                if cwe_id in _CWE_VULN_TYPE_MAP:
                    return _CWE_VULN_TYPE_MAP[cwe_id]
        return ""

    @staticmethod
    def _extract_affected_products(cve_data: dict[str, Any]) -> list[str]:
        """Extract CPE match strings as affected product identifiers."""
        products: list[str] = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        products.append(criteria)
        return products

    @staticmethod
    def _extract_references(cve_data: dict[str, Any]) -> list[str]:
        """Extract reference URLs from CVE data."""
        refs: list[str] = []
        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            if url:
                refs.append(url)
        return refs
