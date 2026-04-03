"""
OsintCollector - Orchestrates passive OSINT data collection.

Runs configured OSINT sources against the target, aggregates findings,
and provides methods to ingest results into TargetGraph and VulnKnowledgeBase.
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING

import structlog

from hellcat.offensive.tools.osint.base import OsintResult
from hellcat.offensive.tools.osint.crtsh import CrtshClient
from hellcat.offensive.tools.osint.nvd import NvdClient

if TYPE_CHECKING:
    from hellcat.offensive.knowledge.vuln_db import VulnKnowledgeBase
    from hellcat.offensive.target_graph.graph import TargetGraph

logger = structlog.get_logger()

# Available OSINT source constructors
_SOURCE_REGISTRY: dict[str, type] = {
    "crtsh": CrtshClient,
    "nvd": NvdClient,
}


class OsintCollector:
    """Orchestrates passive OSINT collection from multiple sources."""

    def __init__(
        self,
        sources: list[str] | None = None,
        api_keys: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> None:
        self._enabled = sources or ["crtsh", "nvd"]
        self._api_keys = api_keys or {}
        self._timeout = timeout

    def collect(
        self,
        target_url: str,
        tech_hints: list[str] | None = None,
    ) -> OsintResult:
        """Run all enabled OSINT sources against the target.

        Args:
            target_url: Full target URL (domain will be extracted).
            tech_hints: Optional tech stack keywords for NVD search
                (e.g. ["express", "nginx", "mysql"]).
        """
        domain = self._extract_domain(target_url)
        hints = tech_hints or []
        result = OsintResult(target=domain)

        # Run crt.sh
        if "crtsh" in self._enabled:
            crtsh_result = self._run_crtsh(domain)
            result = result.merge(crtsh_result)

        # Run NVD for each tech hint
        if "nvd" in self._enabled and hints:
            for hint in hints:
                nvd_result = self._run_nvd(hint)
                result = result.merge(nvd_result)

        logger.info(
            "osint.collection_complete",
            target=domain,
            sources=result.sources_queried,
            findings=len(result.findings),
            errors=list(result.errors.keys()),
        )
        return result

    def _run_crtsh(self, domain: str) -> OsintResult:
        """Query crt.sh for subdomain discovery."""
        result = OsintResult(target=domain)
        try:
            client = CrtshClient(timeout=self._timeout)
            findings = client.query(domain)
            result.findings = findings
            result.sources_queried = ["crtsh"]
        except Exception as exc:
            logger.warning(
                "osint.crtsh.error",
                domain=domain,
                error=str(exc),
            )
            result.errors["crtsh"] = str(exc)
            result.sources_queried = ["crtsh"]
        return result

    def _run_nvd(self, keyword: str) -> OsintResult:
        """Query NVD for CVE intelligence on a keyword."""
        result = OsintResult(target=keyword)
        try:
            api_key = self._api_keys.get("nvd", "")
            client = NvdClient(api_key=api_key, timeout=self._timeout)
            findings = client.query(keyword)
            result.findings = findings
            result.sources_queried = ["nvd"]
        except Exception as exc:
            logger.warning(
                "osint.nvd.error",
                keyword=keyword,
                error=str(exc),
            )
            result.errors["nvd"] = str(exc)
            result.sources_queried = ["nvd"]
        return result

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract domain from URL, stripping scheme, port, and path."""
        parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        hostname = parsed.hostname or parsed.path.split("/")[0]
        return hostname

    def ingest_into_graph(
        self,
        result: OsintResult,
        graph: TargetGraph,
    ) -> int:
        """Feed discovered subdomains into TargetGraph as new target nodes.

        Returns count of nodes added.
        """
        subdomains = result.deduplicated_values("subdomain")
        added = 0
        for subdomain in subdomains:
            graph.add_target(
                url=f"https://{subdomain}",
                description="OSINT: discovered via crt.sh",
            )
            added += 1
        return added

    def ingest_into_knowledge_base(
        self,
        result: OsintResult,
        knowledge_db: VulnKnowledgeBase,
    ) -> int:
        """Feed CVE findings into VulnKnowledgeBase.

        Converts OsintFinding(finding_type="cve") into CveEntry objects
        and ingests them.

        Returns count of CVEs ingested.
        """
        from hellcat.offensive.knowledge.vuln_db import CveEntry

        cve_findings = result.findings_by_type("cve")
        ingested = 0
        for finding in cve_findings:
            meta = finding.metadata
            entry = CveEntry(
                cve_id=finding.value,
                description=meta.get("description", ""),
                cvss=meta.get("cvss", 0.0),
                affected_products=meta.get("affected_products", []),
                references=meta.get("references", []),
                vuln_type=meta.get("vuln_type", ""),
                published_date=meta.get("published_date", ""),
            )
            knowledge_db.ingest_cve(entry)
            ingested += 1
        return ingested
