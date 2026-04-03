"""
CvemapClient - Wrapper for ProjectDiscovery's cvemap CLI.

Provides structured CVE intelligence via the cvemap binary, parsing
JSON output into typed dataclasses for downstream enrichment.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

import structlog

logger = structlog.get_logger()


@dataclass
class CvemapEntry:
    """A single CVE record from cvemap output."""

    cve_id: str
    severity: str = ""
    cvss: float = 0.0
    epss: float = 0.0
    is_kev: bool = False
    product: str = ""
    vendor: str = ""
    description: str = ""


class CvemapClient:
    """Query CVE intelligence via the cvemap CLI tool."""

    def __init__(self, binary: str = "cvemap") -> None:
        self._binary = binary

    def is_available(self) -> bool:
        """Check whether the cvemap binary is on PATH."""
        return shutil.which(self._binary) is not None

    def search_cve(self, cve_id: str, timeout: int = 30) -> CvemapEntry | None:
        """Look up a single CVE by ID.

        Returns:
            CvemapEntry if found, None otherwise.
        """
        logger.debug("osint.cvemap.search_cve", cve_id=cve_id)
        output = self._run([self._binary, "-id", cve_id, "-json"], timeout=timeout)
        if output is None:
            return None
        entries = self.parse(output)
        return entries[0] if entries else None

    def search_product(
        self, product: str, limit: int = 20, timeout: int = 60,
    ) -> list[CvemapEntry]:
        """Search CVEs affecting a product.

        Returns:
            List of CvemapEntry items.
        """
        logger.debug("osint.cvemap.search_product", product=product, limit=limit)
        output = self._run(
            [self._binary, "-product", product, "-json", "-limit", str(limit)],
            timeout=timeout,
        )
        if output is None:
            return []
        return self.parse(output)

    @staticmethod
    def parse(output: str) -> list[CvemapEntry]:
        """Parse cvemap JSON-lines output into CvemapEntry list."""
        entries: list[CvemapEntry] = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            entries.append(CvemapEntry(
                cve_id=obj.get("cve_id", obj.get("cve-id", "")),
                severity=obj.get("severity", ""),
                cvss=float(obj.get("cvss_score", obj.get("cvss", 0.0)) or 0.0),
                epss=float(obj.get("epss", obj.get("epss_score", 0.0)) or 0.0),
                is_kev=bool(obj.get("is_kev", obj.get("kev", False))),
                product=obj.get("product", ""),
                vendor=obj.get("vendor", ""),
                description=obj.get("description", ""),
            ))
        return entries

    def _run(self, cmd: list[str], timeout: int) -> str | None:
        """Execute a cvemap command and return stdout, or None on failure."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            logger.warning("osint.cvemap.not_found", binary=self._binary)
            return None
        except subprocess.TimeoutExpired:
            logger.warning("osint.cvemap.timeout", cmd=cmd, timeout=timeout)
            return None

        if result.returncode != 0:
            logger.warning(
                "osint.cvemap.error",
                cmd=cmd,
                returncode=result.returncode,
                stderr=result.stderr[:500] if result.stderr else "",
            )
            return None

        return result.stdout
