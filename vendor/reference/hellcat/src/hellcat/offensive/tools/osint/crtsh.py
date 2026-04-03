"""CrtshClient - Certificate Transparency log search via crt.sh."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

import structlog

from hellcat.offensive.tools.osint.base import OsintFinding

logger = structlog.get_logger()


class CrtshClient:
    """Query crt.sh Certificate Transparency logs for subdomain discovery."""

    BASE_URL = "https://crt.sh"
    source_name = "crtsh"
    requires_api_key = False

    def __init__(self, timeout: int = 30) -> None:
        self._timeout = timeout

    def query(self, target: str, **kwargs: Any) -> list[OsintFinding]:
        """Query crt.sh for certificates matching the target domain.

        Args:
            target: Domain to search (e.g. "example.com").
            include_expired: Whether to include expired certs (default False).

        Returns:
            List of OsintFinding items for each unique subdomain discovered.
        """
        include_expired = kwargs.get("include_expired", False)

        url = f"{self.BASE_URL}/?q=%25.{target}&output=json"
        if not include_expired:
            url += "&exclude=expired"

        logger.debug("osint.crtsh.query", target=target, url=url)

        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Hellcat-OSINT/1.0")
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            logger.warning(
                "osint.crtsh.http_error",
                target=target,
                status=exc.code,
            )
            return []
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            logger.warning(
                "osint.crtsh.request_error",
                target=target,
                error=str(exc),
            )
            return []

        try:
            records = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning(
                "osint.crtsh.json_error",
                target=target,
                error=str(exc),
                raw_len=len(raw),
            )
            return []

        if not isinstance(records, list):
            logger.warning("osint.crtsh.unexpected_response", target=target)
            return []

        return self._extract_findings(target, records)

    def _extract_findings(
        self, target: str, records: list[dict[str, Any]],
    ) -> list[OsintFinding]:
        """Extract unique subdomains from crt.sh certificate records."""
        seen: set[str] = set()
        findings: list[OsintFinding] = []

        for record in records:
            name_value = record.get("name_value", "")
            common_name = record.get("common_name", "")
            issuer = record.get("issuer_name", "")
            not_after = record.get("not_after", "")

            # name_value can contain newline-separated names
            names = set()
            for raw_name in name_value.split("\n"):
                name = raw_name.strip().lower()
                if name:
                    names.add(name)
            if common_name:
                names.add(common_name.strip().lower())

            for name in names:
                if name in seen:
                    continue
                seen.add(name)

                is_wildcard = name.startswith("*.")
                clean_name = name.lstrip("*.")

                # Skip names that don't belong to the target domain
                if not clean_name.endswith(target.lower()) and clean_name != target.lower():
                    continue

                finding_type = "subdomain"
                metadata: dict[str, Any] = {
                    "issuer": issuer,
                    "not_after": not_after,
                }
                if is_wildcard:
                    metadata["wildcard"] = True
                    metadata["original"] = name

                findings.append(OsintFinding(
                    source=self.source_name,
                    finding_type=finding_type,
                    value=clean_name,
                    confidence=0.9 if is_wildcard else 1.0,
                    metadata=metadata,
                ))

        logger.info(
            "osint.crtsh.results",
            target=target,
            records_parsed=len(records),
            unique_subdomains=len(findings),
        )
        return findings
