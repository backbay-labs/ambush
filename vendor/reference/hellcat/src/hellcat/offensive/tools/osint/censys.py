"""Censys Search API client for passive host/certificate intelligence."""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CensysHostResult:
    """Result from a Censys host search."""

    ip: str
    services: list[dict[str, Any]] = field(default_factory=list)
    location: dict[str, Any] = field(default_factory=dict)
    autonomous_system: dict[str, Any] = field(default_factory=dict)
    operating_system: str = ""


class CensysClient:
    """Censys Search API client for passive exposure intelligence.

    Uses CENSYS_API_ID + CENSYS_API_SECRET environment variables.
    """

    BASE_URL = "https://search.censys.io/api"
    source_name = "censys"
    requires_api_key = True

    def __init__(
        self,
        api_id: str | None = None,
        api_secret: str | None = None,
        timeout: int = 30,
    ) -> None:
        self._api_id = api_id or os.environ.get("CENSYS_API_ID", "")
        self._api_secret = api_secret or os.environ.get("CENSYS_API_SECRET", "")
        self._timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self._api_id and self._api_secret)

    def search_hosts(self, query: str, per_page: int = 25) -> list[CensysHostResult]:
        """Search for hosts matching a query."""
        if not self.is_configured:
            logger.warning("osint.censys.no_api_credentials")
            return []

        url = f"{self.BASE_URL}/v2/hosts/search?q={query}&per_page={per_page}"
        data = self._fetch(url)
        if data is None:
            return []

        results: list[CensysHostResult] = []
        for hit in data.get("result", {}).get("hits", []):
            services = []
            for svc in hit.get("services", []):
                services.append({
                    "port": svc.get("port", 0),
                    "service_name": svc.get("service_name", ""),
                    "transport_protocol": svc.get("transport_protocol", "TCP"),
                    "certificate": svc.get("certificate", ""),
                })
            results.append(CensysHostResult(
                ip=hit.get("ip", ""),
                services=services,
                location=hit.get("location", {}),
                autonomous_system=hit.get("autonomous_system", {}),
                operating_system=hit.get(
                    "operating_system", {},
                ).get("product", ""),
            ))
        return results

    def get_host(self, ip: str) -> CensysHostResult | None:
        """Get detailed information about a specific host."""
        if not self.is_configured:
            logger.warning("osint.censys.no_api_credentials")
            return None

        url = f"{self.BASE_URL}/v2/hosts/{ip}"
        data = self._fetch(url)
        if data is None:
            return None

        result = data.get("result", {})
        services = []
        for svc in result.get("services", []):
            services.append({
                "port": svc.get("port", 0),
                "service_name": svc.get("service_name", ""),
                "transport_protocol": svc.get("transport_protocol", "TCP"),
                "banner": svc.get("banner", ""),
                "certificate": svc.get("tls", {}).get(
                    "certificates", {},
                ).get("leaf", {}).get("fingerprint_sha256", ""),
            })
        return CensysHostResult(
            ip=result.get("ip", ip),
            services=services,
            location=result.get("location", {}),
            autonomous_system=result.get("autonomous_system", {}),
            operating_system=result.get(
                "operating_system", {},
            ).get("product", ""),
        )

    def search_certs(
        self, domain: str, per_page: int = 25,
    ) -> list[dict[str, Any]]:
        """Search for certificates matching a domain."""
        if not self.is_configured:
            logger.warning("osint.censys.no_api_credentials")
            return []

        url = (
            f"{self.BASE_URL}/v2/certificates/search"
            f"?q=names:{domain}&per_page={per_page}"
        )
        data = self._fetch(url)
        if data is None:
            return []

        results: list[dict[str, Any]] = []
        for hit in data.get("result", {}).get("hits", []):
            results.append({
                "fingerprint": hit.get("fingerprint_sha256", ""),
                "names": hit.get("names", []),
                "issuer": hit.get("issuer_dn", ""),
                "subject": hit.get("subject_dn", ""),
                "validity_start": hit.get("validity", {}).get("start", ""),
                "validity_end": hit.get("validity", {}).get("end", ""),
            })
        return results

    def _fetch(self, url: str) -> dict[str, Any] | None:
        """Fetch JSON from Censys API with basic auth."""
        try:
            req = urllib.request.Request(url)
            credentials = base64.b64encode(
                f"{self._api_id}:{self._api_secret}".encode(),
            ).decode()
            req.add_header("Authorization", f"Basic {credentials}")
            req.add_header("User-Agent", "Hellcat-OSINT/1.0")
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
        except urllib.error.HTTPError as exc:
            logger.warning("osint.censys.http_error", status=exc.code)
            return None
        except (
            urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError,
        ) as exc:
            logger.warning("osint.censys.request_error", error=str(exc))
            return None
