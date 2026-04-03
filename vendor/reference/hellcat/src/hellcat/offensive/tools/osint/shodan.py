"""Shodan API client for passive host/service intelligence."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ShodanHostResult:
    """Result from a Shodan host lookup."""

    ip: str
    hostnames: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    os_guess: str = ""
    org: str = ""
    isp: str = ""
    vulns: list[str] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)


class ShodanClient:
    """Shodan API client for passive exposure intelligence.

    Uses SHODAN_API_KEY environment variable for authentication.
    No API key = graceful degradation (returns empty results).
    """

    BASE_URL = "https://api.shodan.io"
    source_name = "shodan"
    requires_api_key = True

    def __init__(self, api_key: str | None = None, timeout: int = 30) -> None:
        self._api_key = api_key or os.environ.get("SHODAN_API_KEY", "")
        self._timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)

    def search_host(self, ip: str) -> ShodanHostResult | None:
        """Look up a single host by IP address."""
        if not self.is_configured:
            logger.warning("osint.shodan.no_api_key")
            return None

        url = f"{self.BASE_URL}/shodan/host/{ip}?key={self._api_key}"
        data = self._fetch(url)
        if data is None:
            return None

        return ShodanHostResult(
            ip=data.get("ip_str", ip),
            hostnames=data.get("hostnames", []),
            ports=data.get("ports", []),
            os_guess=data.get("os", "") or "",
            org=data.get("org", "") or "",
            isp=data.get("isp", "") or "",
            vulns=data.get("vulns", []),
            services=[
                {
                    "port": svc.get("port", 0),
                    "transport": svc.get("transport", "tcp"),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "banner": svc.get("data", "")[:500],
                    "cpe": svc.get("cpe", []),
                }
                for svc in data.get("data", [])
            ],
        )

    def search_domain(self, domain: str) -> list[dict[str, Any]]:
        """Search Shodan for hosts matching a domain."""
        if not self.is_configured:
            logger.warning("osint.shodan.no_api_key")
            return []

        url = f"{self.BASE_URL}/dns/domain/{domain}?key={self._api_key}"
        data = self._fetch(url)
        if data is None:
            return []

        results: list[dict[str, Any]] = []
        for record in data.get("data", []):
            results.append({
                "subdomain": record.get("subdomain", ""),
                "type": record.get("type", ""),
                "value": record.get("value", ""),
            })
        return results

    def _fetch(self, url: str) -> dict[str, Any] | None:
        """Fetch JSON from Shodan API."""
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Hellcat-OSINT/1.0")
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
        except urllib.error.HTTPError as exc:
            logger.warning("osint.shodan.http_error", status=exc.code)
            return None
        except (
            urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError,
        ) as exc:
            logger.warning("osint.shodan.request_error", error=str(exc))
            return None
