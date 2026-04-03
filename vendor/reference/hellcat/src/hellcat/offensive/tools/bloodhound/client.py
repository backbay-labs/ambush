"""BloodHound CE REST API client."""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any
from urllib.error import URLError

import structlog

from hellcat.offensive.tools.bloodhound.models import AttackPath
from hellcat.offensive.tools.bloodhound.parser import BloodHoundParser

logger = structlog.get_logger()


class BloodHoundClient:
    """Client for the BloodHound Community Edition REST API."""

    def __init__(
        self,
        url: str = "",
        api_key: str = "",
        timeout: int = 30,
    ) -> None:
        self._url = (url or os.environ.get("BLOODHOUND_URL", "")).rstrip("/")
        self._api_key = api_key or os.environ.get("BLOODHOUND_API_KEY", "")
        self._timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self._url and self._api_key)

    def get_attack_paths(
        self, source: str = "", target: str = ""
    ) -> list[AttackPath]:
        """Query BloodHound CE for attack paths."""
        endpoint = "/api/v2/graphs/shortest-path"
        params: dict[str, str] = {}
        if source:
            params["source_node"] = source
        if target:
            params["target_node"] = target

        if params:
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            endpoint = f"{endpoint}?{qs}"

        data = self._fetch(endpoint)
        if data is None:
            return []

        paths_data = data.get("data", data.get("paths", []))
        if isinstance(paths_data, list):
            return BloodHoundParser.parse_attack_paths(paths_data)
        return []

    def get_domain_info(self) -> dict[str, Any]:
        """Retrieve domain metadata from BloodHound CE."""
        data = self._fetch("/api/v2/available-domains")
        if data is None:
            return {}
        domains = data.get("data", [])
        if isinstance(domains, list) and domains:
            return BloodHoundParser.parse_domain_info(domains[0])
        return {}

    def _fetch(self, endpoint: str) -> dict[str, Any] | None:
        """HTTP GET with API key header."""
        if not self.is_configured:
            logger.warning("bloodhound.not_configured")
            return None

        url = f"{self._url}{endpoint}"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self._api_key}")
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = resp.read().decode()
                return json.loads(body)
        except (URLError, json.JSONDecodeError, OSError) as exc:
            logger.warning("bloodhound.fetch_failed", endpoint=endpoint, error=str(exc))
            return None
