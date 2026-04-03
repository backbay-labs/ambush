"""GoPhishClient - REST API client for GoPhish phishing platform."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

import structlog

from hellcat.offensive.tools.gophish.models import (
    PhishingCampaign,
    PhishingResult,
)

logger = structlog.get_logger()


class GoPhishClient:
    """GoPhish REST API client for phishing campaign management.

    Uses GOPHISH_API_KEY and GOPHISH_URL environment variables.
    """

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        timeout: int = 30,
    ) -> None:
        self._url = (url or os.environ.get("GOPHISH_URL", "")).rstrip("/")
        self._api_key = api_key or os.environ.get("GOPHISH_API_KEY", "")
        self._timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self._url and self._api_key)

    def create_campaign(self, campaign_data: dict[str, Any]) -> PhishingCampaign | None:
        """Create a new phishing campaign."""
        data = self._post("/api/campaigns/", campaign_data)
        if data is None:
            return None
        return PhishingCampaign(
            campaign_id=data.get("id", 0),
            name=data.get("name", ""),
            status=data.get("status", ""),
            created_date=data.get("created_date", ""),
            url=data.get("url", ""),
        )

    def get_campaign_results(self, campaign_id: int) -> PhishingResult | None:
        """Get results for a specific campaign."""
        data = self._fetch(f"/api/campaigns/{campaign_id}/results")
        if data is None:
            return None

        from hellcat.offensive.tools.gophish.parser import GoPhishParser

        return GoPhishParser.parse_campaign_results(data)

    def get_raw_campaign_results(
        self, campaign_id: int,
    ) -> dict[str, Any] | None:
        """Get raw JSON results for a campaign (for credential extraction)."""
        return self._fetch(f"/api/campaigns/{campaign_id}/results")

    def get_campaigns(self) -> list[PhishingCampaign]:
        """List all campaigns."""
        data = self._fetch("/api/campaigns/")
        if data is None:
            return []

        campaigns: list[PhishingCampaign] = []
        items = data if isinstance(data, list) else []
        for item in items:
            campaigns.append(PhishingCampaign(
                campaign_id=item.get("id", 0),
                name=item.get("name", ""),
                status=item.get("status", ""),
                created_date=item.get("created_date", ""),
                completed_date=item.get("completed_date", ""),
            ))
        return campaigns

    def create_template(self, template_data: dict[str, Any]) -> dict[str, Any] | None:
        """Create a phishing email template."""
        return self._post("/api/templates/", template_data)

    def create_landing_page(self, page_data: dict[str, Any]) -> dict[str, Any] | None:
        """Create a phishing landing page."""
        return self._post("/api/pages/", page_data)

    def create_sending_profile(
        self, profile_data: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Create an SMTP sending profile."""
        return self._post("/api/smtp/", profile_data)

    def import_group(self, group_data: dict[str, Any]) -> dict[str, Any] | None:
        """Import a target group."""
        return self._post("/api/groups/", group_data)

    def _fetch(self, endpoint: str) -> Any:
        """GET request to GoPhish API."""
        if not self.is_configured:
            logger.warning("gophish.not_configured")
            return None

        url = f"{self._url}{endpoint}"
        try:
            req = urllib.request.Request(url)
            req.add_header("Authorization", f"Bearer {self._api_key}")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
        except urllib.error.HTTPError as exc:
            logger.warning("gophish.http_error", endpoint=endpoint, status=exc.code)
            return None
        except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError) as exc:
            logger.warning("gophish.request_error", endpoint=endpoint, error=str(exc))
            return None

    def _post(self, endpoint: str, data: dict[str, Any]) -> Any:
        """POST request to GoPhish API."""
        if not self.is_configured:
            logger.warning("gophish.not_configured")
            return None

        url = f"{self._url}{endpoint}"
        body = json.dumps(data).encode("utf-8")
        try:
            req = urllib.request.Request(url, data=body, method="POST")
            req.add_header("Authorization", f"Bearer {self._api_key}")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
        except urllib.error.HTTPError as exc:
            logger.warning("gophish.http_error", endpoint=endpoint, status=exc.code)
            return None
        except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError) as exc:
            logger.warning("gophish.request_error", endpoint=endpoint, error=str(exc))
            return None
