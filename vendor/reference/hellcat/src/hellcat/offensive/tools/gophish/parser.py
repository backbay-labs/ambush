"""Parser for GoPhish API responses."""
from __future__ import annotations

from typing import Any

from hellcat.offensive.tools.gophish.models import CapturedCredential, PhishingResult


class GoPhishParser:
    """Parse GoPhish API responses into typed models."""

    @staticmethod
    def parse_campaign_results(data: dict[str, Any]) -> PhishingResult:
        """Parse campaign results endpoint response."""
        results = data.get("results", [])

        targets_sent = len(results)
        emails_opened = sum(
            1 for r in results
            if r.get("status") in ("Email Opened", "Clicked Link", "Submitted Data")
        )
        links_clicked = sum(
            1 for r in results
            if r.get("status") in ("Clicked Link", "Submitted Data")
        )
        credentials_captured = sum(
            1 for r in results if r.get("status") == "Submitted Data"
        )
        reported_count = sum(1 for r in results if r.get("reported", False))

        return PhishingResult(
            campaign_name=data.get("name", ""),
            targets_sent=targets_sent,
            emails_opened=emails_opened,
            links_clicked=links_clicked,
            credentials_captured=credentials_captured,
            reported_count=reported_count,
            email_open_rate=emails_opened / max(targets_sent, 1),
            click_rate=links_clicked / max(targets_sent, 1),
            credential_capture_rate=credentials_captured / max(targets_sent, 1),
        )

    @staticmethod
    def extract_credentials(data: dict[str, Any]) -> list[CapturedCredential]:
        """Extract captured credentials from campaign results."""
        creds: list[CapturedCredential] = []
        for result in data.get("results", []):
            if result.get("status") != "Submitted Data":
                continue

            details = result.get("details", {})
            payload = details.get("payload", {})

            username = ""
            password = ""
            for key, values in payload.items():
                key_lower = key.lower()
                if any(k in key_lower for k in ("user", "email", "login")):
                    username = values[0] if values else ""
                elif any(k in key_lower for k in ("pass", "pwd", "secret")):
                    password = values[0] if values else ""

            if username or password:
                creds.append(CapturedCredential(
                    email=result.get("email", ""),
                    username=username,
                    password=password,
                    campaign_name=data.get("name", ""),
                    captured_at=details.get("date", ""),
                ))
        return creds
