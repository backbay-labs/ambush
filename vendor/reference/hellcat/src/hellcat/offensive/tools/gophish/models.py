"""Data models for GoPhish integration."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PhishingCampaign:
    """A GoPhish phishing campaign."""

    campaign_id: int = 0
    name: str = ""
    status: str = ""  # "Created", "Queued", "In Progress", "Completed"
    created_date: str = ""
    completed_date: str = ""
    template_name: str = ""
    landing_page: str = ""
    sending_profile: str = ""
    url: str = ""


@dataclass
class PhishingResult:
    """Aggregated results from a phishing campaign."""

    campaign_name: str = ""
    targets_sent: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    credentials_captured: int = 0
    reported_count: int = 0
    email_open_rate: float = 0.0
    click_rate: float = 0.0
    credential_capture_rate: float = 0.0


@dataclass
class CapturedCredential:
    """A credential captured via phishing."""

    email: str = ""
    username: str = ""
    password: str = ""
    campaign_name: str = ""
    captured_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
