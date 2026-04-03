"""
EngagementConfig - Typed configuration for Hellcat pentest engagements.

Supports loading from YAML files or dictionaries. Validates required fields
and applies sensible defaults for optional ones.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml


class Aggression(StrEnum):
    """Aggression level controls noise profile and evasion behavior."""

    STEALTH = "stealth"
    NORMAL = "normal"
    SIEGE = "siege"


# All known engagement phases in execution order
ALL_PHASES: list[str] = [
    "structured_recon", "recon", "vuln_analysis", "exploitation", "reporting",
]

# Valid report formats
VALID_REPORT_FORMATS: set[str] = {"markdown", "json", "sarif"}


class EngagementConfigError(Exception):
    """Raised when engagement config is invalid."""


@dataclass
class EngagementConfig:
    """Configuration for a single Hellcat pentest engagement.

    Required:
        target_url: The URL of the target application.

    Optional:
        target_repo: Path or URL to source code (white-box mode).
        scope_includes: URL patterns to include in scope.
        scope_excludes: URL patterns to exclude from scope.
        credentials: Login credentials for the target.
        phases: Engagement phases to run (default: all).
        model_overrides: Operator-to-model mapping overrides.
        stealth_budget: Total noise budget (default 100).
        aggression: Noise profile (stealth/normal/siege).
        max_concurrency: Max parallel StrikeCells (default 3).
        timeout_seconds: Overall engagement timeout (default 3600).
        output_dir: Directory for reports and artifacts.
        report_formats: Output formats (markdown, json, sarif).
    """

    target_url: str
    target_repo: str | None = None
    scope_includes: list[str] = field(default_factory=list)
    scope_excludes: list[str] = field(default_factory=list)
    credentials: dict[str, str] = field(default_factory=dict)
    phases: list[str] = field(default_factory=lambda: list(ALL_PHASES))
    model_overrides: dict[str, str] = field(default_factory=dict)
    stealth_budget: float = 100.0
    aggression: str = Aggression.NORMAL
    max_concurrency: int = 3
    timeout_seconds: int = 3600
    output_dir: str = "./hellcat-output/"
    report_formats: list[str] = field(default_factory=lambda: ["markdown"])
    osint_sources: list[str] = field(default_factory=lambda: ["crtsh", "nvd"])
    osint_api_keys: dict[str, str] = field(default_factory=dict)
    recon_pipeline_enabled: bool = True
    recon_pipeline_phases: list[str] = field(default_factory=lambda: [
        "asset_discovery", "domain_recon", "port_scan", "service_fingerprint",
        "web_crawl", "resource_enum", "vuln_scan", "intel_enrichment",
    ])
    recon_pipeline_timeout: int = 300
    engagement_id: str | None = None
    project_id: str | None = None

    # Feed freshness SLA
    epss_max_age_hours: int = 24
    nvd_max_age_hours: int = 24
    warn_on_stale_feeds: bool = True

    # Safety / control-plane fields
    authorization_ref: str | None = None
    global_disable: bool = False
    disabled_tools: list[str] = field(default_factory=list)
    disabled_phases: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        """Validate config fields."""
        if not self.target_url or not self.target_url.strip():
            raise EngagementConfigError("target_url is required")

        # Validate phases
        for phase in self.phases:
            if phase not in ALL_PHASES:
                raise EngagementConfigError(
                    f"Unknown phase '{phase}'. Valid phases: {ALL_PHASES}"
                )

        # Validate aggression
        valid_aggression = {a.value for a in Aggression}
        if self.aggression not in valid_aggression:
            raise EngagementConfigError(
                f"Unknown aggression '{self.aggression}'. "
                f"Valid: {sorted(valid_aggression)}"
            )

        # Validate report formats
        for fmt in self.report_formats:
            if fmt not in VALID_REPORT_FORMATS:
                raise EngagementConfigError(
                    f"Unknown report format '{fmt}'. Valid: {sorted(VALID_REPORT_FORMATS)}"
                )

        # Validate numeric bounds
        if self.stealth_budget < 0:
            raise EngagementConfigError("stealth_budget must be >= 0")
        if self.max_concurrency < 1:
            raise EngagementConfigError("max_concurrency must be >= 1")
        if self.timeout_seconds < 1:
            raise EngagementConfigError("timeout_seconds must be >= 1")

    @classmethod
    def from_yaml(cls, path: str | Path) -> EngagementConfig:
        """Load config from a YAML file.

        Args:
            path: Path to the YAML config file.

        Returns:
            EngagementConfig instance.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            EngagementConfigError: If the YAML is invalid.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, dict):
            raise EngagementConfigError(
                f"Config file must contain a YAML mapping, got {type(raw).__name__}"
            )

        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EngagementConfig:
        """Create config from a dictionary.

        Unknown keys are silently ignored to allow forward compatibility.

        Args:
            d: Dictionary with config values.

        Returns:
            EngagementConfig instance.

        Raises:
            EngagementConfigError: If required fields are missing or invalid.
        """
        if "target_url" not in d:
            raise EngagementConfigError("target_url is required in config")

        # Only pass known fields to avoid TypeError on unknown keys
        known_fields = {
            "target_url", "target_repo", "scope_includes", "scope_excludes",
            "credentials", "phases", "model_overrides", "stealth_budget",
            "aggression", "max_concurrency", "timeout_seconds", "output_dir",
            "report_formats", "osint_sources", "osint_api_keys",
            "recon_pipeline_enabled", "recon_pipeline_phases",
            "recon_pipeline_timeout",
            "engagement_id", "project_id",
            "epss_max_age_hours", "nvd_max_age_hours", "warn_on_stale_feeds",
            "authorization_ref", "global_disable",
            "disabled_tools", "disabled_phases",
        }
        filtered = {k: v for k, v in d.items() if k in known_fields}
        return cls(**filtered)

    def to_dict(self) -> dict[str, Any]:
        """Serialize config to a dictionary."""
        return {
            "target_url": self.target_url,
            "target_repo": self.target_repo,
            "scope_includes": self.scope_includes,
            "scope_excludes": self.scope_excludes,
            "credentials": self.credentials,
            "phases": self.phases,
            "model_overrides": self.model_overrides,
            "stealth_budget": self.stealth_budget,
            "aggression": self.aggression,
            "max_concurrency": self.max_concurrency,
            "timeout_seconds": self.timeout_seconds,
            "output_dir": self.output_dir,
            "report_formats": self.report_formats,
            "osint_sources": self.osint_sources,
            "osint_api_keys": self.osint_api_keys,
            "recon_pipeline_enabled": self.recon_pipeline_enabled,
            "recon_pipeline_phases": self.recon_pipeline_phases,
            "recon_pipeline_timeout": self.recon_pipeline_timeout,
            "engagement_id": self.engagement_id,
            "project_id": self.project_id,
            "epss_max_age_hours": self.epss_max_age_hours,
            "nvd_max_age_hours": self.nvd_max_age_hours,
            "warn_on_stale_feeds": self.warn_on_stale_feeds,
            "authorization_ref": self.authorization_ref,
            "global_disable": self.global_disable,
            "disabled_tools": self.disabled_tools,
            "disabled_phases": self.disabled_phases,
        }
