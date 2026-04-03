"""
OSINT source abstractions for Hellcat recon operators.

Defines the OsintFinding data class, OsintSource protocol, and OsintResult
container used by all OSINT data providers (crt.sh, NVD, search engines, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol


@dataclass
class OsintFinding:
    """A single finding from an OSINT data source."""

    source: str
    finding_type: str
    value: str
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(UTC).isoformat()


class OsintSource(Protocol):
    """Protocol that all OSINT data sources must satisfy."""

    @property
    def source_name(self) -> str: ...

    @property
    def requires_api_key(self) -> bool: ...

    def query(self, target: str, **kwargs: Any) -> list[OsintFinding]: ...


@dataclass
class OsintResult:
    """Aggregated results from one or more OSINT source queries."""

    target: str
    findings: list[OsintFinding] = field(default_factory=list)
    sources_queried: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    def merge(self, other: OsintResult) -> OsintResult:
        """Merge another OsintResult into a new combined result."""
        return OsintResult(
            target=self.target,
            findings=self.findings + other.findings,
            sources_queried=list(
                dict.fromkeys(self.sources_queried + other.sources_queried)
            ),
            errors={**self.errors, **other.errors},
        )

    def findings_by_type(self, finding_type: str) -> list[OsintFinding]:
        """Return all findings of a given type."""
        return [f for f in self.findings if f.finding_type == finding_type]

    def deduplicated_values(self, finding_type: str) -> list[str]:
        """Return unique finding values for a given type, preserving order."""
        return list(dict.fromkeys(
            f.value for f in self.findings if f.finding_type == finding_type
        ))
