"""
Evidence level definitions, requirements, and schemas for proof validation.

Defines the L1-L4 evidence hierarchy used to classify and validate
security findings from operator executions during authorized pentesting
engagements.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Evidence levels
# ---------------------------------------------------------------------------


class EvidenceLevel(str, enum.Enum):
    """Four-tier evidence classification for security findings."""

    L1_INFORMATIONAL = "L1"  # Observation-based, no active exploitation
    L2_LIKELY = "L2"         # Behavioral anomaly suggests vuln exists
    L3_CONFIRMED = "L3"      # Active exploitation produced controlled output
    L4_EXPLOITED = "L4"      # Full exploit chain with impact demonstration


# ---------------------------------------------------------------------------
# Evidence requirements per level
# ---------------------------------------------------------------------------


@dataclass
class EvidenceRequirement:
    """Schema gate: what fields and thresholds a given level demands."""

    level: EvidenceLevel
    required_fields: list[str]
    min_confidence: float
    requires_payload: bool
    requires_reproduction: bool
    requires_impact: bool


EVIDENCE_REQUIREMENTS: dict[EvidenceLevel, EvidenceRequirement] = {
    EvidenceLevel.L1_INFORMATIONAL: EvidenceRequirement(
        level=EvidenceLevel.L1_INFORMATIONAL,
        required_fields=["description", "source_location"],
        min_confidence=0.3,
        requires_payload=False,
        requires_reproduction=False,
        requires_impact=False,
    ),
    EvidenceLevel.L2_LIKELY: EvidenceRequirement(
        level=EvidenceLevel.L2_LIKELY,
        required_fields=["description", "source_location", "observed_behavior"],
        min_confidence=0.5,
        requires_payload=False,
        requires_reproduction=False,
        requires_impact=False,
    ),
    EvidenceLevel.L3_CONFIRMED: EvidenceRequirement(
        level=EvidenceLevel.L3_CONFIRMED,
        required_fields=[
            "description", "source_location",
            "witness_payload", "response_evidence",
        ],
        min_confidence=0.7,
        requires_payload=True,
        requires_reproduction=True,
        requires_impact=False,
    ),
    EvidenceLevel.L4_EXPLOITED: EvidenceRequirement(
        level=EvidenceLevel.L4_EXPLOITED,
        required_fields=[
            "description", "source_location",
            "witness_payload", "response_evidence",
            "impact_description",
        ],
        min_confidence=0.85,
        requires_payload=True,
        requires_reproduction=True,
        requires_impact=True,
    ),
}


# ---------------------------------------------------------------------------
# Reproduction result
# ---------------------------------------------------------------------------


@dataclass
class ReproductionResult:
    """Outcome of attempting to reproduce a claimed exploit."""

    reproduced: bool
    attempts: int
    matching_response: bool
    response_snippet: str
    duration_ms: int
    error: str | None = None


# ---------------------------------------------------------------------------
# Security proof
# ---------------------------------------------------------------------------


@dataclass
class SecurityProof:
    """Evidence package from an operator execution."""

    vuln_node_id: str
    operator_name: str
    claimed_level: EvidenceLevel

    # Core evidence
    description: str
    source_location: str  # URL / endpoint where finding exists

    # L2+
    observed_behavior: str = ""

    # L3+
    witness_payload: str = ""
    response_evidence: str = ""

    # L4
    impact_description: str = ""
    data_accessed: str = ""
    privilege_gained: str = ""

    # Metadata
    confidence: float = 0.5
    cvss: float | None = None
    reproduction_result: ReproductionResult | None = None

    # Timing
    created_at: str = field(default_factory=_utc_now)
    operator_duration_ms: int = 0
