"""
AttackProof - Standardized output from a security operator execution.

Replaces PatchProof for the red-teaming / pentesting context.
Each operator returns an AttackProof after executing against a target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class VulnerabilityFinding:
    """A single vulnerability discovered during an operator run."""

    vuln_id: str
    vuln_type: str  # e.g., "SQLi", "XSS-Reflected", "IDOR", "SSRF"
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    description: str
    endpoint: str
    parameter: str | None = None
    evidence_summary: str = ""
    cwe_id: str | None = None  # e.g., "CWE-89"
    cvss_score: float | None = None


@dataclass
class ExploitationResult:
    """Proof-of-exploitation for a single vulnerability."""

    vuln_id: str
    proof_level: Literal["L1", "L2", "L3", "L4"]
    # L1 = theoretical (code path exists)
    # L2 = confirmed (error-based / behavioral proof)
    # L3 = demonstrated (data extracted / action performed)
    # L4 = full chain (multi-step exploitation achieved)
    reproducible: bool
    payload: str = ""
    response_summary: str = ""
    data_extracted: dict[str, Any] = field(default_factory=dict)
    impact_description: str = ""


@dataclass
class DefenseObservation:
    """A defense mechanism encountered during testing."""

    defense_type: str  # e.g., "WAF", "CSP", "rate-limit", "input-validation"
    description: str
    bypassed: bool = False
    bypass_technique: str | None = None


@dataclass
class AttackProof:
    """Standardized output from a security operator (strike cell) execution.

    This is the red-teaming counterpart to PatchProof. Every security
    operator returns an AttackProof documenting what was attempted,
    what was found, and what evidence was collected.
    """

    schema_version: str = "1.0.0"
    strike_cell_id: str = ""
    target_id: str = ""
    operator_name: str = ""

    status: Literal[
        "success", "partial", "failed", "blocked", "evasion_needed"
    ] = "failed"

    # Evidence: raw request/response pairs, screenshots, extracted data
    evidence: dict[str, Any] = field(default_factory=dict)
    # Structured vulnerability findings
    vulnerabilities_found: list[VulnerabilityFinding] = field(default_factory=list)
    # Exploitation results with proof levels
    exploitation_results: list[ExploitationResult] = field(default_factory=list)
    # Credentials or tokens harvested during testing
    credentials_harvested: list[dict[str, Any]] = field(default_factory=list)
    # Follow-up attack vectors discovered for other operators
    chain_opportunities: list[str] = field(default_factory=list)
    # Defenses encountered (WAFs, CSPs, rate limits, etc.)
    defense_observations: list[DefenseObservation] = field(default_factory=list)

    # Execution metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    # Overall confidence in the findings (0.0 = no confidence, 1.0 = certain)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "schema_version": self.schema_version,
            "strike_cell_id": self.strike_cell_id,
            "target_id": self.target_id,
            "operator_name": self.operator_name,
            "status": self.status,
            "evidence": self.evidence,
            "vulnerabilities_found": [
                {
                    "vuln_id": v.vuln_id,
                    "vuln_type": v.vuln_type,
                    "severity": v.severity,
                    "title": v.title,
                    "description": v.description,
                    "endpoint": v.endpoint,
                    "parameter": v.parameter,
                    "evidence_summary": v.evidence_summary,
                    "cwe_id": v.cwe_id,
                    "cvss_score": v.cvss_score,
                }
                for v in self.vulnerabilities_found
            ],
            "exploitation_results": [
                {
                    "vuln_id": e.vuln_id,
                    "proof_level": e.proof_level,
                    "reproducible": e.reproducible,
                    "payload": e.payload,
                    "response_summary": e.response_summary,
                    "data_extracted": e.data_extracted,
                    "impact_description": e.impact_description,
                }
                for e in self.exploitation_results
            ],
            "credentials_harvested": self.credentials_harvested,
            "chain_opportunities": self.chain_opportunities,
            "defense_observations": [
                {
                    "defense_type": d.defense_type,
                    "description": d.description,
                    "bypassed": d.bypassed,
                    "bypass_technique": d.bypass_technique,
                }
                for d in self.defense_observations
            ],
            "metadata": self.metadata,
            "confidence": self.confidence,
        }
