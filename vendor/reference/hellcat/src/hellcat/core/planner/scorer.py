"""
AttackScorer for Hellcat engagement planner.

Scores ANALYZED vulnerability nodes for prioritization by combining:
  severity(30%) + exploitability(25%) + chain_potential(20%) + epss(15%) + cvss_v4(10%)
  divided by stealth_cost factor, with defense_penalty and staleness discount applied.

Used by the AttackPlanner to rank ready attacks for scheduling.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import structlog

from hellcat.offensive.target_graph.models import EdgeType, Severity

if TYPE_CHECKING:
    from hellcat.offensive.knowledge.vuln_db import VulnKnowledgeBase
    from hellcat.core.planner.chain_analyzer import ChainAnalyzer
    from hellcat.offensive.target_graph.graph import TargetGraph

logger = structlog.get_logger()

# Default staleness thresholds (hours)
EPSS_STALENESS_HOURS = 7 * 24   # 7 days
NVD_STALENESS_HOURS = 30 * 24   # 30 days


# Severity -> numeric score
SEVERITY_SCORES: dict[Severity, float] = {
    Severity.INFO: 0.1,
    Severity.LOW: 0.3,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.8,
    Severity.CRITICAL: 1.0,
}

# Default stealth costs for common vuln types (maps to ACTION_COSTS keys)
_VULN_TYPE_TO_ACTION: dict[str, str] = {
    "sqli": "injection_probe",
    "xss": "xss_probe",
    "ssrf": "ssrf_probe",
    "rce": "exploit_attempt",
    "auth_bypass": "auth_test",
    "idor": "auth_test",
    "lfi": "injection_probe",
    "xxe": "injection_probe",
    "credential_spray": "credential_spray",
    "privesc": "privilege_escalation",
}


@dataclass
class ScoredAttack:
    """A scored and ranked attack candidate."""

    node_id: str
    vuln_type: str
    score: float
    breakdown: dict[str, float] = field(default_factory=dict)
    recommended_operator: str = ""


class AttackScorer:
    """
    Scores ANALYZED vulnerability nodes for attack prioritization.

    Combines severity, exploitability, chain potential, and stealth cost
    into a single comparable score used by the AttackPlanner.
    """

    def __init__(
        self,
        graph: TargetGraph,
        chain_analyzer: ChainAnalyzer,
        action_costs: dict[str, float] | None = None,
        vuln_kb: VulnKnowledgeBase | None = None,
        epss_staleness_hours: float | None = None,
        nvd_staleness_hours: float | None = None,
    ) -> None:
        self.graph = graph
        self.chain_analyzer = chain_analyzer
        self.vuln_kb = vuln_kb
        self._epss_staleness_hours = (
            epss_staleness_hours if epss_staleness_hours is not None
            else EPSS_STALENESS_HOURS
        )
        self._nvd_staleness_hours = (
            nvd_staleness_hours if nvd_staleness_hours is not None
            else NVD_STALENESS_HOURS
        )
        # Import at runtime to avoid circular deps
        from hellcat.offensive.opsec.stealth_budget import ACTION_COSTS

        self._action_costs = action_costs or ACTION_COSTS

    def score_node(self, node: dict[str, Any]) -> ScoredAttack:
        """Score a single ANALYZED node and return a ScoredAttack."""
        node_id: str = node["id"]
        vuln_type: str = node.get("vuln_type", "unknown")

        severity = self._compute_severity(node)
        exploitability = self._compute_exploitability(node)
        kev_boost = self._compute_kev_boost(node)
        exploitability = min(1.0, exploitability + kev_boost)
        chain_potential = self.chain_analyzer.get_chain_potential(self.graph, node_id)
        stealth_cost = self._compute_stealth_cost(vuln_type)
        defense_penalty = self._compute_defense_penalty(node_id)

        # Standards signals from enrichment metadata
        epss_boost = self._compute_epss_boost(node)
        cvss_v4_factor = self._compute_cvss_v4_factor(node)
        staleness_discount = self._compute_staleness_discount(node)

        # Weighted composite score
        raw = (
            severity * 0.30
            + exploitability * 0.25
            + chain_potential * 0.20
            + epss_boost * 0.15
            + cvss_v4_factor * 0.10
        )

        # Divide by stealth cost factor (floor at 0.01 to avoid division by zero)
        cost_divisor = max(stealth_cost * 0.10, 0.01)
        score = raw / cost_divisor

        # Apply defense penalty
        score = score * (1.0 - defense_penalty)

        # Apply staleness discount
        score = score * (1.0 - staleness_discount)

        breakdown = {
            "severity": round(severity, 3),
            "exploitability": round(exploitability, 3),
            "kev_boost": round(kev_boost, 3),
            "chain_potential": round(chain_potential, 3),
            "stealth_cost": round(stealth_cost, 3),
            "defense_penalty": round(defense_penalty, 3),
            "epss_boost": round(epss_boost, 3),
            "cvss_v4_factor": round(cvss_v4_factor, 3),
            "staleness_discount": round(staleness_discount, 3),
            "raw_composite": round(raw, 3),
        }

        recommended = self._recommend_operator(vuln_type)

        scored = ScoredAttack(
            node_id=node_id,
            vuln_type=vuln_type,
            score=round(score, 3),
            breakdown=breakdown,
            recommended_operator=recommended,
        )

        logger.debug(
            "planner.scored_attack",
            node_id=node_id,
            vuln_type=vuln_type,
            score=scored.score,
            severity=severity,
            exploitability=exploitability,
            chain_potential=chain_potential,
            epss_boost=epss_boost,
            cvss_v4_factor=cvss_v4_factor,
        )

        return scored

    def _compute_severity(self, node: dict[str, Any]) -> float:
        """Map the node's Severity enum to a numeric score."""
        sev_str = node.get("severity", "medium")
        try:
            sev = Severity(sev_str)
        except ValueError:
            sev = Severity.MEDIUM
        return SEVERITY_SCORES.get(sev, 0.5)

    def _compute_exploitability(self, node: dict[str, Any]) -> float:
        """Score exploitability based on confidence and witness payload existence."""
        confidence = float(node.get("confidence", 0.5))
        has_witness = bool(node.get("witness_payload", ""))

        # Base: confidence value (0.0-1.0)
        score = confidence

        # Bonus for having a witness payload (proven exploitable)
        if has_witness:
            score = min(1.0, score + 0.2)

        return score

    def _compute_stealth_cost(self, vuln_type: str) -> float:
        """Estimate the stealth cost for exploiting this vuln type."""
        action_key = _VULN_TYPE_TO_ACTION.get(vuln_type, "exploit_attempt")
        base_cost = self._action_costs.get(action_key, 5.0)
        # Normalize to 0.0-1.0 range (max cost in table is ~10)
        return min(1.0, base_cost / 10.0)

    def _compute_defense_penalty(self, node_id: str) -> float:
        """Check if active defenses block this node. Returns 0.5 if blocked, 0.0 if clear."""
        edges = self.graph.get_edges_to(node_id, edge_type=EdgeType.BLOCKS)
        if not edges:
            return 0.0

        # Check if all blockers have been bypassed
        for edge in edges:
            source_id = edge["source_id"]
            bypasses = self.graph.get_edges_to(source_id, edge_type=EdgeType.BYPASSED_BY)
            if not bypasses:
                return 0.5

        return 0.0

    def _get_enrichment_meta(self, node: dict[str, Any]) -> dict[str, Any]:
        """Parse enrichment metadata from a node's metadata_json."""
        meta_raw = node.get("metadata_json", "{}")
        try:
            return json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}

    def _compute_epss_boost(self, node: dict[str, Any]) -> float:
        """Score EPSS exploitation probability as a 0.0-1.0 signal.

        High EPSS (>0.5) maps to high signal. The raw probability
        is used directly as it's already 0.0-1.0.
        """
        meta = self._get_enrichment_meta(node)
        epss = meta.get("epss_score")
        if epss is None:
            return 0.0
        try:
            return max(0.0, min(1.0, float(epss)))
        except (TypeError, ValueError):
            return 0.0

    def _compute_cvss_v4_factor(self, node: dict[str, Any]) -> float:
        """Score CVSS v4 impact as a 0.0-1.0 signal.

        Normalizes the 0-10 CVSS v4 score to 0.0-1.0.
        """
        meta = self._get_enrichment_meta(node)
        v4 = meta.get("cvss_v4_score")
        if v4 is None:
            return 0.0
        try:
            return max(0.0, min(1.0, float(v4) / 10.0))
        except (TypeError, ValueError):
            return 0.0

    def _compute_staleness_discount(self, node: dict[str, Any]) -> float:
        """Discount score when enrichment data is stale.

        Returns 0.0-0.3 discount factor based on data_freshness age.
        """
        meta = self._get_enrichment_meta(node)
        freshness = meta.get("data_freshness")
        if not freshness:
            return 0.0
        try:
            ts = datetime.fromisoformat(freshness)
            age_hours = (datetime.now(UTC) - ts).total_seconds() / 3600.0
        except (TypeError, ValueError):
            return 0.0
        if age_hours <= self._epss_staleness_hours:
            return 0.0
        if age_hours <= self._nvd_staleness_hours:
            return 0.1
        return 0.3

    def _compute_kev_boost(self, node: dict[str, Any]) -> float:
        """Return 0.2 exploitability bonus if the node's CVE is in the KEV catalog."""
        if not self.vuln_kb:
            return 0.0
        meta_raw = node.get("metadata_json", "{}")
        try:
            meta = json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
        except (json.JSONDecodeError, ValueError):
            return 0.0
        cve_id = meta.get("cve_id", "")
        if cve_id and self.vuln_kb.is_kev(cve_id):
            return 0.2
        return 0.0

    def _recommend_operator(self, vuln_type: str) -> str:
        """Suggest which operator type should handle this vuln."""
        mapping = {
            "sqli": "injection_operator",
            "xss": "xss_operator",
            "ssrf": "ssrf_operator",
            "rce": "rce_operator",
            "auth_bypass": "auth_operator",
            "idor": "auth_operator",
            "lfi": "injection_operator",
            "xxe": "injection_operator",
            "credential_spray": "credential_operator",
            "privesc": "privesc_operator",
        }
        return mapping.get(vuln_type, "generic_operator")
