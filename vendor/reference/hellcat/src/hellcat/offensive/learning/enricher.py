"""
PatternEnricher - Enrich operator context with historical pattern data.

Bridges the AttackPatternDB with the dispatch/prompt pipeline by:
  - Adding historical success data to StrikeManifests
  - Generating {{PATTERN_CONTEXT}} sections for prompt templates
  - Adjusting AttackScorer weights based on historical success rates
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from hellcat.offensive.learning.pattern_db import AttackPatternDB
    from hellcat.offensive.strikecell.manifest import StrikeManifest

logger = structlog.get_logger()


class PatternEnricher:
    """
    Enriches operator context with historical attack pattern data.

    Used by the dispatch pipeline to inject learned knowledge into
    operator prompts, improving technique selection and payload choices.
    """

    def __init__(self, pattern_db: AttackPatternDB) -> None:
        self._db = pattern_db

    def enrich_manifest(self, manifest: StrikeManifest) -> None:
        """
        Add historical success data to a StrikeManifest's prior_findings.

        Injects a "pattern_context" entry into prior_findings containing:
          - Best techniques for this vuln type
          - Known-working payloads
          - Historical success rates
        """
        # Derive vuln_type from attack_type or operator name
        vuln_type = self._infer_vuln_type(manifest)
        if not vuln_type:
            return

        patterns = self._db.get_best_techniques(vuln_type)
        if not patterns:
            return

        # Build pattern context as a prior finding
        context: dict[str, Any] = {
            "source_operator": "pattern_db",
            "source_cell": "cross_engagement",
            "type": "pattern_context",
            "data": {
                "vuln_type": vuln_type,
                "techniques": [
                    {
                        "name": p.technique,
                        "success_rate": p.success_rate,
                        "attempts": p.attempts,
                        "avg_evasion_attempts": p.avg_evasion_attempts,
                        "payloads": p.payloads[:3],
                    }
                    for p in patterns[:5]
                ],
            },
        }

        manifest.prior_findings.append(context)

        logger.debug(
            "learning.manifest_enriched",
            vuln_type=vuln_type,
            patterns_added=len(patterns[:5]),
        )

    def enrich_prompt_context(
        self,
        vuln_type: str,
        tech_stack: str = "",
    ) -> str:
        """
        Generate a PATTERN_CONTEXT section for prompt template interpolation.

        Returns a formatted string suitable for injection into operator prompts.
        """
        patterns = self._db.get_best_techniques(vuln_type, tech_stack)
        if not patterns:
            return ""

        lines: list[str] = [
            "<pattern_context>",
            f"Historical data for {vuln_type}" + (f" against {tech_stack}" if tech_stack else "") + ":",
            "",
        ]

        for p in patterns[:5]:
            lines.append(
                f"- {p.technique}: {p.success_rate:.0%} success "
                f"({p.attempts} attempts, avg {p.avg_evasion_attempts:.0f} evasion retries)"
            )
            if p.payloads:
                for payload in p.payloads[:2]:
                    # Truncate long payloads
                    display = payload[:100] + "..." if len(payload) > 100 else payload
                    lines.append(f"  payload: {display}")

        lines.append("")
        lines.append("Use these patterns to inform your approach. Prefer techniques with higher success rates.")
        lines.append("</pattern_context>")

        return "\n".join(lines)

    def get_scorer_adjustments(
        self,
        vuln_type: str,
        tech_stack: str = "",
    ) -> dict[str, float]:
        """
        Return score adjustments for techniques based on historical success.

        Used by AttackScorer to boost/penalize techniques based on learned data.
        Returns a dict of technique -> adjustment factor (0.5 to 1.5).
        """
        patterns = self._db.get_best_techniques(vuln_type, tech_stack, min_attempts=3)
        if not patterns:
            return {}

        adjustments: dict[str, float] = {}
        for p in patterns:
            if p.success_rate >= 0.7:
                adjustments[p.technique] = 1.3
            elif p.success_rate >= 0.4:
                adjustments[p.technique] = 1.0
            elif p.success_rate >= 0.1:
                adjustments[p.technique] = 0.7
            else:
                adjustments[p.technique] = 0.5

        return adjustments

    def _infer_vuln_type(self, manifest: StrikeManifest) -> str:
        """Infer vuln_type from manifest fields."""
        # Map operator names to vuln types
        op_to_vuln: dict[str, str] = {
            "injection-vuln": "sqli",
            "injection-exploit": "sqli",
            "xss-vuln": "xss",
            "auth-vuln": "auth_bypass",
            "auth-exploit": "auth_bypass",
            "authz-vuln": "idor",
            "ssrf-vuln": "ssrf",
        }
        return op_to_vuln.get(manifest.operator_name, manifest.attack_type)
