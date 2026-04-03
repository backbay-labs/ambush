"""
Attack failure classifier for the evasion loop.

Inspects HTTP responses, error messages, and behavioral signals to determine
why an exploitation attempt was blocked, so the strategy generator can
select an appropriate bypass technique.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from hellcat.offensive.target_graph.models import DefenseType

if TYPE_CHECKING:
    from hellcat.offensive.knowledge.vuln_db import VulnKnowledgeBase

logger = structlog.get_logger()


class BlockReason(str, enum.Enum):
    """Why an exploitation attempt was blocked."""

    WAF_BLOCKED = "waf_blocked"
    RATE_LIMITED = "rate_limited"
    INPUT_VALIDATED = "input_validated"
    SESSION_KILLED = "session_killed"
    CAPTCHA_CHALLENGED = "captcha_challenged"
    IP_BLOCKED = "ip_blocked"
    PATCHED = "patched"
    HONEYPOT_DETECTED = "honeypot_detected"
    UNKNOWN = "unknown"


# Maps BlockReason -> the DefenseType that likely caused it.
REASON_TO_DEFENSE: dict[BlockReason, DefenseType] = {
    BlockReason.WAF_BLOCKED: DefenseType.WAF,
    BlockReason.RATE_LIMITED: DefenseType.RATE_LIMITER,
    BlockReason.INPUT_VALIDATED: DefenseType.INPUT_VALIDATION,
    BlockReason.CAPTCHA_CHALLENGED: DefenseType.CAPTCHA,
    BlockReason.IP_BLOCKED: DefenseType.IP_ALLOWLIST,
    BlockReason.SESSION_KILLED: DefenseType.AUTH_MECHANISM,
}


@dataclass
class ClassificationResult:
    """Result of classifying a blocked exploitation attempt."""

    reason: BlockReason
    confidence: float  # 0.0 - 1.0
    defense_type: DefenseType | None = None
    evidence: str = ""
    raw_signals: dict[str, Any] = field(default_factory=dict)


@dataclass
class EnhancedClassification:
    """Classification enriched with defense signature intelligence."""

    reason: BlockReason
    confidence: float
    defense_type: DefenseType | None = None
    evidence: str = ""
    raw_signals: dict[str, Any] = field(default_factory=dict)
    # Defense intelligence fields
    defense_id: str = ""
    defense_product: str = ""
    defense_match_confidence: float = 0.0
    recommended_bypasses: list[str] = field(default_factory=list)
    recommended_techniques: list[str] = field(default_factory=list)


# Indicator patterns: (regex, BlockReason, base_confidence)
_PATTERNS: list[tuple[str, BlockReason, float]] = [
    # WAF signatures
    (r"403 forbidden", BlockReason.WAF_BLOCKED, 0.7),
    (r"mod_security|modsec", BlockReason.WAF_BLOCKED, 0.9),
    (r"cloudflare.*blocked|cf-ray.*403", BlockReason.WAF_BLOCKED, 0.85),
    (r"aws ?waf|waf.*rule", BlockReason.WAF_BLOCKED, 0.85),
    (r"access denied.*security", BlockReason.WAF_BLOCKED, 0.75),
    (r"request blocked|blocked by.*firewall", BlockReason.WAF_BLOCKED, 0.8),
    # Rate limiting
    (r"429 too many", BlockReason.RATE_LIMITED, 0.95),
    (r"rate.?limit|throttl", BlockReason.RATE_LIMITED, 0.85),
    (r"retry.?after", BlockReason.RATE_LIMITED, 0.8),
    (r"too many requests", BlockReason.RATE_LIMITED, 0.9),
    # Input validation
    (r"invalid.*input|validation.*fail", BlockReason.INPUT_VALIDATED, 0.7),
    (r"malformed.*request|bad request.*param", BlockReason.INPUT_VALIDATED, 0.65),
    (r"xss.*detected|script.*blocked", BlockReason.INPUT_VALIDATED, 0.8),
    (r"sql.*inject.*detect", BlockReason.INPUT_VALIDATED, 0.85),
    # Session/auth
    (r"session.*expired|session.*invalid", BlockReason.SESSION_KILLED, 0.8),
    (r"401 unauthorized", BlockReason.SESSION_KILLED, 0.6),
    (r"token.*expired|jwt.*invalid", BlockReason.SESSION_KILLED, 0.75),
    # CAPTCHA
    (r"captcha|recaptcha|hcaptcha", BlockReason.CAPTCHA_CHALLENGED, 0.9),
    (r"challenge.*required|verify.*human", BlockReason.CAPTCHA_CHALLENGED, 0.8),
    # IP blocking
    (r"ip.*blocked|ip.*banned|blacklist", BlockReason.IP_BLOCKED, 0.85),
    (r"connection refused|connection reset", BlockReason.IP_BLOCKED, 0.5),
    (r"timeout.*connect", BlockReason.IP_BLOCKED, 0.4),
    # Honeypot
    (r"honeypot|tarpit|canary", BlockReason.HONEYPOT_DETECTED, 0.7),
]


class FailureClassifier:
    """
    Classifies why an exploitation attempt was blocked.

    Examines HTTP status codes, response bodies, headers, and behavioral
    signals to determine the blocking mechanism.
    """

    def classify(
        self,
        *,
        status_code: int | None = None,
        response_body: str = "",
        response_headers: dict[str, str] | None = None,
        error_message: str = "",
        response_time_ms: float | None = None,
    ) -> ClassificationResult:
        """Classify a blocked attempt from available signals."""
        headers = response_headers or {}
        signals: dict[str, Any] = {
            "status_code": status_code,
            "response_time_ms": response_time_ms,
        }

        # Combine text to search
        search_text = "\n".join([
            str(status_code or ""),
            response_body[:4000],
            " ".join(f"{k}: {v}" for k, v in headers.items()),
            error_message,
        ]).lower()

        # Score each reason by matching patterns
        scores: dict[BlockReason, float] = {}
        evidence_parts: dict[BlockReason, list[str]] = {}

        for pattern, reason, base_conf in _PATTERNS:
            match = re.search(pattern, search_text, re.IGNORECASE)
            if match:
                current = scores.get(reason, 0.0)
                scores[reason] = max(current, base_conf)
                evidence_parts.setdefault(reason, []).append(
                    f"matched '{pattern}' -> {match.group()}"
                )

        # Boost from status code heuristics
        if status_code == 429:
            scores[BlockReason.RATE_LIMITED] = max(
                scores.get(BlockReason.RATE_LIMITED, 0.0), 0.95
            )
        elif status_code == 403:
            scores[BlockReason.WAF_BLOCKED] = max(
                scores.get(BlockReason.WAF_BLOCKED, 0.0), 0.6
            )
        elif status_code == 401:
            scores[BlockReason.SESSION_KILLED] = max(
                scores.get(BlockReason.SESSION_KILLED, 0.0), 0.5
            )

        # Behavioral: very slow response might be tarpit/honeypot
        if response_time_ms and response_time_ms > 30_000:
            scores[BlockReason.HONEYPOT_DETECTED] = max(
                scores.get(BlockReason.HONEYPOT_DETECTED, 0.0), 0.6
            )
            signals["slow_response"] = True

        if not scores:
            return ClassificationResult(
                reason=BlockReason.UNKNOWN,
                confidence=0.0,
                evidence="no matching patterns",
                raw_signals=signals,
            )

        # Pick highest-confidence reason
        best_reason = max(scores, key=lambda r: scores[r])
        confidence = scores[best_reason]
        evidence = "; ".join(evidence_parts.get(best_reason, []))
        defense_type = REASON_TO_DEFENSE.get(best_reason)

        result = ClassificationResult(
            reason=best_reason,
            confidence=confidence,
            defense_type=defense_type,
            evidence=evidence,
            raw_signals=signals,
        )

        logger.debug(
            "evasion.classified",
            reason=best_reason.value,
            confidence=confidence,
            defense_type=defense_type.value if defense_type else None,
        )

        return result

    def classify_with_intelligence(
        self,
        vuln_db: VulnKnowledgeBase,
        *,
        status_code: int | None = None,
        response_body: str = "",
        response_headers: dict[str, str] | None = None,
        error_message: str = "",
        response_time_ms: float | None = None,
    ) -> EnhancedClassification:
        """
        Classify a blocked attempt and enrich with defense signature intelligence.

        Uses VulnKnowledgeBase defense signatures to identify the specific
        defense product and provide recommended bypasses.

        Falls back to standard classification when no defense match is found.
        """
        # First do the standard classification
        base = self.classify(
            status_code=status_code,
            response_body=response_body,
            response_headers=response_headers,
            error_message=error_message,
            response_time_ms=response_time_ms,
        )

        # Try to identify the defense from response signals
        matches = vuln_db.identify_defense(
            response_headers=response_headers,
            status_code=status_code,
            body_snippet=response_body[:4000],
        )

        defense_id = ""
        defense_product = ""
        defense_match_confidence = 0.0
        recommended_bypasses: list[str] = []
        recommended_techniques: list[str] = []

        if matches:
            top_sig, top_conf = matches[0]
            defense_id = top_sig.defense_id
            defense_product = top_sig.product
            defense_match_confidence = top_conf
            recommended_bypasses = list(top_sig.known_bypasses)
            recommended_techniques = list(top_sig.evasion_techniques)

        enhanced = EnhancedClassification(
            reason=base.reason,
            confidence=base.confidence,
            defense_type=base.defense_type,
            evidence=base.evidence,
            raw_signals=base.raw_signals,
            defense_id=defense_id,
            defense_product=defense_product,
            defense_match_confidence=defense_match_confidence,
            recommended_bypasses=recommended_bypasses,
            recommended_techniques=recommended_techniques,
        )

        logger.debug(
            "evasion.classified_with_intelligence",
            reason=base.reason.value,
            confidence=base.confidence,
            defense_product=defense_product or None,
            defense_confidence=defense_match_confidence,
        )

        return enhanced
