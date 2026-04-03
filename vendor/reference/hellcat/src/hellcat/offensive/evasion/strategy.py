"""
Evasion strategy generator for the Hellcat kernel.

Given a classified block reason and context about the target/vulnerability,
generates a bypass strategy with concrete technique parameters that the
operator can use on retry.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

import structlog

from hellcat.offensive.evasion.classifier import BlockReason

logger = structlog.get_logger()


class EvasionTechnique(str, enum.Enum):
    """Categories of evasion techniques."""

    # Encoding mutations
    DOUBLE_URL_ENCODE = "double_url_encode"
    UNICODE_NORMALIZE = "unicode_normalize"
    HTML_ENTITY_ENCODE = "html_entity_encode"
    HEX_ENCODE = "hex_encode"
    MIXED_CASE = "mixed_case"

    # Timing adjustments
    SLOW_RATE = "slow_rate"
    RANDOM_JITTER = "random_jitter"
    BURST_THEN_PAUSE = "burst_then_pause"

    # Payload mutation
    POLYMORPHIC_PAYLOAD = "polymorphic_payload"
    COMMENT_INJECTION = "comment_injection"
    WHITESPACE_VARIATION = "whitespace_variation"
    NULL_BYTE_INSERT = "null_byte_insert"
    CONCATENATION_SPLIT = "concatenation_split"

    # Protocol-level
    CHUNKED_ENCODING = "chunked_encoding"
    HTTP2_DESYNC = "http2_desync"
    HEADER_SMUGGLING = "header_smuggling"
    CONTENT_TYPE_MISMATCH = "content_type_mismatch"

    # Session/auth
    RE_AUTHENTICATE = "re_authenticate"
    ROTATE_SESSION = "rotate_session"
    TOKEN_REFRESH = "token_refresh"

    # Network
    PROXY_ROTATE = "proxy_rotate"
    USER_AGENT_ROTATE = "user_agent_rotate"
    REFERER_SPOOF = "referer_spoof"

    # Avoidance
    ABORT_TARGET = "abort_target"
    DEPRIORITIZE = "deprioritize"


@dataclass
class EvasionStrategy:
    """A concrete bypass strategy for a blocked attempt."""

    techniques: list[EvasionTechnique]
    parameters: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    estimated_success_rate: float = 0.0
    max_retries: int = 2
    cooldown_seconds: float = 0.0


# Strategy tables: BlockReason -> list of (techniques, params, description, est_success, cooldown)
_WAF_STRATEGIES: list[tuple[list[EvasionTechnique], dict, str, float, float]] = [
    (
        [EvasionTechnique.DOUBLE_URL_ENCODE, EvasionTechnique.MIXED_CASE],
        {"encode_depth": 2},
        "Double URL-encode payload with mixed case to bypass regex-based WAF rules",
        0.4,
        5.0,
    ),
    (
        [EvasionTechnique.UNICODE_NORMALIZE, EvasionTechnique.COMMENT_INJECTION],
        {"unicode_form": "NFKC"},
        "Use Unicode normalization with inline comments to evade pattern matching",
        0.35,
        5.0,
    ),
    (
        [EvasionTechnique.CHUNKED_ENCODING, EvasionTechnique.WHITESPACE_VARIATION],
        {"chunk_size": 8},
        "Split payload across HTTP chunks with whitespace variation",
        0.3,
        10.0,
    ),
    (
        [EvasionTechnique.CONTENT_TYPE_MISMATCH, EvasionTechnique.POLYMORPHIC_PAYLOAD],
        {},
        "Send mismatched Content-Type to confuse WAF parser, with polymorphic payload",
        0.25,
        5.0,
    ),
]

_RATE_LIMIT_STRATEGIES: list[tuple[list[EvasionTechnique], dict, str, float, float]] = [
    (
        [EvasionTechnique.SLOW_RATE, EvasionTechnique.RANDOM_JITTER],
        {"min_delay_ms": 2000, "max_delay_ms": 8000},
        "Slow down request rate with randomized jitter",
        0.7,
        30.0,
    ),
    (
        [EvasionTechnique.BURST_THEN_PAUSE, EvasionTechnique.USER_AGENT_ROTATE],
        {"burst_count": 3, "pause_seconds": 60},
        "Send small bursts then pause, rotating user-agent between bursts",
        0.5,
        60.0,
    ),
]

_INPUT_VALIDATION_STRATEGIES: list[tuple[list[EvasionTechnique], dict, str, float, float]] = [
    (
        [EvasionTechnique.DOUBLE_URL_ENCODE, EvasionTechnique.NULL_BYTE_INSERT],
        {},
        "Double-encode with null byte insertion to bypass input sanitization",
        0.35,
        2.0,
    ),
    (
        [EvasionTechnique.CONCATENATION_SPLIT, EvasionTechnique.COMMENT_INJECTION],
        {},
        "Split payload using string concatenation with inline comments",
        0.3,
        2.0,
    ),
    (
        [EvasionTechnique.HEX_ENCODE, EvasionTechnique.WHITESPACE_VARIATION],
        {},
        "Hex-encode critical characters with whitespace variation",
        0.3,
        2.0,
    ),
]

_SESSION_STRATEGIES: list[tuple[list[EvasionTechnique], dict, str, float, float]] = [
    (
        [EvasionTechnique.RE_AUTHENTICATE, EvasionTechnique.ROTATE_SESSION],
        {},
        "Re-authenticate and obtain a fresh session",
        0.8,
        5.0,
    ),
    (
        [EvasionTechnique.TOKEN_REFRESH],
        {},
        "Refresh authentication token",
        0.7,
        2.0,
    ),
]

_IP_BLOCK_STRATEGIES: list[tuple[list[EvasionTechnique], dict, str, float, float]] = [
    (
        [EvasionTechnique.PROXY_ROTATE, EvasionTechnique.SLOW_RATE],
        {"min_delay_ms": 5000, "max_delay_ms": 15000},
        "Rotate proxy and reduce scan rate significantly",
        0.5,
        60.0,
    ),
]

_CAPTCHA_STRATEGIES: list[tuple[list[EvasionTechnique], dict, str, float, float]] = [
    (
        [EvasionTechnique.ABORT_TARGET],
        {"reason": "captcha_required"},
        "CAPTCHA detected - abort and alert engagement owner",
        0.0,
        0.0,
    ),
]

_HONEYPOT_STRATEGIES: list[tuple[list[EvasionTechnique], dict, str, float, float]] = [
    (
        [EvasionTechnique.ABORT_TARGET],
        {"reason": "honeypot_detected"},
        "Honeypot/tarpit detected - abort target immediately",
        0.0,
        0.0,
    ),
]

_STRATEGY_TABLE: dict[
    BlockReason,
    list[tuple[list[EvasionTechnique], dict, str, float, float]],
] = {
    BlockReason.WAF_BLOCKED: _WAF_STRATEGIES,
    BlockReason.RATE_LIMITED: _RATE_LIMIT_STRATEGIES,
    BlockReason.INPUT_VALIDATED: _INPUT_VALIDATION_STRATEGIES,
    BlockReason.SESSION_KILLED: _SESSION_STRATEGIES,
    BlockReason.IP_BLOCKED: _IP_BLOCK_STRATEGIES,
    BlockReason.CAPTCHA_CHALLENGED: _CAPTCHA_STRATEGIES,
    BlockReason.HONEYPOT_DETECTED: _HONEYPOT_STRATEGIES,
}


class StrategyGenerator:
    """
    Generates evasion strategies for blocked exploitation attempts.

    Selects techniques based on the classified block reason and optionally
    incorporates historical success/failure data from the AttackPatternDB.
    """

    def __init__(self, max_retries: int = 2) -> None:
        self.max_retries = max_retries
        # Track which strategies have been tried per vuln node, to avoid repeats
        self._attempted: dict[str, set[int]] = {}

    def generate(
        self,
        reason: BlockReason,
        *,
        vuln_node_id: str = "",
        attempt_number: int = 0,
    ) -> EvasionStrategy | None:
        """
        Generate an evasion strategy for the given block reason.

        Returns None if no viable strategies remain (target should be hardened).
        """
        candidates = _STRATEGY_TABLE.get(reason, [])

        if not candidates:
            logger.info(
                "evasion.no_strategies",
                reason=reason.value,
                vuln_node_id=vuln_node_id,
            )
            return None

        # Filter out already-attempted strategies for this vuln
        attempted = self._attempted.get(vuln_node_id, set())
        remaining = [
            (i, c) for i, c in enumerate(candidates) if i not in attempted
        ]

        if not remaining:
            logger.info(
                "evasion.strategies_exhausted",
                reason=reason.value,
                vuln_node_id=vuln_node_id,
                total_tried=len(attempted),
            )
            return None

        # Pick the highest estimated success rate among untried strategies
        idx, (techniques, params, desc, est_success, cooldown) = max(
            remaining, key=lambda x: x[1][3]
        )

        # Record this strategy as attempted
        self._attempted.setdefault(vuln_node_id, set()).add(idx)

        strategy = EvasionStrategy(
            techniques=techniques,
            parameters=dict(params),
            description=desc,
            estimated_success_rate=est_success,
            max_retries=self.max_retries,
            cooldown_seconds=cooldown,
        )

        logger.info(
            "evasion.strategy_generated",
            reason=reason.value,
            techniques=[t.value for t in techniques],
            est_success=est_success,
            vuln_node_id=vuln_node_id,
            attempt=attempt_number,
        )

        return strategy

    def reset(self, vuln_node_id: str) -> None:
        """Reset attempted strategies for a vuln node."""
        self._attempted.pop(vuln_node_id, None)

    def reset_all(self) -> None:
        """Reset all tracked attempts."""
        self._attempted.clear()
