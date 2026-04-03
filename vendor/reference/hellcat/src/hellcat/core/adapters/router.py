"""
Toolchain Router - Smart selection of toolchains based on task characteristics.

Routes tasks to the most appropriate toolchain based on:
- Task complexity and risk
- Toolchain availability and health
- Cost optimization
- Historical performance
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from hellcat.core.adapters.base import ToolchainAdapter
from hellcat.core.adapters.claude import ClaudeAdapter
from hellcat.core.adapters.codex import CodexAdapter
from hellcat.core.adapters.crush import CrushAdapter
from hellcat.core.adapters.opencode import OpenCodeAdapter
from hellcat.core.adapters.youtu_agent import YoutuAgentAdapter

if TYPE_CHECKING:
    from hellcat.core.scheduler.routing import KernelConfig
    from hellcat.core.state.models import Issue

logger = structlog.get_logger()


@dataclass
class RoutingDecision:
    """Result of routing decision."""

    toolchain: str
    reason: str
    alternatives: list[str] = field(default_factory=list)
    estimated_cost: float = 0.0


@dataclass
class ToolchainProfile:
    """Profile of a toolchain's capabilities."""

    name: str
    max_complexity: str  # XS, S, M, L, XL
    best_for: list[str]  # tags like "auth", "api", "refactor"
    cost_tier: str  # low, medium, high
    speed_tier: str  # fast, medium, slow
    reliability: float  # 0-1


# Default profiles based on known characteristics
DEFAULT_PROFILES: dict[str, ToolchainProfile] = {
    "codex": ToolchainProfile(
        name="codex",
        max_complexity="XL",
        best_for=["refactor", "api", "test", "fix"],
        cost_tier="high",
        speed_tier="medium",
        reliability=0.85,
    ),
    "claude": ToolchainProfile(
        name="claude",
        max_complexity="XL",
        best_for=["auth", "security", "complex", "architecture"],
        cost_tier="high",
        speed_tier="medium",
        reliability=0.90,
    ),
    "crush": ToolchainProfile(
        name="crush",
        max_complexity="XL",
        best_for=["general", "flexible", "multi-provider"],
        cost_tier="medium",  # Can use cheaper models
        speed_tier="fast",
        reliability=0.85,
    ),
    "opencode": ToolchainProfile(
        name="opencode",
        max_complexity="M",
        best_for=["quick-fix", "simple", "low-risk"],
        cost_tier="low",
        speed_tier="fast",
        reliability=0.7,
    ),
    "youtu-agent": ToolchainProfile(
        name="youtu-agent",
        max_complexity="M",
        best_for=["quick-fix", "simple", "low-risk"],
        cost_tier="low",
        speed_tier="fast",
        reliability=0.65,
    ),
}


class ToolchainRouter:
    """
    Smart router for selecting the best toolchain for a task.

    Selection criteria:
    1. Explicit hint from issue (dk_tool_hint)
    2. Task tags matching toolchain profiles
    3. Complexity matching
    4. Cost optimization
    5. Availability
    """

    def __init__(
        self,
        config: KernelConfig,
        profiles: dict[str, ToolchainProfile] | None = None,
    ) -> None:
        self.config = config
        self.profiles = profiles or DEFAULT_PROFILES
        self._adapters: dict[str, ToolchainAdapter] = {}
        self._overrides_path = Path(self.config.state_dir) / "routing_overrides.json"
        self._overrides: dict[str, Any] = {}
        self._overrides_mtime = 0.0
        self._init_adapters()

    def _init_adapters(self) -> None:
        """Initialize available adapters."""
        adapter_classes: dict[str, type[ToolchainAdapter]] = {
            "codex": CodexAdapter,
            "claude": ClaudeAdapter,
            "crush": CrushAdapter,
            "opencode": OpenCodeAdapter,
            "youtu-agent": YoutuAgentAdapter,
        }

        for name in self.config.toolchain_priority:
            if name in adapter_classes:
                self._adapters[name] = adapter_classes[name]()

    def route(self, issue: Issue) -> RoutingDecision:
        """
        Select the best toolchain for an issue.

        Returns routing decision with reasoning.
        """
        self._load_overrides()
        # Check explicit hint first
        if issue.dk_tool_hint and issue.dk_tool_hint in self._adapters:
            adapter = self._adapters[issue.dk_tool_hint]
            if adapter.available:
                return RoutingDecision(
                    toolchain=issue.dk_tool_hint,
                    reason="explicit_hint",
                    alternatives=self._get_alternatives(issue.dk_tool_hint),
                )

        # Score each toolchain
        scores: dict[str, float] = {}
        reasons: dict[str, str] = {}

        for name, adapter in self._adapters.items():
            if not adapter.available:
                continue

            score, reason = self._score_toolchain(name, issue)
            scores[name] = score
            reasons[name] = reason

        if not scores:
            # No available toolchains - return first in priority
            first = self.config.toolchain_priority[0] if self.config.toolchain_priority else "codex"
            return RoutingDecision(
                toolchain=first,
                reason="no_available_fallback",
                alternatives=[],
            )

        # Select best
        best = max(scores, key=lambda x: scores[x])
        alternatives = [n for n in scores if n != best]

        logger.debug(
            "Toolchain routed",
            issue_id=issue.id,
            selected=best,
            reason=reasons[best],
            scores=scores,
        )

        return RoutingDecision(
            toolchain=best,
            reason=reasons[best],
            alternatives=alternatives,
        )

    def _load_overrides(self) -> None:
        """Load routing overrides from state file if present."""
        try:
            if not self._overrides_path.exists():
                return
            mtime = self._overrides_path.stat().st_mtime
            if mtime <= self._overrides_mtime:
                return
            data = json.loads(self._overrides_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._overrides = data
                self._overrides_mtime = mtime
        except Exception as exc:
            logger.warning("Failed to load routing overrides", error=str(exc))

    def _get_bias(self, name: str, issue: Issue) -> float:
        """Return bias adjustment for a toolchain based on overrides."""
        if not self._overrides:
            return 0.0

        bias = 0.0
        toolchain_bias = self._overrides.get("toolchain_bias", {})
        if isinstance(toolchain_bias, dict):
            bias += float(toolchain_bias.get(name, 0.0) or 0.0)

        tag_bias = self._overrides.get("tag_bias", {})
        if isinstance(tag_bias, dict):
            for tag in issue.tags or []:
                per_tag = tag_bias.get(tag)
                if isinstance(per_tag, dict):
                    bias += float(per_tag.get(name, 0.0) or 0.0)

        return bias

    def _score_toolchain(self, name: str, issue: Issue) -> tuple[float, str]:
        """
        Score a toolchain for an issue.

        Returns (score, reason) tuple.
        """
        profile = self.profiles.get(name)
        if not profile:
            return 50.0, "no_profile"

        score = 50.0
        reason = "default"

        # Tag matching (0-20 points)
        tags = issue.tags or []
        matching_tags = len(set(tags) & set(profile.best_for))
        if matching_tags > 0:
            score += matching_tags * 10
            reason = f"tag_match:{','.join(set(tags) & set(profile.best_for))}"

        # Complexity matching (0-15 points)
        complexity_order = ["XS", "S", "M", "L", "XL"]
        issue_complexity = (
            complexity_order.index(issue.dk_size) if issue.dk_size in complexity_order else 2
        )
        max_complexity = complexity_order.index(profile.max_complexity)

        if issue_complexity <= max_complexity:
            score += 15
        else:
            score -= 20  # Penalize if over capacity

        # Apply dynamic bias overrides (from sleeptime policy updates)
        bias = self._get_bias(name, issue)
        if bias:
            bias_scale = float(self._overrides.get("bias_scale", 12.0)) if self._overrides else 12.0
            score += bias * bias_scale
            reason = f"{reason}+bias({bias:+.2f})"

        # Risk matching (0-15 points)
        # High-risk tasks should go to high-reliability toolchains
        if issue.dk_risk in ("high", "critical"):
            score += profile.reliability * 15
            if profile.reliability >= 0.9:
                reason = "high_reliability_for_risk"

        # Cost optimization (0-10 points)
        # Lower cost is better for low-risk, simple tasks
        if issue.dk_risk == "low" and issue.dk_size in ("XS", "S"):
            cost_bonus = {"low": 10, "medium": 5, "high": 0}.get(profile.cost_tier, 5)
            score += cost_bonus
            if cost_bonus == 10:
                reason = "cost_optimized"

        # Priority order bonus (0-10 points)
        # Give slight preference to priority order
        try:
            priority_index = self.config.toolchain_priority.index(name)
            score += (len(self.config.toolchain_priority) - priority_index) * 2
        except ValueError:
            pass

        return score, reason

    def _get_alternatives(self, selected: str) -> list[str]:
        """Get alternative toolchains."""
        return [
            name
            for name, adapter in self._adapters.items()
            if name != selected and adapter.available
        ]

    def get_available(self) -> list[str]:
        """Get list of available toolchains."""
        return [name for name, adapter in self._adapters.items() if adapter.available]

    def health_check_all(self) -> dict[str, bool]:
        """Check health of all adapters."""
        results = {}
        for name, adapter in self._adapters.items():
            try:
                results[name] = adapter.health_check_sync()
            except Exception:
                results[name] = False
        return results
