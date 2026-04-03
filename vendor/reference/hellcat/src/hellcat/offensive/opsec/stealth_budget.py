"""
Stealth budget for Hellcat engagements.

Each engagement starts with a finite noise budget. Every action that could
trigger detection costs points from the budget. The aggression level controls
how aggressively the kernel spends its budget.

Aggression levels:
  WHISPER  - Maximum stealth: slow scanning, minimal active probing
  NORMAL   - Balanced: standard scan rates with jitter
  LOUD     - Aggressive: parallel exploitation, faster scanning
  SIEGE    - Maximum speed: no OPSEC constraints (CTF/lab mode)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()


class AggressionLevel(str, enum.Enum):
    """How aggressively the kernel consumes its stealth budget."""

    WHISPER = "whisper"
    NORMAL = "normal"
    LOUD = "loud"
    SIEGE = "siege"


# Cost multipliers per aggression level
_AGGRESSION_MULTIPLIERS: dict[AggressionLevel, float] = {
    AggressionLevel.WHISPER: 2.0,   # Actions cost 2x (stealth-conscious)
    AggressionLevel.NORMAL: 1.0,    # Baseline
    AggressionLevel.LOUD: 0.5,      # Actions cost 0.5x (speed over stealth)
    AggressionLevel.SIEGE: 0.0,     # Infinite budget (no OPSEC)
}

# Delay multipliers per aggression level (applied to inter-request timing)
_DELAY_MULTIPLIERS: dict[AggressionLevel, float] = {
    AggressionLevel.WHISPER: 3.0,   # 3x normal delay between requests
    AggressionLevel.NORMAL: 1.0,    # Baseline timing
    AggressionLevel.LOUD: 0.3,      # 30% of normal delay
    AggressionLevel.SIEGE: 0.0,     # No delays
}

# Concurrency limits per aggression level
_CONCURRENCY_LIMITS: dict[AggressionLevel, int] = {
    AggressionLevel.WHISPER: 1,     # Sequential only
    AggressionLevel.NORMAL: 3,      # Moderate parallelism
    AggressionLevel.LOUD: 5,        # High parallelism
    AggressionLevel.SIEGE: 10,      # Maximum parallelism
}


# Action cost table: action_type -> base cost
ACTION_COSTS: dict[str, float] = {
    # Reconnaissance (low noise)
    "passive_recon": 0.0,
    "dns_lookup": 0.5,
    "port_scan": 3.0,
    "directory_brute": 5.0,
    "subdomain_enum": 2.0,
    # Vulnerability scanning (medium noise)
    "parameter_fuzz": 4.0,
    "auth_test": 3.0,
    "injection_probe": 5.0,
    "xss_probe": 4.0,
    "ssrf_probe": 5.0,
    # Exploitation (high noise)
    "exploit_attempt": 8.0,
    "credential_spray": 10.0,
    "privilege_escalation": 8.0,
    "data_exfiltration": 10.0,
    # Evasion (variable)
    "evasion_retry": 6.0,
    "proxy_rotate": 1.0,
    "session_refresh": 2.0,
}


@dataclass
class BudgetConfig:
    """Configuration for stealth budget."""

    total_budget: float = 100.0
    aggression: AggressionLevel = AggressionLevel.NORMAL
    auto_downgrade: bool = True  # Auto-reduce aggression when budget is low
    low_budget_threshold: float = 0.2  # Downgrade below 20% remaining


@dataclass
class BudgetSpend:
    """Record of a budget spend."""

    action_type: str
    base_cost: float
    actual_cost: float
    remaining: float
    timestamp: float = 0.0


class StealthBudget:
    """
    Tracks and enforces the engagement's noise budget.

    Every action that could trigger detection deducts from the budget.
    The aggression level multiplier affects how much each action costs.
    When the budget is exhausted, the kernel should pause or abort.
    """

    def __init__(self, config: BudgetConfig | None = None) -> None:
        self.config = config or BudgetConfig()
        self._remaining = self.config.total_budget
        self._total_spent = 0.0
        self._spend_log: list[BudgetSpend] = []
        self._original_aggression = self.config.aggression

    @property
    def remaining(self) -> float:
        """Remaining budget points."""
        return self._remaining

    @property
    def remaining_fraction(self) -> float:
        """Remaining budget as a fraction (0.0 - 1.0)."""
        if self.config.total_budget <= 0:
            return 0.0
        return self._remaining / self.config.total_budget

    @property
    def aggression(self) -> AggressionLevel:
        """Current aggression level."""
        return self.config.aggression

    def can_afford(self, action_type: str) -> bool:
        """Check if the budget can afford an action."""
        if self.config.aggression == AggressionLevel.SIEGE:
            return True
        cost = self._compute_cost(action_type)
        return self._remaining >= cost

    def spend(self, action_type: str) -> BudgetSpend:
        """
        Deduct the cost of an action from the budget.

        Returns the spend record. Does not prevent overspending - caller
        should check can_afford() first.
        """
        import time

        base_cost = ACTION_COSTS.get(action_type, 5.0)
        multiplier = _AGGRESSION_MULTIPLIERS[self.config.aggression]
        actual_cost = base_cost * multiplier

        self._remaining = max(0.0, self._remaining - actual_cost)
        self._total_spent += actual_cost

        spend = BudgetSpend(
            action_type=action_type,
            base_cost=base_cost,
            actual_cost=actual_cost,
            remaining=self._remaining,
            timestamp=time.time(),
        )
        self._spend_log.append(spend)

        # Keep log bounded
        if len(self._spend_log) > 500:
            self._spend_log = self._spend_log[-500:]

        logger.debug(
            "opsec.budget_spent",
            action=action_type,
            cost=round(actual_cost, 1),
            remaining=round(self._remaining, 1),
            aggression=self.config.aggression.value,
        )

        # Auto-downgrade aggression if budget is low
        if self.config.auto_downgrade:
            self._maybe_downgrade()

        return spend

    def get_delay_multiplier(self) -> float:
        """Get the delay multiplier for current aggression level."""
        return _DELAY_MULTIPLIERS[self.config.aggression]

    def get_concurrency_limit(self) -> int:
        """Get the concurrency limit for current aggression level."""
        return _CONCURRENCY_LIMITS[self.config.aggression]

    def set_aggression(self, level: AggressionLevel) -> None:
        """Manually set the aggression level."""
        previous = self.config.aggression
        self.config.aggression = level
        if previous != level:
            logger.info(
                "opsec.aggression_changed",
                previous=previous.value,
                current=level.value,
                remaining_budget=round(self._remaining, 1),
            )

    def is_exhausted(self) -> bool:
        """Whether the budget is fully exhausted."""
        if self.config.aggression == AggressionLevel.SIEGE:
            return False
        return self._remaining <= 0.0

    def get_status(self) -> dict[str, Any]:
        """Get current budget status."""
        return {
            "total": self.config.total_budget,
            "remaining": round(self._remaining, 1),
            "remaining_pct": round(self.remaining_fraction * 100, 1),
            "spent": round(self._total_spent, 1),
            "aggression": self.config.aggression.value,
            "concurrency_limit": self.get_concurrency_limit(),
            "delay_multiplier": self.get_delay_multiplier(),
            "is_exhausted": self.is_exhausted(),
            "actions_logged": len(self._spend_log),
        }

    def reset(self) -> None:
        """Reset budget to full."""
        self._remaining = self.config.total_budget
        self._total_spent = 0.0
        self._spend_log.clear()
        self.config.aggression = self._original_aggression

    def _compute_cost(self, action_type: str) -> float:
        """Compute the cost of an action at the current aggression level."""
        base = ACTION_COSTS.get(action_type, 5.0)
        multiplier = _AGGRESSION_MULTIPLIERS[self.config.aggression]
        return base * multiplier

    def _maybe_downgrade(self) -> None:
        """Auto-downgrade aggression when budget runs low."""
        if self.remaining_fraction > self.config.low_budget_threshold:
            return

        current = self.config.aggression
        order = [
            AggressionLevel.SIEGE,
            AggressionLevel.LOUD,
            AggressionLevel.NORMAL,
            AggressionLevel.WHISPER,
        ]

        try:
            idx = order.index(current)
        except ValueError:
            return

        if idx < len(order) - 1:
            new_level = order[idx + 1]
            logger.warning(
                "opsec.auto_downgrade",
                previous=current.value,
                new=new_level.value,
                remaining_pct=round(self.remaining_fraction * 100, 1),
            )
            self.config.aggression = new_level
