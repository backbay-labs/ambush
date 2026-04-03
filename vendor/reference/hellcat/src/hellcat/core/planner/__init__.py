"""
Attack planner for Hellcat Kernel.

Scores and schedules ANALYZED vulnerability nodes for exploitation,
respecting OPSEC constraints from the noise monitor, stealth budget,
and circuit breaker.

Planning cycle:
1. Compute ready set (ANALYZED, unblocked nodes)
2. Find critical exploit chains
3. Score and rank attacks
4. Apply OPSEC constraints (noise, budget, circuit state)
5. Pack into concurrency slots
6. Return AttackPlan
"""

from hellcat.core.planner.chain_analyzer import ChainAnalyzer, ExploitChain
from hellcat.core.planner.dispatch import CellOutcome, DispatchResult, PlannerDispatcher
from hellcat.core.planner.planner import AttackPlan, AttackPlanner
from hellcat.core.planner.scorer import AttackScorer, ScoredAttack

__all__ = [
    "AttackPlan",
    "AttackPlanner",
    "AttackScorer",
    "CellOutcome",
    "ChainAnalyzer",
    "DispatchResult",
    "ExploitChain",
    "PlannerDispatcher",
    "ScoredAttack",
]
