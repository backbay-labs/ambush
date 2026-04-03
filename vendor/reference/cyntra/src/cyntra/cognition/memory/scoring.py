"""
Memory importance scoring.

This module provides a simple, run-based scoring model for ranking memories and
estimating decay. The intent is to keep the logic lightweight and testable while
still capturing the main signals:

- Value: how often a memory is accessed
- Hubness: how connected it is to other memories
- Mentions: explicit agent/LLM references
- Recency: how recently it was accessed (run-count based)
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from uuid import UUID

from .models import AgentMemory


@dataclass(frozen=True)
class ScoringConstants:
    """Tunable constants for importance scoring."""

    value_weight: float = 0.35
    hub_weight: float = 0.25
    mention_weight: float = 0.20
    recency_weight: float = 0.20

    # Exponential decay rate per run (used for recency and decay estimation)
    decay_rate: float = 0.03

    # New memories get a temporary boost that decays over `newness_runs`
    newness_bonus: float = 0.20
    newness_runs: int = 5


DEFAULT_CONSTANTS = ScoringConstants()


def calculate_importance(
    memory: AgentMemory,
    current_runs: int,
    inbound_links: int = 0,
    outbound_links: int = 0,
    constants: ScoringConstants = DEFAULT_CONSTANTS,
) -> float:
    """
    Calculate memory importance score (0..1).

    Args:
        memory: Memory to score
        current_runs: Current run count for the agent
        inbound_links: Number of inbound links (hub signal)
        outbound_links: Number of outbound links (hub signal)
        constants: Scoring constants

    Returns:
        Importance score bounded to [0.0, 1.0]
    """
    # Value signal: saturating curve over access_count
    value_signal = 1.0 - math.exp(-max(0, memory.access_count) / 5.0)

    # Hub signal: saturating curve over total links
    link_count = max(0, inbound_links + outbound_links)
    hub_signal = 1.0 - math.exp(-link_count / 10.0)

    # Mention signal: saturating curve over mention_count
    mention_signal = 1.0 - math.exp(-max(0, memory.mention_count) / 3.0)

    # Recency signal: exponential decay over runs since last access
    runs_at_last_access = memory.runs_at_last_access
    if runs_at_last_access is None:
        runs_at_last_access = memory.runs_at_creation or 0
    runs_since_access = max(0, current_runs - (runs_at_last_access or 0))
    recency_signal = math.exp(-constants.decay_rate * float(runs_since_access))

    score = (
        constants.value_weight * value_signal
        + constants.hub_weight * hub_signal
        + constants.mention_weight * mention_signal
        + constants.recency_weight * recency_signal
    )

    # Newness bonus (linearly decays across the newness window)
    runs_at_creation = memory.runs_at_creation or 0
    runs_since_creation = max(0, current_runs - runs_at_creation)
    if runs_since_creation <= constants.newness_runs and constants.newness_runs > 0:
        fade = 1.0 - (runs_since_creation / float(constants.newness_runs))
        score += constants.newness_bonus * max(0.0, fade)

    # Confidence scales score (keeps bounds)
    score *= max(0.0, min(1.0, memory.confidence))

    return max(0.0, min(1.0, score))


def estimate_decay_time(
    current_importance: float,
    target_importance: float = 0.1,
    decay_rate: float | None = None,
    constants: ScoringConstants = DEFAULT_CONSTANTS,
) -> int:
    """
    Estimate runs until `current_importance` decays to `target_importance`.

    Uses exponential decay: importance(t) = current * exp(-decay_rate * t)
    """
    if current_importance <= target_importance:
        return 0

    rate = constants.decay_rate if decay_rate is None else decay_rate
    if rate <= 0:
        return 0

    runs = math.log(target_importance / current_importance) / (-rate)
    return max(0, int(math.ceil(runs)))


async def recalculate_all_scores(
    store,  # MemoryStore
    agent_id: str,
) -> int:
    """Bulk score recalculation for sleeptime (delegated to SQL)."""
    return await store.recalculate_scores(agent_id)


async def get_archival_candidates(
    store,  # MemoryStore
    agent_id: str,
    threshold: float = 0.1,
    limit: int = 100,
) -> list[UUID]:
    """Find memories below archival threshold (delegated to SQL)."""
    return await store.get_archival_candidates(agent_id, threshold, limit)
