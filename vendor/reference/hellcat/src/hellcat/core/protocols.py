"""
Protocol interfaces for cognition layer dependencies.

Defines structural typing contracts so that core/ modules can type-hint
against capabilities rather than concrete cognition classes.  The actual
cognition implementations (TransitionDB, DomainProfileStore,
SleeptimeOrchestrator, MemoryHooks) satisfy these protocols via
structural subtyping -- no explicit inheritance required.

Usage in core/:
    from hellcat.core.protocols import DynamicsProvider, StrategyProfileProvider

    class Scheduler:
        def __init__(self, dynamics: DynamicsProvider | None = None): ...
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Protocol

# ---------------------------------------------------------------------------
# DynamicsProvider -- what core/ needs from cognition.dynamics.transition_db
# ---------------------------------------------------------------------------


class DynamicsProvider(Protocol):
    """Read/write access to the dynamics transition database.

    Satisfied by ``hellcat.cognition.dynamics.transition_db.TransitionDB``.

    The protocol intentionally exposes ``conn`` and ``db_path`` because
    several core/ call-sites execute raw SQL (scheduler trap check,
    circuit-breaker trap load, speculation synthesis).  A future cleanup
    may replace those with dedicated methods, at which point ``conn``
    can be removed from the protocol.
    """

    conn: sqlite3.Connection
    db_path: Path

    def close(self) -> None: ...

    # Transition CRUD
    def insert_transition(self, transition: dict[str, Any]) -> str: ...

    # Trap introspection
    def get_trap_state_ids(self) -> set[str]: ...

    # Strategy profile helpers (used by StrategyIntegration)
    def insert_profile(self, profile: Any, outcome: str) -> str: ...

    def get_optimal_strategy_for(
        self,
        toolchain: str | None = None,
        outcome: str = "success",
        min_confidence: float = 0.5,
    ) -> dict[str, str]: ...

    def get_dimension_distribution(
        self,
        dimension_id: str,
        toolchain: str | None = None,
        outcome: str | None = None,
    ) -> dict[str, int]: ...

    def profile_count(self) -> int: ...


# ---------------------------------------------------------------------------
# StrategyProfileProvider -- what core/ needs from cognition.strategy.profiles
# ---------------------------------------------------------------------------


class StrategyProfileProvider(Protocol):
    """Domain-level strategy profiles for scheduling and token estimation.

    Satisfied by ``hellcat.cognition.strategy.profiles.DomainProfileStore``.
    """

    def estimate_tokens(self, domain: str, issue_type: str) -> int | None:
        """Return estimated token count for a domain/issue_type pair, or None."""
        ...

    def rebuild(self) -> int:
        """Rebuild profiles from underlying data.  Returns count of profiles."""
        ...

    def all_profiles(self) -> list[Any]:
        """Return all cached profiles."""
        ...


# ---------------------------------------------------------------------------
# SleeptimeProvider -- what core/ needs from cognition.sleeptime
# ---------------------------------------------------------------------------


class SleeptimeProvider(Protocol):
    """Background consolidation orchestrator contract.

    Satisfied by ``hellcat.cognition.sleeptime.orchestrator.SleeptimeOrchestrator``.
    """

    def should_trigger(self) -> bool:
        """Return True when consolidation thresholds are met."""
        ...

    def consolidate(self) -> Any:
        """Run the full consolidation pipeline.  Returns a ConsolidationResult."""
        ...

    def on_workcell_complete(self, success: bool) -> Any | None:
        """Record a workcell completion; may trigger consolidation."""
        ...

    def get_learned_context(
        self, block_names: list[str] | None = None
    ) -> dict[str, str]:
        """Read learned-context blocks for prompt injection."""
        ...

    def notify_ralph(self, ralph_integration: Any, result: Any) -> None:
        """Notify Ralph integration of a consolidation result."""
        ...


# ---------------------------------------------------------------------------
# MemoryProvider -- what core/ needs from cognition.memory
# ---------------------------------------------------------------------------


class MemoryProvider(Protocol):
    """Agent memory hooks for the workcell lifecycle.

    Satisfied by ``hellcat.cognition.memory.hooks.MemoryHooks``.
    """

    def workcell_start(
        self,
        workcell_id: str,
        issue_id: str,
        issue_title: str,
        *,
        tags: list[str] | None = None,
        manifest: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Called at workcell start; returns context dict for the agent."""
        ...

    def tool_use(
        self,
        tool: str,
        content: str,
        *,
        outcome: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record a tool invocation observation."""
        ...

    def gate_result(
        self,
        gate: str,
        passed: bool,
        *,
        details: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record a quality-gate result observation."""
        ...

    def workcell_end(self, status: str) -> dict[str, Any]:
        """Called at workcell end; returns session summary."""
        ...

    def close(self) -> None:
        """Release resources."""
        ...
