"""
HSM Dynamics - Integration with the dynamics layer for learning and analysis.

This module provides:
- HSMStateHasher: Converts HSM state to T1 state IDs for dynamics tracking
- HSMDynamicsLogger: Logs transitions to the dynamics database
- HSMPotentialLookup: Provides V(state) lookup for policy guidance
- HSMMemoryIntegration: Injects patterns from memory layer

The dynamics layer uses these to:
1. Track state transitions for Markov analysis
2. Compute state potentials (expected value to completion)
3. Detect trap states and inefficient paths
4. Learn from historical execution patterns
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from hellcat.core.topology.hsm_schema import (
    CycleState,
    ExecutionTrace,
    HSMStateSnapshot,
    PhaseState,
    StateContext,
    StateSnapshot,
    TaskState,
    TransitionResult,
)

if TYPE_CHECKING:
    from hellcat.cognition.dynamics.transition_db import TransitionDB
    from hellcat.core.topology.cycle import PolicySignals

logger = logging.getLogger(__name__)

__all__ = [
    # State hashing
    "HSMStateHasher",
    # Dynamics logging
    "HSMDynamicsLogger",
    "TransitionRecord",
    "DynamicsDBProtocol",
    "InMemoryDynamicsDB",
    "SQLiteDynamicsDB",
    # Potential lookup
    "HSMPotentialLookup",
    "TrapDetectionConfig",
    # Memory integration
    "HSMMemoryIntegration",
    "MemoryPattern",
    # Factory
    "create_dynamics_integration",
]


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class TrapDetectionConfig:
    """Configuration for trap state detection thresholds."""

    # Potential thresholds
    severe_trap_potential: float = -5.0  # V(state) below this = definite trap
    moderate_trap_potential: float = -2.0  # V(state) below this = possible trap

    # Probability values for potential-based detection
    severe_trap_probability: float = 0.8
    moderate_trap_probability: float = 0.3
    mild_trap_probability: float = 0.1

    # Failure count thresholds
    failure_trap_threshold: int = 3  # consecutive failures to trigger trap detection
    failure_base_probability: float = 0.6
    failure_increment: float = 0.1  # added per additional failure
    failure_max_increment: int = 4  # cap on additional failures counted

    # Stagnation thresholds
    stagnation_trap_threshold: int = 3  # cycles without progress
    stagnation_base_probability: float = 0.4

    # Terminal state potentials
    success_potential: float = 0.0
    abort_potential: float = -10.0


# =============================================================================
# State Hashing
# =============================================================================


class HSMStateHasher:
    """
    Produces T1 state IDs from HSM state.

    The T1 representation captures:
    - Discrete states (task, phase, cycle)
    - Coarse-grained continuous features (bucketed progress, failures)

    This provides a tractable state space for Markov analysis while
    preserving meaningful distinctions.
    """

    def __init__(
        self,
        progress_buckets: int = 10,
        failure_threshold: int = 5,
        cycle_threshold: int = 10,
    ) -> None:
        """
        Initialize the hasher.

        Args:
            progress_buckets: Number of buckets for progress (0.0-1.0)
            failure_threshold: Cap on failure count in state ID
            cycle_threshold: Cap on cycle count in state ID
        """
        self.progress_buckets = progress_buckets
        self.failure_threshold = failure_threshold
        self.cycle_threshold = cycle_threshold

    def hash_state(
        self,
        task_state: TaskState,
        phase_state: PhaseState | None,
        cycle_state: CycleState | None,
        context: StateContext,
    ) -> str:
        """
        Create T1 state ID from current HSM state.

        Format: task:STATE|phase:STATE|cycle:STATE|progress:X|failures:Y|cycles:Z

        Progress is bucketed (0-N) for coarse representation.
        Failures and cycles are capped for state space reduction.

        Args:
            task_state: Current task state
            phase_state: Current phase state (if any)
            cycle_state: Current cycle state (if any)
            context: Execution context with continuous metrics

        Returns:
            State ID string suitable for dynamics DB keys
        """
        parts = [f"task:{task_state.name}"]

        if phase_state is not None:
            parts.append(f"phase:{phase_state.name}")

        if cycle_state is not None:
            parts.append(f"cycle:{cycle_state.name}")

        # Bucket progress (0.0-1.0 -> 0-N)
        progress_bucket = min(
            int(context.phase_progress * self.progress_buckets),
            self.progress_buckets - 1,
        )
        parts.append(f"progress:{progress_bucket}")

        # Cap failures
        failures = min(context.consecutive_failures, self.failure_threshold)
        parts.append(f"failures:{failures}")

        # Cap cycles
        cycles = min(context.cycle_count, self.cycle_threshold)
        parts.append(f"cycles:{cycles}")

        return "|".join(parts)

    def hash_snapshot(self, snapshot: StateSnapshot) -> str:
        """Hash a state snapshot."""
        context = snapshot.context or StateContext(task_id="unknown")
        return self.hash_state(
            snapshot.task_state,
            snapshot.phase_state,
            snapshot.cycle_state,
            context,
        )

    def hash_hsm_snapshot(self, snapshot: HSMStateSnapshot) -> str:
        """Hash an HSM state snapshot."""
        # Create minimal context from snapshot data
        context = StateContext(
            task_id="",
            phase_progress=snapshot.continuous_features.get("progress", 0.0),
            consecutive_failures=int(
                snapshot.continuous_features.get("failures", 0)
            ),
            cycle_count=int(snapshot.continuous_features.get("cycles", 0)),
        )
        return self.hash_state(
            snapshot.task_state,
            snapshot.phase_state,
            snapshot.cycle_state,
            context,
        )

    def get_state_features(
        self,
        task_state: TaskState,
        phase_state: PhaseState | None,
        cycle_state: CycleState | None,
        context: StateContext,
    ) -> dict[str, float]:
        """
        Extract continuous features for dynamics analysis.

        Returns dict suitable for potential fitting and learning.
        """
        features = {
            # Ordinal state values
            "task_ordinal": float(task_state.value),
            "phase_ordinal": float(phase_state.value) if phase_state else 0.0,
            "cycle_ordinal": float(cycle_state.value) if cycle_state else 0.0,
            # Progress metrics
            "phase_progress": context.phase_progress,
            "phase_ratio": context.current_phase_index / max(context.total_phases, 1),
            # Effort metrics
            "cycle_count": float(context.cycle_count),
            "consecutive_failures": float(context.consecutive_failures),
            "cycles_without_progress": float(context.cycles_without_progress),
            # Resource usage
            "tokens_used": float(context.tokens_used),
            "time_elapsed_ms": float(context.time_elapsed_ms),
            "token_budget_ratio": context.tokens_used / max(context.token_budget, 1),
            "time_budget_ratio": context.time_elapsed_ms
            / max(context.time_budget_ms, 1),
        }

        # Terminal state indicators
        features["is_terminal"] = 1.0 if task_state.is_terminal else 0.0
        features["is_success"] = 1.0 if task_state == TaskState.COMPLETE else 0.0
        features["is_failed"] = 1.0 if task_state == TaskState.ABORTED else 0.0

        return features

    def get_compact_hash(
        self,
        task_state: TaskState,
        phase_state: PhaseState | None,
        cycle_state: CycleState | None,
        context: StateContext,
    ) -> str:
        """
        Create a compact MD5 hash of the state.

        Useful for database keys when full state ID is too long.
        """
        full_id = self.hash_state(task_state, phase_state, cycle_state, context)
        return hashlib.md5(full_id.encode()).hexdigest()[:12]


# =============================================================================
# Transition Logging
# =============================================================================


@dataclass
class TransitionRecord:
    """Record of a single HSM transition for dynamics DB."""

    timestamp: datetime
    from_state_id: str
    to_state_id: str
    transition_name: str

    # Context
    action_taken: str  # Policy action that led to this
    outcome: str  # "success", "failure", "timeout", "abort"

    # Metrics
    tokens_used: int
    time_elapsed_ms: int

    # Identification
    task_id: str
    phase_name: str
    phase_index: int
    cycle_index: int

    # Optional signals snapshot
    signals_json: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "from_state_id": self.from_state_id,
            "to_state_id": self.to_state_id,
            "transition_name": self.transition_name,
            "action_taken": self.action_taken,
            "outcome": self.outcome,
            "tokens_used": self.tokens_used,
            "time_elapsed_ms": self.time_elapsed_ms,
            "task_id": self.task_id,
            "phase_name": self.phase_name,
            "phase_index": self.phase_index,
            "cycle_index": self.cycle_index,
            "signals_json": self.signals_json,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TransitionRecord:
        """Create from dictionary."""
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            from_state_id=data["from_state_id"],
            to_state_id=data["to_state_id"],
            transition_name=data["transition_name"],
            action_taken=data["action_taken"],
            outcome=data["outcome"],
            tokens_used=data["tokens_used"],
            time_elapsed_ms=data["time_elapsed_ms"],
            task_id=data["task_id"],
            phase_name=data["phase_name"],
            phase_index=data["phase_index"],
            cycle_index=data["cycle_index"],
            signals_json=data.get("signals_json"),
        )


class DynamicsDBProtocol(Protocol):
    """Protocol for dynamics database access."""

    def log_transition(self, record: TransitionRecord) -> None:
        """Log a transition to the database."""
        ...

    def get_potential(self, state_id: str) -> float | None:
        """Get V(state) for a state ID."""
        ...

    def get_transition_count(self, from_id: str, to_id: str) -> int:
        """Get count of transitions between states."""
        ...

    def get_transition_probability(self, from_id: str, to_id: str) -> float:
        """Get P(to|from) transition probability."""
        ...


class InMemoryDynamicsDB:
    """Simple in-memory implementation of DynamicsDBProtocol for testing."""

    def __init__(self) -> None:
        self.transitions: list[TransitionRecord] = []
        self.potentials: dict[str, float] = {}
        self._transition_counts: dict[tuple[str, str], int] = {}

    def log_transition(self, record: TransitionRecord) -> None:
        """Log a transition."""
        self.transitions.append(record)
        key = (record.from_state_id, record.to_state_id)
        self._transition_counts[key] = self._transition_counts.get(key, 0) + 1

    def get_potential(self, state_id: str) -> float | None:
        """Get V(state)."""
        return self.potentials.get(state_id)

    def set_potential(self, state_id: str, value: float) -> None:
        """Set V(state)."""
        self.potentials[state_id] = value

    def get_transition_count(self, from_id: str, to_id: str) -> int:
        """Get transition count."""
        return self._transition_counts.get((from_id, to_id), 0)

    def get_transition_probability(self, from_id: str, to_id: str) -> float:
        """Get transition probability with Laplace smoothing."""
        count = self.get_transition_count(from_id, to_id)
        total = sum(
            c for (f, _), c in self._transition_counts.items() if f == from_id
        )
        if total == 0:
            return 0.0
        # Laplace smoothing
        return (count + 1) / (total + len(self._transition_counts))


class SQLiteDynamicsDB:
    """DynamicsDBProtocol adapter wrapping the existing TransitionDB from cognition.dynamics."""

    def __init__(self, transition_db: TransitionDB) -> None:
        from hellcat.cognition.dynamics.transition_db import TransitionDB as _TDBCls  # noqa: N811

        self._db: _TDBCls = transition_db

    def log_transition(self, record: TransitionRecord) -> None:
        """Convert TransitionRecord to the dict format TransitionDB.insert_transition() expects."""
        ts = record.timestamp.isoformat()
        self._db.insert_transition({
            "transition_id": f"{record.task_id}_{record.cycle_index}_{ts}",
            "from_state": {
                "state_id": record.from_state_id,
                "domain": record.phase_name,
                "job_type": "hsm",
            },
            "to_state": {
                "state_id": record.to_state_id,
                "domain": record.phase_name,
                "job_type": "hsm",
            },
            "transition_kind": record.transition_name,
            "timestamp": record.timestamp.isoformat(),
            "action_label": {
                "tool": record.action_taken,
                "command_class": "hsm",
                "domain": record.phase_name,
            },
            "context": {
                "issue_id": record.task_id,
                "workcell_id": f"wc-{record.task_id}",
            },
        })
        self._db.conn.commit()

    def get_potential(self, state_id: str) -> float | None:
        """Get V(state) from the potentials table."""
        return self._db.get_potential(state_id)

    def set_potential(self, state_id: str, value: float) -> None:
        """Persist V(state) to the potentials table."""
        self._db.set_potential(state_id, value)

    def get_transition_count(self, from_id: str, to_id: str) -> int:
        """Query transition count directly from the SQLite transitions table."""
        row = self._db.conn.execute(
            "SELECT COUNT(*) as cnt FROM transitions WHERE from_state = ? AND to_state = ?",
            (from_id, to_id),
        ).fetchone()
        return row["cnt"] if row else 0

    def get_transition_probability(self, from_id: str, to_id: str) -> float:
        """Compute P(to|from) with Laplace smoothing."""
        count = self.get_transition_count(from_id, to_id)
        total_row = self._db.conn.execute(
            "SELECT COUNT(*) as cnt FROM transitions WHERE from_state = ?",
            (from_id,),
        ).fetchone()
        total = total_row["cnt"] if total_row else 0
        if total == 0:
            return 0.0
        # Laplace smoothing: (count + 1) / (total + 2)
        return (count + 1) / (total + 2)


class HSMDynamicsLogger:
    """
    Logs HSM execution to dynamics layer.

    Records every transition with context, enabling:
    - Transition probability estimation
    - Potential function fitting
    - Pattern analysis
    """

    def __init__(
        self,
        hasher: HSMStateHasher,
        db: DynamicsDBProtocol | None = None,
        log_file: Path | None = None,
    ) -> None:
        """
        Initialize the logger.

        Args:
            hasher: State hasher for creating state IDs
            db: Database for persistent logging (optional)
            log_file: JSONL file for transition logging (optional)
        """
        self.hasher = hasher
        self.db = db
        self.log_file = log_file
        self._pending_records: list[TransitionRecord] = []
        self._session_start = datetime.now(UTC)

    def log_transition(
        self,
        from_snapshot: HSMStateSnapshot,
        to_snapshot: HSMStateSnapshot,
        transition_name: str,
        context: StateContext,
        action_taken: str = "",
        outcome: str = "success",
        signals: PolicySignals | None = None,
    ) -> TransitionRecord:
        """
        Log a transition between HSM states.

        Args:
            from_snapshot: State before transition
            to_snapshot: State after transition
            transition_name: Name of the transition
            context: Current execution context
            action_taken: Policy action that triggered this
            outcome: Outcome of the transition
            signals: Optional policy signals to record

        Returns:
            The created TransitionRecord
        """
        from_id = self.hasher.hash_hsm_snapshot(from_snapshot)
        to_id = self.hasher.hash_hsm_snapshot(to_snapshot)

        # Serialize signals if provided
        signals_json = None
        if signals is not None:
            signals_dict = {
                "phase_completion": signals.phase_completion,
                "consecutive_failures": signals.consecutive_failures,
                "cycles_without_progress": signals.cycles_without_progress,
                "trap_probability": signals.trap_probability,
            }
            signals_json = json.dumps(signals_dict)

        record = TransitionRecord(
            timestamp=datetime.now(UTC),
            from_state_id=from_id,
            to_state_id=to_id,
            transition_name=transition_name,
            action_taken=action_taken,
            outcome=outcome,
            tokens_used=context.tokens_used,
            time_elapsed_ms=context.time_elapsed_ms,
            task_id=context.task_id,
            phase_name=context.current_phase_name,
            phase_index=context.current_phase_index,
            cycle_index=context.cycle_count,
            signals_json=signals_json,
        )

        # Log to DB if available
        if self.db is not None:
            self.db.log_transition(record)
        else:
            self._pending_records.append(record)

        # Log to file if available
        if self.log_file is not None:
            self._write_to_file(record)

        logger.debug(
            f"Logged transition: {from_id[:20]}... -> {to_id[:20]}... ({transition_name})"
        )

        return record

    def log_transition_result(
        self,
        result: TransitionResult,
        context: StateContext,
        action_taken: str = "",
    ) -> TransitionRecord | None:
        """
        Log a TransitionResult (convenience method).

        Only logs successful transitions.
        """
        if not result.success or result.to_state is None:
            return None

        # Create snapshots from result
        from_snapshot = HSMStateSnapshot(
            state_path=result.from_state.name,
            task_state=TaskState.RUNNING,  # Assume running if transitioning
            phase_state=result.from_state
            if isinstance(result.from_state, PhaseState)
            else None,
            cycle_state=result.from_state
            if isinstance(result.from_state, CycleState)
            else None,
            continuous_features={
                "progress": context.phase_progress,
                "failures": float(context.consecutive_failures),
                "cycles": float(context.cycle_count),
            },
        )

        to_snapshot = HSMStateSnapshot(
            state_path=result.to_state.name,
            task_state=TaskState.RUNNING,
            phase_state=result.to_state
            if isinstance(result.to_state, PhaseState)
            else None,
            cycle_state=result.to_state
            if isinstance(result.to_state, CycleState)
            else None,
            continuous_features={
                "progress": context.phase_progress,
                "failures": float(context.consecutive_failures),
                "cycles": float(context.cycle_count),
            },
        )

        return self.log_transition(
            from_snapshot=from_snapshot,
            to_snapshot=to_snapshot,
            transition_name=result.transition_name or "unknown",
            context=context,
            action_taken=action_taken,
        )

    def _write_to_file(self, record: TransitionRecord) -> None:
        """Write record to JSONL file."""
        if self.log_file is None:
            return

        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_file, "a") as f:
            f.write(json.dumps(record.to_dict()) + "\n")

    def flush_to_db(self, db: DynamicsDBProtocol) -> int:
        """Flush pending records to database."""
        count = len(self._pending_records)
        for record in self._pending_records:
            db.log_transition(record)
        self._pending_records.clear()
        logger.info(f"Flushed {count} transition records to database")
        return count

    def get_pending_count(self) -> int:
        """Get count of pending (unflushed) records."""
        return len(self._pending_records)

    def get_session_records(self) -> list[TransitionRecord]:
        """Get all records from current session."""
        return self._pending_records.copy()


# =============================================================================
# Potential Lookup
# =============================================================================


class HSMPotentialLookup:
    """
    Provides V(state) lookup for policy guidance.

    V(state) represents the expected "distance" to successful completion.
    - V = 0 for terminal success states
    - V < 0 for non-terminal states (depth in potential well)
    - V << 0 for trap states (hard to escape)

    The potential function is computed offline from transition data
    using graph Laplacian methods.
    """

    def __init__(
        self,
        hasher: HSMStateHasher,
        db: DynamicsDBProtocol | None = None,
        default_potential: float = 0.0,
        cache_size: int = 1000,
        trap_config: TrapDetectionConfig | None = None,
    ) -> None:
        """
        Initialize the lookup.

        Args:
            hasher: State hasher for creating state IDs
            db: Database for potential lookup
            default_potential: Default V(state) when not in DB
            cache_size: Maximum cache entries
            trap_config: Configuration for trap detection thresholds
        """
        self.hasher = hasher
        self.db = db
        self.default_potential = default_potential
        self._cache: dict[str, float] = {}
        self._cache_size = cache_size
        self.trap_config = trap_config or TrapDetectionConfig()

    def get_potential(
        self,
        task_state: TaskState,
        phase_state: PhaseState | None,
        cycle_state: CycleState | None,
        context: StateContext,
    ) -> float:
        """
        Get V(state) for current HSM state.

        Args:
            task_state: Current task state
            phase_state: Current phase state
            cycle_state: Current cycle state
            context: Execution context

        Returns:
            Potential value (higher is better, 0 = terminal success)
        """
        # Terminal states have known potentials
        if task_state == TaskState.COMPLETE:
            return self.trap_config.success_potential
        if task_state == TaskState.ABORTED:
            return self.trap_config.abort_potential

        state_id = self.hasher.hash_state(
            task_state, phase_state, cycle_state, context
        )

        # Check cache
        if state_id in self._cache:
            return self._cache[state_id]

        # Query DB
        potential = self.default_potential
        if self.db is not None:
            db_potential = self.db.get_potential(state_id)
            if db_potential is not None:
                potential = db_potential

        # Cache result
        self._update_cache(state_id, potential)

        return potential

    def get_potential_by_id(self, state_id: str) -> float:
        """Get V(state) by state ID directly."""
        if state_id in self._cache:
            return self._cache[state_id]

        if self.db is not None:
            potential = self.db.get_potential(state_id)
            if potential is not None:
                self._update_cache(state_id, potential)
                return potential

        return self.default_potential

    def get_transition_value(
        self,
        from_state_id: str,
        to_state_id: str,
    ) -> float:
        """
        Get expected value of a transition.

        Returns V(to) - V(from), which is positive for "uphill" transitions
        toward the goal.
        """
        from_v = self.get_potential_by_id(from_state_id)
        to_v = self.get_potential_by_id(to_state_id)
        return to_v - from_v

    def estimate_trap_probability(
        self,
        task_state: TaskState,
        phase_state: PhaseState | None,
        cycle_state: CycleState | None,
        context: StateContext,
    ) -> float:
        """
        Estimate probability of being in a trap state.

        Uses potential value and failure count heuristics.
        All thresholds are configurable via TrapDetectionConfig.
        """
        cfg = self.trap_config
        potential = self.get_potential(
            task_state, phase_state, cycle_state, context
        )

        # Low potential indicates trap
        if potential < cfg.severe_trap_potential:
            return cfg.severe_trap_probability

        # Many failures without progress
        if context.consecutive_failures >= cfg.failure_trap_threshold:
            extra_failures = context.consecutive_failures - cfg.failure_trap_threshold
            capped_extra = min(extra_failures, cfg.failure_max_increment)
            return cfg.failure_base_probability + cfg.failure_increment * capped_extra

        # Many cycles without progress
        if context.cycles_without_progress >= cfg.stagnation_trap_threshold:
            extra_stagnation = context.cycles_without_progress - cfg.stagnation_trap_threshold
            capped_extra = min(extra_stagnation, cfg.failure_max_increment)
            return cfg.stagnation_base_probability + cfg.failure_increment * capped_extra

        # Default based on potential
        if potential < cfg.moderate_trap_potential:
            return cfg.moderate_trap_probability
        if potential < 0.0:
            return cfg.mild_trap_probability

        return 0.0

    def _update_cache(self, state_id: str, potential: float) -> None:
        """Update cache, evicting oldest if full."""
        if len(self._cache) >= self._cache_size:
            # Simple FIFO eviction (could use LRU)
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        self._cache[state_id] = potential

    def preload_from_db(self, state_ids: list[str]) -> int:
        """Preload potentials for a list of state IDs."""
        if self.db is None:
            return 0

        count = 0
        for state_id in state_ids:
            potential = self.db.get_potential(state_id)
            if potential is not None:
                self._update_cache(state_id, potential)
                count += 1

        return count

    def invalidate_cache(self) -> None:
        """Clear the potential cache."""
        self._cache.clear()


# =============================================================================
# Memory Integration
# =============================================================================


@dataclass
class MemoryPattern:
    """Pattern retrieved from memory layer."""

    pattern_id: str
    summary: str
    relevance: float  # 0.0 - 1.0
    tags: list[str] = field(default_factory=list)
    domain: str = ""
    source_block: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class MemoryDBProtocol(Protocol):
    """Protocol for memory database access."""

    def search_patterns(
        self,
        tags: list[str],
        domain: str,
        block_types: list[str],
        limit: int,
    ) -> list[MemoryPattern]:
        """Search for relevant patterns."""
        ...

    def store_observation(self, observation: dict[str, Any]) -> None:
        """Store an execution observation."""
        ...


class HSMMemoryIntegration:
    """
    Integrates HSM with the memory layer.

    Provides:
    - Pattern injection on PREPARE state entry
    - Learning feedback on terminal states
    """

    def __init__(
        self,
        memory_db: MemoryDBProtocol | None = None,
        max_patterns: int = 5,
        relevance_threshold: float = 0.5,
    ) -> None:
        """
        Initialize memory integration.

        Args:
            memory_db: Memory database (optional)
            max_patterns: Maximum patterns to inject per phase
            relevance_threshold: Minimum relevance score for patterns
        """
        self.memory_db = memory_db
        self.max_patterns = max_patterns
        self.relevance_threshold = relevance_threshold

    def inject_patterns(
        self,
        context: StateContext,
        tags: list[str] | None = None,
        domain: str = "",
    ) -> list[MemoryPattern]:
        """
        Query memory for relevant patterns and inject into context.

        Called on PREPARE state entry.

        Args:
            context: Execution context to inject into
            tags: Tags to search for (default: from context)
            domain: Domain to search in

        Returns:
            List of injected patterns
        """
        if self.memory_db is None:
            return []

        # Use tags from context if not provided
        if tags is None:
            tags = context.get_data("task_tags", [])

        # Search for patterns
        patterns = self.memory_db.search_patterns(
            tags=tags,
            domain=domain,
            block_types=["successful_chains", "failure_modes", "repair_strategies"],
            limit=self.max_patterns * 2,  # Get more, filter by relevance
        )

        # Filter by relevance
        patterns = [p for p in patterns if p.relevance >= self.relevance_threshold]
        patterns = patterns[: self.max_patterns]

        # Inject into context
        context.memory_hints = [
            {
                "pattern": p.summary,
                "relevance": p.relevance,
                "source": p.source_block,
                "tags": p.tags,
            }
            for p in patterns
        ]

        logger.debug(f"Injected {len(patterns)} patterns into context")
        return patterns

    def extract_observation(
        self,
        context: StateContext,
        trace: ExecutionTrace,
        outcome: str,
    ) -> dict[str, Any]:
        """
        Extract an observation from execution for memory consolidation.

        Called on terminal states (COMPLETE or FAILED).

        Args:
            context: Final execution context
            trace: Execution trace
            outcome: "success" or "failure"

        Returns:
            Observation dict for memory consolidator
        """
        # Extract tool sequence from trace
        tool_sequence = [
            t.transition_name for t in trace.transitions if t.transition_name
        ]

        # Extract state path
        state_path = [s.state_path() for s in trace.snapshots]

        observation = {
            "task_id": context.task_id,
            "outcome": outcome,
            "tool_sequence": tool_sequence,
            "state_path": state_path,
            "duration_ms": trace.total_time_ms,
            "tokens_used": trace.total_tokens,
            "total_cycles": trace.total_cycles,
            "phases_completed": len(trace.cycles_per_phase),
            "tags": context.get_data("task_tags", []),
            "domain": context.get_data("task_domain", ""),
            "working_approaches": context.working_approaches,
            "failed_approaches": context.failed_approaches,
            "key_findings": context.key_findings,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        return observation

    def store_observation(
        self,
        context: StateContext,
        trace: ExecutionTrace,
        outcome: str,
    ) -> None:
        """
        Store an execution observation in memory.

        Args:
            context: Final execution context
            trace: Execution trace
            outcome: "success" or "failure"
        """
        if self.memory_db is None:
            logger.debug("No memory DB, skipping observation storage")
            return

        observation = self.extract_observation(context, trace, outcome)
        self.memory_db.store_observation(observation)
        logger.debug(f"Stored observation for task {context.task_id}")


# =============================================================================
# Factory Function
# =============================================================================


def create_dynamics_integration(
    db: DynamicsDBProtocol | None = None,
    memory_db: MemoryDBProtocol | None = None,
    log_file: Path | None = None,
    progress_buckets: int = 10,
    max_patterns: int = 5,
) -> tuple[HSMStateHasher, HSMDynamicsLogger, HSMPotentialLookup, HSMMemoryIntegration]:
    """
    Create a complete dynamics integration setup.

    Returns tuple of (hasher, logger, potential_lookup, memory_integration).
    """
    hasher = HSMStateHasher(progress_buckets=progress_buckets)
    dynamics_logger = HSMDynamicsLogger(hasher, db, log_file)
    potential_lookup = HSMPotentialLookup(hasher, db)
    memory_integration = HSMMemoryIntegration(memory_db, max_patterns=max_patterns)

    return hasher, dynamics_logger, potential_lookup, memory_integration
