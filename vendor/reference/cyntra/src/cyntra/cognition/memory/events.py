"""
Domain events for Cyntra Agent Memory System.

Immutable event objects representing state changes in the memory system.
Adapted from Mira OS's event architecture for agent swarm context.

Event flow:
1. RunCompletedEvent → triggers extraction
2. MemoryExtractionEvent → extraction started
3. MemoryLinkingEvent → linking started after extraction
4. PatternDiscoveredEvent → new pattern identified
5. DynamicLearnedEvent → behavioral observation captured
6. MemoryConsolidatedEvent → memories merged during sleeptime
7. PatternPromotedEvent → individual pattern promoted to collective
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4


def utc_now() -> datetime:
    """Get current UTC timestamp."""
    return datetime.utcnow()


@dataclass(frozen=True, kw_only=True)
class MemoryEvent:
    """Base class for all memory system events."""

    agent_id: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=utc_now)
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def event_type(self) -> str:
        """Get event type from class name."""
        # Convert CamelCase to snake_case
        name = self.__class__.__name__
        if name.endswith("Event"):
            name = name[:-5]  # Remove "Event" suffix
        # Convert CamelCase to snake_case
        result = []
        for i, char in enumerate(name):
            if char.isupper() and i > 0:
                result.append("_")
            result.append(char.lower())
        return "".join(result)


# ============================================================================
# Run Lifecycle Events
# ============================================================================


@dataclass(frozen=True)
class RunCompletedEvent(MemoryEvent):
    """
    Agent run completed - triggers memory extraction.

    Published by kernel runner when workcell execution finishes.
    Carries run transcript and metadata for extraction pipeline.
    """

    run_id: str
    workcell_id: str
    issue_id: str | None
    world_id: str | None  # Fab World context if applicable

    # Run outcome
    status: str  # success, failed, timeout
    patch_applied: bool
    gates_passed: bool

    # Run transcript for extraction
    transcript: str  # Full conversation transcript
    tool_calls: list[dict[str, Any]]  # Tool usage history
    file_changes: list[str]  # Files modified

    # Metadata
    issue_tags: list[str]
    duration_seconds: float
    token_count: int

    @classmethod
    def create(
        cls,
        agent_id: str,
        run_id: str,
        workcell_id: str,
        issue_id: str | None,
        world_id: str | None,
        status: str,
        patch_applied: bool,
        gates_passed: bool,
        transcript: str,
        tool_calls: list[dict[str, Any]],
        file_changes: list[str],
        issue_tags: list[str],
        duration_seconds: float,
        token_count: int,
    ) -> "RunCompletedEvent":
        """Create run completed event with auto-generated metadata."""
        return cls(
            agent_id=agent_id,
            event_id=str(uuid4()),
            occurred_at=utc_now(),
            run_id=run_id,
            workcell_id=workcell_id,
            issue_id=issue_id,
            world_id=world_id,
            status=status,
            patch_applied=patch_applied,
            gates_passed=gates_passed,
            transcript=transcript,
            tool_calls=tool_calls,
            file_changes=file_changes,
            issue_tags=issue_tags,
            duration_seconds=duration_seconds,
            token_count=token_count,
        )


# ============================================================================
# Extraction Events
# ============================================================================


@dataclass(frozen=True)
class MemoryExtractionEvent(MemoryEvent):
    """
    Memory extraction started for a completed run.

    Published when extraction pipeline begins processing run transcript.
    """

    run_id: str
    batch_id: str  # Extraction batch identifier
    memory_count_estimate: int

    @classmethod
    def create(
        cls,
        agent_id: str,
        run_id: str,
        batch_id: str,
        memory_count_estimate: int,
    ) -> "MemoryExtractionEvent":
        """Create extraction event."""
        return cls(
            agent_id=agent_id,
            event_id=str(uuid4()),
            occurred_at=utc_now(),
            run_id=run_id,
            batch_id=batch_id,
            memory_count_estimate=memory_count_estimate,
        )


@dataclass(frozen=True)
class MemoryLinkingEvent(MemoryEvent):
    """
    Memory linking started after extraction.

    Published when relationship classification begins for newly extracted memories.
    """

    memory_ids: list[UUID]
    batch_id: str
    pair_count: int  # Number of memory pairs to classify

    @classmethod
    def create(
        cls,
        agent_id: str,
        memory_ids: list[UUID],
        batch_id: str,
        pair_count: int,
    ) -> "MemoryLinkingEvent":
        """Create linking event."""
        return cls(
            agent_id=agent_id,
            event_id=str(uuid4()),
            occurred_at=utc_now(),
            memory_ids=memory_ids,
            batch_id=batch_id,
            pair_count=pair_count,
        )


# ============================================================================
# Discovery Events
# ============================================================================


@dataclass(frozen=True)
class PatternDiscoveredEvent(MemoryEvent):
    """
    New pattern discovered and stored.

    Published when a successful pattern is extracted from run analysis.
    """

    memory_id: UUID
    pattern_text: str
    confidence: float
    issue_tags: list[str]
    success_context: dict[str, Any]  # What made this work

    @classmethod
    def create(
        cls,
        agent_id: str,
        memory_id: UUID,
        pattern_text: str,
        confidence: float,
        issue_tags: list[str],
        success_context: dict[str, Any],
    ) -> "PatternDiscoveredEvent":
        """Create pattern discovered event."""
        return cls(
            agent_id=agent_id,
            event_id=str(uuid4()),
            occurred_at=utc_now(),
            memory_id=memory_id,
            pattern_text=pattern_text,
            confidence=confidence,
            issue_tags=issue_tags,
            success_context=success_context,
        )


@dataclass(frozen=True)
class DynamicLearnedEvent(MemoryEvent):
    """
    Behavioral dynamic learned from observation.

    Published when dynamics analysis identifies a behavioral pattern.
    """

    memory_id: UUID
    dynamic_text: str
    confidence: float
    sample_size: int  # Number of observations supporting this dynamic
    conditions: dict[str, Any]  # When this dynamic applies

    @classmethod
    def create(
        cls,
        agent_id: str,
        memory_id: UUID,
        dynamic_text: str,
        confidence: float,
        sample_size: int,
        conditions: dict[str, Any],
    ) -> "DynamicLearnedEvent":
        """Create dynamic learned event."""
        return cls(
            agent_id=agent_id,
            event_id=str(uuid4()),
            occurred_at=utc_now(),
            memory_id=memory_id,
            dynamic_text=dynamic_text,
            confidence=confidence,
            sample_size=sample_size,
            conditions=conditions,
        )


# ============================================================================
# Refinement Events
# ============================================================================


@dataclass(frozen=True)
class MemoryConsolidatedEvent(MemoryEvent):
    """
    Similar memories consolidated into single memory.

    Published during sleeptime processing when similar memories are merged.
    """

    new_memory_id: UUID
    consolidated_ids: list[UUID]
    similarity_score: float
    token_savings: int  # Tokens saved by consolidation

    @classmethod
    def create(
        cls,
        agent_id: str,
        new_memory_id: UUID,
        consolidated_ids: list[UUID],
        similarity_score: float,
        token_savings: int,
    ) -> "MemoryConsolidatedEvent":
        """Create consolidation event."""
        return cls(
            agent_id=agent_id,
            event_id=str(uuid4()),
            occurred_at=utc_now(),
            new_memory_id=new_memory_id,
            consolidated_ids=consolidated_ids,
            similarity_score=similarity_score,
            token_savings=token_savings,
        )


@dataclass(frozen=True)
class PatternPromotedEvent(MemoryEvent):
    """
    Individual pattern promoted to collective scope.

    Published when a pattern is validated across multiple agents and
    promoted to collective memory for knowledge sharing.
    """

    memory_id: UUID
    pattern_text: str
    validation_count: int  # Number of agents that validated this pattern
    validation_agents: list[str]  # Which agents validated it

    @classmethod
    def create(
        cls,
        agent_id: str,
        memory_id: UUID,
        pattern_text: str,
        validation_count: int,
        validation_agents: list[str],
    ) -> "PatternPromotedEvent":
        """Create promotion event."""
        return cls(
            agent_id=agent_id,
            event_id=str(uuid4()),
            occurred_at=utc_now(),
            memory_id=memory_id,
            pattern_text=pattern_text,
            validation_count=validation_count,
            validation_agents=validation_agents,
        )


# ============================================================================
# Archival Events
# ============================================================================


@dataclass(frozen=True)
class MemoryArchivedEvent(MemoryEvent):
    """
    Memory archived due to low importance score.

    Published when sleeptime processing archives stale memories.
    """

    memory_id: UUID
    importance_score: float
    runs_since_access: int
    reason: str  # Why it was archived

    @classmethod
    def create(
        cls,
        agent_id: str,
        memory_id: UUID,
        importance_score: float,
        runs_since_access: int,
        reason: str,
    ) -> "MemoryArchivedEvent":
        """Create archival event."""
        return cls(
            agent_id=agent_id,
            event_id=str(uuid4()),
            occurred_at=utc_now(),
            memory_id=memory_id,
            importance_score=importance_score,
            runs_since_access=runs_since_access,
            reason=reason,
        )


# ============================================================================
# Sleeptime Events
# ============================================================================


@dataclass(frozen=True)
class SleeptimeCompletedEvent(MemoryEvent):
    """
    Sleeptime processing completed.

    Published when background maintenance operations finish.
    """

    memories_consolidated: int
    patterns_discovered: int
    memories_archived: int
    duration_seconds: float

    @classmethod
    def create(
        cls,
        agent_id: str,
        memories_consolidated: int,
        patterns_discovered: int,
        memories_archived: int,
        duration_seconds: float,
    ) -> "SleeptimeCompletedEvent":
        """Create sleeptime completed event."""
        return cls(
            agent_id=agent_id,
            event_id=str(uuid4()),
            occurred_at=utc_now(),
            memories_consolidated=memories_consolidated,
            patterns_discovered=patterns_discovered,
            memories_archived=memories_archived,
            duration_seconds=duration_seconds,
        )
