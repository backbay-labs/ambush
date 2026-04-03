"""
Pydantic models for Cyntra Agent Memory System.

Adapted from Mira OS's LT_Memory architecture for agent swarm context.
All data structures for agent memories, links, batches, and processing.

Key Adaptations from Mira:
- Replace user_id with agent_id
- Replace activity_days with runs_at_creation/runs_at_last_access
- Add agent-specific scopes (individual, collective, world)
- Add agent-specific memory types and link types
"""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class MemoryScope(str, Enum):
    """
    Memory visibility and sharing scope.

    - individual: Private to single agent
    - collective: Shared across all agents (promoted patterns/dynamics)
    - world: Scoped to specific Fab World instance
    """

    INDIVIDUAL = "individual"
    COLLECTIVE = "collective"
    WORLD = "world"


class MemoryType(str, Enum):
    """
    Agent memory classification types.

    Core types:
    - pattern: Successful approach that worked (what + why + when)
    - failure: Failed approach with analysis (what failed + root cause + fix)
    - dynamic: Behavioral observation from dynamics analysis
    - context: Codebase understanding (file purpose, architecture)

    Meta types:
    - playbook: Repair instruction for specific fail codes
    - frontier: Pareto-optimal solution (always collective scope)
    """

    PATTERN = "pattern"
    FAILURE = "failure"
    DYNAMIC = "dynamic"
    CONTEXT = "context"
    PLAYBOOK = "playbook"
    FRONTIER = "frontier"


class LinkType(str, Enum):
    """
    Relationship types between memories.

    Mira types (causal/temporal):
    - conflicts: Memories describe contradictory information
    - supersedes: This memory replaces outdated information
    - causes: This memory explains cause of another
    - instance_of: Specific example of general pattern
    - invalidated_by: Memory proven wrong by evidence
    - motivated_by: Decision/action driven by this memory

    Agent-specific types:
    - improves_on: Enhanced version of previous pattern
    - requires: Dependency relationship (X requires Y)
    - repairs: Fix for specific failure mode
    """

    CONFLICTS = "conflicts"
    SUPERSEDES = "supersedes"
    CAUSES = "causes"
    INSTANCE_OF = "instance_of"
    INVALIDATED_BY = "invalidated_by"
    MOTIVATED_BY = "motivated_by"

    # Agent-specific
    IMPROVES_ON = "improves_on"
    REQUIRES = "requires"
    REPAIRS = "repairs"


class AgentMemory(BaseModel):
    """
    Core agent memory object stored in database.

    Returned by memory store for type-safe operations.
    Adapted from Mira's Memory model with agent context.
    """

    id: UUID
    agent_id: str  # Toolchain identifier (codex, claude, opencode, crush)
    text: str
    embedding: list[float] | None = None  # mdbr-leaf-ir-asym (768d)
    importance_score: float = Field(ge=0.0, le=1.0, default=0.5)

    # Memory classification
    memory_type: MemoryType
    scope: MemoryScope = MemoryScope.INDIVIDUAL

    # Timestamps
    created_at: datetime
    updated_at: datetime | None = None
    expires_at: datetime | None = None
    last_accessed: datetime | None = None
    happens_at: datetime | None = None  # When event occurred (for temporal context)

    # Access tracking
    access_count: int = 0
    mention_count: int = 0  # Explicit LLM references (strongest signal)

    # Link tracking arrays for efficient hub scoring
    inbound_links: list[dict[str, Any]] = Field(default_factory=list)
    outbound_links: list[dict[str, Any]] = Field(default_factory=list)

    # Metadata
    confidence: float = Field(ge=0.0, le=1.0, default=0.9)
    is_archived: bool = False
    archived_at: datetime | None = None

    # Refinement tracking
    is_refined: bool = False
    last_refined_at: datetime | None = None
    refinement_rejection_count: int = 0

    # Run-based activity snapshots (agent context, not calendar days)
    runs_at_creation: int | None = None
    runs_at_last_access: int | None = None

    # Agent-specific fields
    run_id: str | None = None  # Run that created this memory
    world_id: str | None = None  # Fab World context (for scope=world)
    issue_tags: list[str] = Field(default_factory=list)  # Issue labels/tags
    file_paths: list[str] = Field(default_factory=list)  # Referenced files

    # Transient fields populated by similarity search
    similarity_score: float | None = None

    # Transient fields populated during link traversal
    linked_memories: list[Any] | None = Field(default=None, exclude=True)
    link_metadata: dict[str, Any] | None = Field(default=None, exclude=True)


class MemoryLink(BaseModel):
    """
    Relationship link between agent memories.

    Stored bidirectionally in memory inbound_links/outbound_links JSONB arrays.
    Adapted from Mira with agent-specific relationship types.
    """

    source_id: UUID
    target_id: UUID
    link_type: LinkType
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("link_type")
    @classmethod
    def validate_link_type(cls, v: LinkType) -> LinkType:
        """Ensure link type is valid LinkType enum."""
        if not isinstance(v, LinkType):
            raise ValueError(f"link_type must be LinkType enum, got {type(v)}")
        return v


class ExtractedMemory(BaseModel):
    """
    Memory extracted from agent run before persistence.

    Used during extraction pipeline. Lighter than AgentMemory.
    Adapted from Mira's ExtractedMemory with agent fields.
    """

    id: UUID | None = None  # Populated after persistence (if stored)
    text: str
    memory_type: MemoryType
    importance_score: float = Field(ge=0.0, le=1.0, default=0.5)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)

    # Optional temporal context
    expires_at: datetime | None = None
    happens_at: datetime | None = None

    # Linking hints for intra-batch relationships
    linking_hints: list[int] = Field(
        default_factory=list,
        description="Indices of other memories in batch to consider for linking",
    )

    # Agent context
    issue_tags: list[str] = Field(default_factory=list)
    file_paths: list[str] = Field(default_factory=list)

    @field_validator("importance_score", "confidence")
    @classmethod
    def validate_score_range(cls, v: float) -> float:
        """Ensure scores are within valid range."""
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"Score must be between 0.0 and 1.0, got {v}")
        return v


class ExtractionResult(BaseModel):
    """
    Result of memory extraction containing memories and linking hints.

    Used to pass both extracted memories and intra-batch linking hints
    through the extraction pipeline.
    """

    memories: list[ExtractedMemory]
    linking_pairs: list[tuple[int, int]] = Field(
        default_factory=list,
        description="Pairs of memory indices that should be evaluated for relationships",
    )


class ConsolidationCluster(BaseModel):
    """
    Cluster of similar memories identified for consolidation.

    Used during sleeptime refinement to group memories that should be merged.
    Adapted from Mira with agent context.
    """

    cluster_id: str
    memory_ids: list[UUID]
    memory_texts: list[str]
    similarity_scores: list[float]
    avg_similarity: float
    consolidation_confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("memory_ids")
    @classmethod
    def validate_min_cluster_size(cls, v: list[UUID]) -> list[UUID]:
        """Ensure cluster has at least 2 memories."""
        if len(v) < 2:
            raise ValueError("ConsolidationCluster must contain at least 2 memories")
        return v


class ExtractionBatch(BaseModel):
    """
    Batch extraction tracking for async memory extraction.

    Represents a row in memory_extraction_batches table.
    Tracks LLM batch API job for extracting memories from run transcripts.
    """

    id: UUID | None = None  # Generated by database
    batch_id: str  # LLM provider batch ID
    custom_id: str
    agent_id: str
    run_id: str
    request_payload: dict[str, Any]
    run_metadata: dict[str, Any] | None = None
    memory_context: dict[str, Any] | None = None
    status: str  # submitted, processing, completed, failed, expired, cancelled
    created_at: datetime
    submitted_at: datetime
    completed_at: datetime | None = None
    expires_at: datetime | None = None
    result_url: str | None = None
    result_payload: dict[str, Any] | None = None
    extracted_memories: list[dict[str, Any]] | None = None
    error_message: str | None = None
    retry_count: int = 0
    processing_time_ms: int | None = None
    tokens_used: int | None = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        """Validate status is one of allowed values."""
        allowed = {"submitted", "processing", "completed", "failed", "expired", "cancelled"}
        if v not in allowed:
            raise ValueError(f"status must be one of {allowed}, got '{v}'")
        return v


class LinkingBatch(BaseModel):
    """
    Post-processing batch for relationship classification.

    Represents a row in memory_linking_batches table.
    Tracks LLM batch job for classifying relationships between memories.
    """

    id: UUID | None = None  # Generated by database
    batch_id: str  # LLM provider batch ID
    agent_id: str
    request_payload: dict[str, Any]
    input_data: dict[str, Any]
    items_submitted: int
    items_completed: int = 0
    items_failed: int = 0
    status: str
    created_at: datetime
    submitted_at: datetime
    completed_at: datetime | None = None
    expires_at: datetime | None = None
    result_payload: dict[str, Any] | None = None
    error_message: str | None = None
    retry_count: int = 0
    processing_time_ms: int | None = None
    tokens_used: int | None = None
    links_created: int = 0
    conflicts_flagged: int = 0

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        """Validate status is one of allowed values."""
        allowed = {"submitted", "processing", "completed", "failed", "expired", "cancelled"}
        if v not in allowed:
            raise ValueError(f"status must be one of {allowed}, got '{v}'")
        return v
