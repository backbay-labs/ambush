"""
Collective Memory Service - Cross-agent knowledge sharing.

Manages promotion of individual memories to collective scope
for sharing across all agents.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from .models import AgentMemory, MemoryScope, MemoryType

logger = logging.getLogger(__name__)


@dataclass
class PromotionCriteria:
    """Criteria for promoting memory to collective scope."""

    # Pattern promotion (used by multiple agents)
    pattern_min_agents: int = 3
    pattern_min_confidence: float = 0.8

    # Dynamic promotion (high sample size)
    dynamic_min_sample_size: int = 10
    dynamic_min_confidence: float = 0.85

    # General thresholds
    min_importance: float = 0.6
    min_access_count: int = 3


class CollectiveMemoryService:
    """
    Service for managing collective (cross-agent) memories.

    Collective memories are:
    - Patterns validated across multiple agents
    - High-confidence dynamics with large sample sizes
    - Pareto frontier solutions (always collective)
    """

    def __init__(
        self,
        store,  # MemoryStore
        criteria: PromotionCriteria = None,
    ):
        """
        Initialize collective memory service.

        Args:
            store: MemoryStore for database access
            criteria: Promotion criteria
        """
        self.store = store
        self.criteria = criteria or PromotionCriteria()

    async def promote_to_collective(
        self,
        memory_id: UUID,
        validation_agents: list[str] | None = None,
    ) -> bool:
        """
        Promote individual memory to collective scope.

        Args:
            memory_id: Memory to promote
            validation_agents: List of agents that validated this pattern

        Returns:
            True if promoted, False otherwise
        """
        memory = await self.store.get(memory_id)
        if not memory:
            logger.warning(f"Memory {memory_id} not found for promotion")
            return False

        # Already collective
        if memory.scope == MemoryScope.COLLECTIVE:
            return True

        # Check promotion criteria
        if not await self.check_promotion_criteria(memory, validation_agents):
            return False

        # Update scope
        await self.store.update(
            memory_id=memory_id,
            updates={
                "scope": MemoryScope.COLLECTIVE.value,
                "updated_at": datetime.utcnow(),
            },
        )

        logger.info(f"Promoted memory {memory_id} to collective scope")
        return True

    async def check_promotion_criteria(
        self,
        memory: AgentMemory,
        validation_agents: list[str] | None = None,
    ) -> bool:
        """
        Check if memory meets promotion criteria.

        Args:
            memory: Memory to check
            validation_agents: Agents that validated this memory

        Returns:
            True if criteria met
        """
        criteria = self.criteria

        # Check basic thresholds
        if memory.importance_score < criteria.min_importance:
            return False

        if memory.access_count < criteria.min_access_count:
            return False

        # Type-specific criteria
        if memory.memory_type == MemoryType.PATTERN:
            # Pattern needs validation from multiple agents
            if validation_agents and len(validation_agents) >= criteria.pattern_min_agents:
                return memory.confidence >= criteria.pattern_min_confidence
            return False

        elif memory.memory_type == MemoryType.DYNAMIC:
            # Dynamic needs high confidence and sample size
            # Note: sample_size would need to be tracked in metadata
            return memory.confidence >= criteria.dynamic_min_confidence

        elif memory.memory_type == MemoryType.FRONTIER:
            # Pareto frontier solutions are always collective
            return True

        elif memory.memory_type == MemoryType.PLAYBOOK:
            # Playbooks can be promoted if highly accessed
            return memory.access_count >= criteria.min_access_count * 2

        return False

    async def get_collective_patterns(
        self,
        limit: int = 50,
    ) -> list[AgentMemory]:
        """
        Get collective patterns shared across agents.

        Args:
            limit: Maximum patterns to return

        Returns:
            List of collective pattern memories
        """
        # Search for collective scope patterns
        # This requires a custom query since search_by_type is agent-scoped
        async with self.store.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM agent_memories
                WHERE scope = 'collective'
                  AND memory_type = 'pattern'
                  AND is_archived = FALSE
                ORDER BY importance_score DESC
                LIMIT $1
                """,
                limit,
            )
            return [self.store._row_to_memory(row) for row in rows]

    async def get_collective_by_type(
        self,
        memory_type: MemoryType,
        limit: int = 50,
    ) -> list[AgentMemory]:
        """
        Get collective memories of a specific type.

        Args:
            memory_type: Type to filter
            limit: Maximum memories to return

        Returns:
            List of collective memories
        """
        async with self.store.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM agent_memories
                WHERE scope = 'collective'
                  AND memory_type = $1
                  AND is_archived = FALSE
                ORDER BY importance_score DESC
                LIMIT $2
                """,
                memory_type.value,
                limit,
            )
            return [self.store._row_to_memory(row) for row in rows]

    async def find_similar_across_agents(
        self,
        memory: AgentMemory,
        similarity_threshold: float = 0.85,
        limit: int = 10,
    ) -> list[AgentMemory]:
        """
        Find similar memories from other agents.

        Used to identify patterns that should be promoted.

        Args:
            memory: Source memory
            similarity_threshold: Minimum similarity
            limit: Maximum results

        Returns:
            List of similar memories from other agents
        """
        if not memory.embedding:
            return []

        async with self.store.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT m.*,
                       1 - (m.embedding <=> $1::vector) as similarity_score
                FROM agent_memories m
                WHERE m.agent_id != $2
                  AND m.memory_type = $3
                  AND m.is_archived = FALSE
                  AND 1 - (m.embedding <=> $1::vector) >= $4
                ORDER BY m.embedding <=> $1::vector
                LIMIT $5
                """,
                memory.embedding,
                memory.agent_id,
                memory.memory_type.value,
                similarity_threshold,
                limit,
            )

            memories = []
            for row in rows:
                mem = self.store._row_to_memory(row)
                mem.similarity_score = row["similarity_score"]
                memories.append(mem)
            return memories

    async def identify_promotion_candidates(
        self,
        limit: int = 20,
    ) -> list[AgentMemory]:
        """
        Find memories that are candidates for promotion.

        Looks for high-importance individual patterns that appear
        across multiple agents.

        Args:
            limit: Maximum candidates to return

        Returns:
            List of promotion candidate memories
        """
        criteria = self.criteria

        # Find high-quality individual memories
        async with self.store.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM agent_memories
                WHERE scope = 'individual'
                  AND memory_type IN ('pattern', 'dynamic', 'playbook')
                  AND importance_score >= $1
                  AND access_count >= $2
                  AND confidence >= $3
                  AND is_archived = FALSE
                ORDER BY importance_score DESC, access_count DESC
                LIMIT $4
                """,
                criteria.min_importance,
                criteria.min_access_count,
                criteria.pattern_min_confidence,
                limit * 2,  # Fetch extra to filter
            )

            candidates = []
            for row in rows:
                memory = self.store._row_to_memory(row)

                # Check if similar patterns exist in other agents
                similar = await self.find_similar_across_agents(memory)
                if len(similar) >= criteria.pattern_min_agents - 1:
                    candidates.append(memory)
                    if len(candidates) >= limit:
                        break

            return candidates
