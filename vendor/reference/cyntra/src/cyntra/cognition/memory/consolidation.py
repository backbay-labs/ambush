"""
Memory Consolidation Handler - Merge similar memories.

Identifies and consolidates redundant memories during sleeptime
to reduce token usage and improve retrieval quality.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID, uuid4

from .models import AgentMemory, ConsolidationCluster, ExtractedMemory, MemoryType

logger = logging.getLogger(__name__)


@dataclass
class ConsolidationConfig:
    """Configuration for memory consolidation."""

    # Similarity thresholds
    similarity_threshold: float = 0.85
    min_cluster_size: int = 2
    max_cluster_size: int = 5

    # Selection criteria
    min_importance: float = 0.2
    max_age_runs: int = 100  # Don't consolidate very old memories

    # LLM settings (for consolidation text generation)
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 1024
    temperature: float = 0.3


class ConsolidationHandler:
    """
    Handle memory consolidation during sleeptime.

    Process:
    1. Find clusters of similar memories
    2. Generate consolidated text via LLM
    3. Create new memory and archive old ones
    4. Transfer links to new memory
    """

    def __init__(
        self,
        store,  # MemoryStore
        vector_ops=None,  # VectorOps
        llm_client=None,
        config: ConsolidationConfig = None,
    ):
        """
        Initialize consolidation handler.

        Args:
            store: MemoryStore for database access
            vector_ops: VectorOps for similarity
            llm_client: Optional LLM for text generation
            config: Consolidation configuration
        """
        self.store = store
        self.vector_ops = vector_ops
        self.llm_client = llm_client
        self.config = config or ConsolidationConfig()

    async def find_clusters(
        self,
        agent_id: str,
        limit: int = 10,
    ) -> list[ConsolidationCluster]:
        """
        Find clusters of similar memories.

        Args:
            agent_id: Agent to analyze
            limit: Maximum clusters to find

        Returns:
            List of ConsolidationCluster objects
        """
        config = self.config

        # Get candidate memories
        memories = await self._get_consolidation_candidates(agent_id)
        if len(memories) < config.min_cluster_size:
            return []

        # Build similarity graph
        clusters = []
        used_ids = set()

        for i, mem_i in enumerate(memories):
            if mem_i.id in used_ids:
                continue

            cluster_ids = [mem_i.id]
            cluster_texts = [mem_i.text]
            similarities = [1.0]

            for j, mem_j in enumerate(memories):
                if i == j or mem_j.id in used_ids:
                    continue

                if mem_i.embedding and mem_j.embedding:
                    sim = self.vector_ops.cosine_similarity(mem_i.embedding, mem_j.embedding)
                    if sim >= config.similarity_threshold:
                        cluster_ids.append(mem_j.id)
                        cluster_texts.append(mem_j.text)
                        similarities.append(sim)

                        if len(cluster_ids) >= config.max_cluster_size:
                            break

            # Create cluster if large enough
            if len(cluster_ids) >= config.min_cluster_size:
                cluster = ConsolidationCluster(
                    cluster_id=str(uuid4()),
                    memory_ids=cluster_ids,
                    memory_texts=cluster_texts,
                    similarity_scores=similarities,
                    avg_similarity=sum(similarities) / len(similarities),
                    consolidation_confidence=min(similarities),
                )
                clusters.append(cluster)
                used_ids.update(cluster_ids)

            if len(clusters) >= limit:
                break

        return clusters

    async def consolidate_cluster(
        self,
        cluster: ConsolidationCluster,
    ) -> AgentMemory | None:
        """
        Consolidate a cluster of similar memories.

        Args:
            cluster: Cluster to consolidate

        Returns:
            New consolidated memory, or None if failed
        """
        logger.info(
            f"Consolidating cluster {cluster.cluster_id} with {len(cluster.memory_ids)} memories"
        )

        # Get full memory objects
        memories = await self.store.get_batch(cluster.memory_ids)
        if len(memories) < 2:
            return None

        # Generate consolidated text
        consolidated_text = await self._generate_consolidated_text(memories)
        if not consolidated_text:
            return None

        # Determine attributes for new memory
        agent_id = memories[0].agent_id
        memory_type = self._determine_type(memories)
        importance = max(m.importance_score for m in memories)
        confidence = min(m.confidence for m in memories)

        # Collect all tags and paths
        all_tags = set()
        all_paths = set()
        for m in memories:
            all_tags.update(m.issue_tags)
            all_paths.update(m.file_paths)

        # Create new memory
        new_memory = ExtractedMemory(
            text=consolidated_text,
            memory_type=memory_type,
            importance_score=importance,
            confidence=confidence,
            issue_tags=list(all_tags),
            file_paths=list(all_paths),
        )

        # Generate embedding
        embedding = None
        if self.vector_ops:
            embedding = await self.vector_ops.generate_embedding(consolidated_text)

        # Store new memory
        await self.store.get_agent_run_count(agent_id)
        new_id = await self.store.create(
            memory=new_memory,
            agent_id=agent_id,
            embedding=embedding,
        )

        # Transfer links from old memories to new
        await self.transfer_links(cluster.memory_ids, new_id)

        # Archive old memories
        for old_id in cluster.memory_ids:
            await self.store.archive(old_id)

        # Return the new memory
        return await self.store.get(new_id)

    async def transfer_links(
        self,
        old_ids: list[UUID],
        new_id: UUID,
    ) -> None:
        """
        Transfer links from old memories to new consolidated memory.

        Args:
            old_ids: IDs of old memories being consolidated
            new_id: ID of new consolidated memory
        """
        # Get all links from old memories
        all_inbound = []
        all_outbound = []

        for old_id in old_ids:
            links = await self.store.get_links(old_id)
            all_inbound.extend(links["inbound"])
            all_outbound.extend(links["outbound"])

        # Deduplicate links (by target UUID)
        seen_outbound = set()
        unique_outbound = []
        for link in all_outbound:
            target = link.get("uuid")
            if target and target not in seen_outbound and target not in [str(i) for i in old_ids]:
                seen_outbound.add(target)
                unique_outbound.append(link)

        # Note: Link transfer would require updating the new memory's
        # inbound/outbound arrays, but this is complex due to JSONB structure.
        # For now, we just log the links that would be transferred.
        if unique_outbound:
            logger.info(f"Would transfer {len(unique_outbound)} outbound links to {new_id}")

    async def _get_consolidation_candidates(
        self,
        agent_id: str,
        limit: int = 100,
    ) -> list[AgentMemory]:
        """Get memories that are candidates for consolidation."""
        config = self.config

        async with self.store.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM agent_memories
                WHERE agent_id = $1
                  AND importance_score >= $2
                  AND is_archived = FALSE
                  AND embedding IS NOT NULL
                ORDER BY created_at DESC
                LIMIT $3
                """,
                agent_id,
                config.min_importance,
                limit,
            )
            return [self.store._row_to_memory(row) for row in rows]

    async def _generate_consolidated_text(
        self,
        memories: list[AgentMemory],
    ) -> str | None:
        """Generate consolidated text from multiple memories."""
        if self.llm_client:
            return await self._llm_consolidate(memories)
        else:
            return self._simple_consolidate(memories)

    async def _llm_consolidate(
        self,
        memories: list[AgentMemory],
    ) -> str | None:
        """Use LLM to generate consolidated text."""
        texts = [m.text for m in memories]

        prompt = f"""
Consolidate these similar memories into a single, comprehensive memory.

Memories to consolidate:
{chr(10).join(f"- {t}" for t in texts)}

Requirements:
1. Preserve all unique information
2. Remove redundancy
3. Keep it concise but complete
4. Maintain the same style (actionable, specific)

Return only the consolidated memory text.
"""

        try:
            response = await self.llm_client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text.strip()
        except Exception as e:
            logger.error(f"LLM consolidation failed: {e}")
            return self._simple_consolidate(memories)

    def _simple_consolidate(
        self,
        memories: list[AgentMemory],
    ) -> str:
        """Simple text consolidation without LLM."""
        # Take the longest/most detailed memory as base
        memories_sorted = sorted(memories, key=lambda m: len(m.text), reverse=True)
        return memories_sorted[0].text

    def _determine_type(
        self,
        memories: list[AgentMemory],
    ) -> MemoryType:
        """Determine type for consolidated memory."""
        # Use most common type
        type_counts = {}
        for m in memories:
            type_counts[m.memory_type] = type_counts.get(m.memory_type, 0) + 1

        return max(type_counts.items(), key=lambda x: x[1])[0]
