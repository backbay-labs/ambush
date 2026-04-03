"""
Memory Surfacing Service - Retrieve relevant memories for agent runs.

Multi-signal retrieval that combines:
- Semantic similarity
- Tag matching
- File path matching
- Link traversal
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

from .linking import LinkingService
from .models import AgentMemory

logger = logging.getLogger(__name__)


@dataclass
class SurfacingConfig:
    """Configuration for memory surfacing."""

    # Retrieval limits
    max_memories: int = 20
    max_per_signal: int = 10

    # Similarity thresholds
    semantic_threshold: float = 0.6
    min_importance: float = 0.15

    # Link traversal
    max_link_depth: int = 1
    max_per_link_level: int = 3

    # Weighting for final scoring
    semantic_weight: float = 0.4
    tag_weight: float = 0.25
    file_weight: float = 0.25
    link_weight: float = 0.1


class MemorySurfacingService:
    """
    Multi-signal memory retrieval service.

    Retrieves relevant memories using:
    1. Semantic similarity to task description
    2. Tag/label matching
    3. File path matching
    4. Linked memory traversal
    """

    def __init__(
        self,
        store,  # MemoryStore
        vector_ops,  # VectorOps
        linking_service: LinkingService | None = None,
        config: SurfacingConfig = None,
    ):
        """
        Initialize surfacing service.

        Args:
            store: MemoryStore for retrieval
            vector_ops: VectorOps for embeddings
            linking_service: Optional linking service for traversal
            config: Surfacing configuration
        """
        self.store = store
        self.vector_ops = vector_ops
        self.linking_service = linking_service
        self.config = config or SurfacingConfig()

    async def get_relevant_memories(
        self,
        query_text: str,
        agent_id: str,
        tags: list[str] | None = None,
        file_paths: list[str] | None = None,
        limit: int = None,
    ) -> list[AgentMemory]:
        """
        Get relevant memories using multi-signal retrieval.

        Args:
            query_text: Task description or query
            agent_id: Agent identifier
            tags: Optional issue tags
            file_paths: Optional target files
            limit: Maximum memories to return

        Returns:
            List of relevant memories sorted by relevance
        """
        limit = limit or self.config.max_memories
        config = self.config

        # Collect memories from each signal
        all_memories: dict[UUID, tuple[AgentMemory, float]] = {}

        # 1. Semantic similarity
        if query_text:
            fingerprint, embedding = await self.generate_fingerprint(query_text)
            semantic_memories = await self.store.search_similar(
                embedding=embedding,
                agent_id=agent_id,
                limit=config.max_per_signal,
                similarity_threshold=config.semantic_threshold,
                min_importance=config.min_importance,
                include_collective=True,
            )
            for mem in semantic_memories:
                score = (mem.similarity_score or 0.5) * config.semantic_weight
                self._add_memory(all_memories, mem, score)

        # 2. Tag matching
        if tags:
            tag_memories = await self.store.search_by_tags(
                tags=tags,
                agent_id=agent_id,
                limit=config.max_per_signal,
            )
            for mem in tag_memories:
                # Score based on tag overlap
                overlap = len(set(mem.issue_tags) & set(tags))
                tag_score = min(overlap / len(tags), 1.0) * config.tag_weight
                self._add_memory(all_memories, mem, tag_score)

        # 3. File path matching
        if file_paths:
            file_memories = await self.store.search_by_files(
                file_paths=file_paths,
                agent_id=agent_id,
                limit=config.max_per_signal,
            )
            for mem in file_memories:
                # Score based on file overlap
                overlap = len(set(mem.file_paths) & set(file_paths))
                file_score = min(overlap / len(file_paths), 1.0) * config.file_weight
                self._add_memory(all_memories, mem, file_score)

        # 4. Link expansion
        if self.linking_service and all_memories:
            linked = await self.expand_via_links(list(all_memories.keys()))
            for mem in linked:
                if mem.id not in all_memories:
                    self._add_memory(all_memories, mem, config.link_weight)

        # Sort by combined score and return top results
        sorted_memories = sorted(all_memories.values(), key=lambda x: x[1], reverse=True)

        return [mem for mem, score in sorted_memories[:limit]]

    async def generate_fingerprint(
        self,
        query_text: str,
    ) -> tuple[str, list[float]]:
        """
        Generate retrieval fingerprint for query.

        Args:
            query_text: Query text

        Returns:
            Tuple of (fingerprint_hash, embedding_vector)
        """
        import hashlib

        # Generate embedding
        embedding = await self.vector_ops.generate_embedding(query_text)

        # Generate hash fingerprint
        fingerprint = hashlib.md5(query_text.encode()).hexdigest()

        return fingerprint, embedding

    async def expand_via_links(
        self,
        memory_ids: list[UUID],
        max_depth: int = None,
    ) -> list[AgentMemory]:
        """
        Traverse links to find related memories.

        Args:
            memory_ids: Starting memory IDs
            max_depth: Maximum traversal depth

        Returns:
            List of related memories (excluding starting set)
        """
        if not self.linking_service:
            return []

        max_depth = max_depth or self.config.max_link_depth
        config = self.config

        visited: set[UUID] = set(memory_ids)
        result: list[AgentMemory] = []
        current_level = list(memory_ids)

        for _depth in range(max_depth):
            next_level = []

            for mid in current_level[: config.max_per_link_level]:
                # Use linking service for traversal
                related = await self.linking_service.traverse_related(
                    memory_id=mid,
                    max_depth=1,
                    max_per_level=config.max_per_link_level,
                )

                for mem in related:
                    if mem.id not in visited:
                        visited.add(mem.id)
                        result.append(mem)
                        next_level.append(mem.id)

            current_level = next_level
            if not current_level:
                break

        return result

    def _add_memory(
        self,
        memories: dict,
        memory: AgentMemory,
        score: float,
    ) -> None:
        """Add or update memory score in results dict."""
        if memory.id in memories:
            # Combine scores (max to avoid over-counting)
            _, existing_score = memories[memory.id]
            memories[memory.id] = (memory, max(existing_score, score))
        else:
            memories[memory.id] = (memory, score)


class IssueFingerprinter:
    """
    Generate fingerprints for issues to enable quick lookup.
    """

    def __init__(self, vector_ops):
        """
        Initialize fingerprinter.

        Args:
            vector_ops: VectorOps for embedding generation
        """
        self.vector_ops = vector_ops

    async def fingerprint_issue(
        self,
        title: str,
        body: str,
        tags: list[str] | None = None,
    ) -> tuple[str, list[float]]:
        """
        Generate fingerprint for an issue.

        Args:
            title: Issue title
            body: Issue body
            tags: Optional tags

        Returns:
            Tuple of (fingerprint_hash, embedding)
        """
        import hashlib

        # Combine text for embedding
        text_parts = [title]
        if body:
            text_parts.append(body[:2000])  # Limit body length
        if tags:
            text_parts.append(" ".join(tags))

        combined = "\n".join(text_parts)

        # Generate embedding
        embedding = await self.vector_ops.generate_embedding(combined)

        # Generate hash
        fingerprint = hashlib.md5(combined.encode()).hexdigest()

        return fingerprint, embedding
