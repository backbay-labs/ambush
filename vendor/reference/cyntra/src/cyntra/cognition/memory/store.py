"""
Memory Store - PostgreSQL database operations for agent memory.

Adapted from Mira OS's db_access.py for agent swarm context.
Provides type-safe operations with Pydantic model returns.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

from .models import (
    AgentMemory,
    ExtractedMemory,
    ExtractionBatch,
    MemoryLink,
    MemoryScope,
    MemoryType,
)

logger = logging.getLogger(__name__)


def _load_scoring_formula() -> str:
    """Load SQL scoring formula from file."""
    formula_path = (
        Path(__file__).parent.parent.parent.parent / "migrations" / "002_scoring_function.sql"
    )
    if formula_path.exists():
        return formula_path.read_text().strip()
    return ""


class MemoryStore:
    """
    Database gateway for agent memory operations.

    Provides type-safe async database access with Pydantic model returns.
    All operations are designed for agent context (not user context).

    Supports two initialization patterns:
    - Direct: `store = MemoryStore(pool=pool)` with existing pool
    - Lazy: `store = MemoryStore(db_url=url); await store.initialize()`
    """

    def __init__(
        self,
        pool: Any | None = None,
        db_url: str | None = None,
    ):
        """
        Initialize store with connection pool or URL for lazy init.

        Args:
            pool: Existing asyncpg connection pool
            db_url: PostgreSQL connection string (for lazy initialization)

        Raises:
            ValueError: If neither pool nor db_url provided
        """
        self.pool = pool
        self.db_url = db_url
        self._initialized = pool is not None

        if pool is None and db_url is None:
            raise ValueError("Either pool or db_url must be provided")

    async def initialize(self) -> None:
        """
        Initialize connection pool if using lazy initialization.

        Call this after constructing with db_url.
        """
        if self._initialized:
            return

        if not self.db_url:
            raise ValueError("No db_url provided for initialization")

        try:
            import asyncpg  # type: ignore[import-not-found]
        except ImportError as e:
            raise ImportError(
                "asyncpg is required for MemoryStore database operations. "
                "Install with: pip install cyntra[memory]"
            ) from e

        self.pool = await asyncpg.create_pool(self.db_url, min_size=2, max_size=10)
        self._initialized = True

    @classmethod
    async def connect(cls, dsn: str) -> MemoryStore:
        """
        Create store with a new connection pool.

        Args:
            dsn: PostgreSQL connection string

        Returns:
            Initialized MemoryStore
        """
        try:
            import asyncpg  # type: ignore[import-not-found]
        except ImportError as e:
            raise ImportError(
                "asyncpg is required for MemoryStore database operations. "
                "Install with: pip install cyntra[memory]"
            ) from e

        pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10)
        return cls(pool=pool)

    async def close(self) -> None:
        """Close connection pool."""
        await self.pool.close()

    @asynccontextmanager
    async def transaction(self):
        """Provide transaction context for multi-step operations."""
        async with self.pool.acquire() as conn, conn.transaction():
            yield conn

    # ==================== MEMORY CRUD ====================

    async def create(
        self,
        memory: ExtractedMemory,
        agent_id: str,
        embedding: list[float] | None = None,
        run_id: str | None = None,
        world_id: str | None = None,
        scope: MemoryScope = MemoryScope.INDIVIDUAL,
    ) -> UUID:
        """
        Create a new agent memory.

        Args:
            memory: ExtractedMemory to persist
            agent_id: Toolchain identifier
            embedding: Optional embedding vector (768d)
            run_id: Optional run identifier
            world_id: Optional Fab World identifier
            scope: Memory visibility scope

        Returns:
            Created memory UUID
        """
        current_runs = await self.get_agent_run_count(agent_id)

        async with self.pool.acquire() as conn:
            result = await conn.fetchrow(
                """
                INSERT INTO agent_memories (
                    agent_id, text, embedding, importance_score,
                    memory_type, scope, confidence,
                    expires_at, happens_at,
                    runs_at_creation, runs_at_last_access,
                    run_id, world_id, issue_tags, file_paths
                ) VALUES (
                    $1, $2, $3, $4,
                    $5, $6, $7,
                    $8, $9,
                    $10, $10,
                    $11, $12, $13, $14
                ) RETURNING id
                """,
                agent_id,
                memory.text,
                embedding,
                memory.importance_score,
                memory.memory_type.value,
                scope.value,
                memory.confidence,
                memory.expires_at,
                memory.happens_at,
                current_runs,
                run_id,
                world_id,
                memory.issue_tags,
                memory.file_paths,
            )
            return result["id"]

    async def create_batch(
        self,
        memories: list[ExtractedMemory],
        agent_id: str,
        embeddings: list[list[float]] | None = None,
        run_id: str | None = None,
        world_id: str | None = None,
        scope: MemoryScope = MemoryScope.INDIVIDUAL,
    ) -> list[UUID]:
        """
        Batch create multiple memories.

        Args:
            memories: List of ExtractedMemory objects
            agent_id: Toolchain identifier
            embeddings: Optional list of embeddings (must match memory count)
            run_id: Run identifier
            world_id: Fab World identifier
            scope: Memory visibility scope

        Returns:
            List of created memory UUIDs
        """
        if not memories:
            return []

        if embeddings and len(embeddings) != len(memories):
            raise ValueError("Embeddings count must match memories count")

        current_runs = await self.get_agent_run_count(agent_id)
        created_ids = []

        async with self.transaction() as conn:
            for i, memory in enumerate(memories):
                embedding = embeddings[i] if embeddings else None
                result = await conn.fetchrow(
                    """
                    INSERT INTO agent_memories (
                        agent_id, text, embedding, importance_score,
                        memory_type, scope, confidence,
                        expires_at, happens_at,
                        runs_at_creation, runs_at_last_access,
                        run_id, world_id, issue_tags, file_paths
                    ) VALUES (
                        $1, $2, $3, $4,
                        $5, $6, $7,
                        $8, $9,
                        $10, $10,
                        $11, $12, $13, $14
                    ) RETURNING id
                    """,
                    agent_id,
                    memory.text,
                    embedding,
                    memory.importance_score,
                    memory.memory_type.value,
                    scope.value,
                    memory.confidence,
                    memory.expires_at,
                    memory.happens_at,
                    current_runs,
                    run_id,
                    world_id,
                    memory.issue_tags,
                    memory.file_paths,
                )
                created_ids.append(result["id"])

        logger.info(f"Created {len(created_ids)} memories for agent {agent_id}")
        return created_ids

    async def get(self, memory_id: UUID) -> AgentMemory | None:
        """
        Fetch memory by ID.

        Args:
            memory_id: Memory UUID

        Returns:
            AgentMemory or None if not found
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM agent_memories WHERE id = $1",
                memory_id,
            )
            if not row:
                return None
            return self._row_to_memory(row)

    async def get_batch(self, memory_ids: list[UUID]) -> list[AgentMemory]:
        """
        Fetch multiple memories by IDs.

        Args:
            memory_ids: List of memory UUIDs

        Returns:
            List of AgentMemory objects (may be fewer than requested)
        """
        if not memory_ids:
            return []

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM agent_memories
                WHERE id = ANY($1::uuid[])
                ORDER BY importance_score DESC
                """,
                memory_ids,
            )
            return [self._row_to_memory(row) for row in rows]

    async def update(
        self,
        memory_id: UUID,
        updates: dict[str, Any],
    ) -> AgentMemory:
        """
        Update memory fields.

        Args:
            memory_id: Memory UUID
            updates: Field updates

        Returns:
            Updated AgentMemory

        Raises:
            ValueError: If memory not found
        """
        # Build SET clause
        set_parts = []
        values = []
        for i, (field, value) in enumerate(updates.items(), start=2):
            set_parts.append(f"{field} = ${i}")
            values.append(value)

        set_clause = ", ".join(set_parts)

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                f"""
                UPDATE agent_memories
                SET {set_clause}, updated_at = NOW()
                WHERE id = $1
                RETURNING *
                """,
                memory_id,
                *values,
            )
            if not row:
                raise ValueError(f"Memory {memory_id} not found")
            return self._row_to_memory(row)

    async def archive(self, memory_id: UUID) -> None:
        """
        Archive a memory (soft delete).

        Args:
            memory_id: Memory UUID
        """
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE agent_memories
                SET is_archived = TRUE, archived_at = NOW(), updated_at = NOW()
                WHERE id = $1
                """,
                memory_id,
            )

    # ==================== SEARCH OPERATIONS ====================

    async def search_similar(
        self,
        embedding: list[float],
        agent_id: str | None = None,
        limit: int = 10,
        similarity_threshold: float = 0.7,
        min_importance: float = 0.1,
        include_collective: bool = True,
    ) -> list[AgentMemory]:
        """
        Vector similarity search using cosine distance.

        Args:
            embedding: Query vector (768d)
            agent_id: Optional agent filter
            limit: Maximum results
            similarity_threshold: Minimum cosine similarity (0-1)
            min_importance: Minimum importance score
            include_collective: Include collective scope memories

        Returns:
            List of similar memories sorted by similarity
        """
        async with self.pool.acquire() as conn:
            if agent_id and include_collective:
                rows = await conn.fetch(
                    """
                    SELECT m.*,
                           1 - (m.embedding <=> $1::vector) as similarity_score
                    FROM agent_memories m
                    WHERE m.importance_score >= $2
                      AND (m.expires_at IS NULL OR m.expires_at > NOW())
                      AND m.is_archived = FALSE
                      AND (m.agent_id = $3 OR m.scope = 'collective')
                      AND 1 - (m.embedding <=> $1::vector) >= $4
                    ORDER BY m.embedding <=> $1::vector
                    LIMIT $5
                    """,
                    embedding,
                    min_importance,
                    agent_id,
                    similarity_threshold,
                    limit,
                )
            elif agent_id:
                rows = await conn.fetch(
                    """
                    SELECT m.*,
                           1 - (m.embedding <=> $1::vector) as similarity_score
                    FROM agent_memories m
                    WHERE m.importance_score >= $2
                      AND (m.expires_at IS NULL OR m.expires_at > NOW())
                      AND m.is_archived = FALSE
                      AND m.agent_id = $3
                      AND 1 - (m.embedding <=> $1::vector) >= $4
                    ORDER BY m.embedding <=> $1::vector
                    LIMIT $5
                    """,
                    embedding,
                    min_importance,
                    agent_id,
                    similarity_threshold,
                    limit,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT m.*,
                           1 - (m.embedding <=> $1::vector) as similarity_score
                    FROM agent_memories m
                    WHERE m.importance_score >= $2
                      AND (m.expires_at IS NULL OR m.expires_at > NOW())
                      AND m.is_archived = FALSE
                      AND 1 - (m.embedding <=> $1::vector) >= $3
                    ORDER BY m.embedding <=> $1::vector
                    LIMIT $4
                    """,
                    embedding,
                    min_importance,
                    similarity_threshold,
                    limit,
                )

            memories = []
            for row in rows:
                memory = self._row_to_memory(row)
                memory.similarity_score = row["similarity_score"]
                memories.append(memory)
            return memories

    async def search_by_tags(
        self,
        tags: list[str],
        agent_id: str | None = None,
        limit: int = 20,
    ) -> list[AgentMemory]:
        """
        Search memories by issue tags.

        Args:
            tags: Tags to match
            agent_id: Optional agent filter
            limit: Maximum results

        Returns:
            List of matching memories
        """
        async with self.pool.acquire() as conn:
            if agent_id:
                rows = await conn.fetch(
                    """
                    SELECT * FROM agent_memories
                    WHERE issue_tags && $1
                      AND (agent_id = $2 OR scope = 'collective')
                      AND is_archived = FALSE
                    ORDER BY importance_score DESC
                    LIMIT $3
                    """,
                    tags,
                    agent_id,
                    limit,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT * FROM agent_memories
                    WHERE issue_tags && $1
                      AND is_archived = FALSE
                    ORDER BY importance_score DESC
                    LIMIT $2
                    """,
                    tags,
                    limit,
                )
            return [self._row_to_memory(row) for row in rows]

    async def search_by_type(
        self,
        memory_type: MemoryType,
        agent_id: str | None = None,
        limit: int = 20,
    ) -> list[AgentMemory]:
        """
        Search memories by type.

        Args:
            memory_type: Memory type filter
            agent_id: Optional agent filter
            limit: Maximum results

        Returns:
            List of matching memories
        """
        async with self.pool.acquire() as conn:
            if agent_id:
                rows = await conn.fetch(
                    """
                    SELECT * FROM agent_memories
                    WHERE memory_type = $1
                      AND (agent_id = $2 OR scope = 'collective')
                      AND is_archived = FALSE
                    ORDER BY importance_score DESC
                    LIMIT $3
                    """,
                    memory_type.value,
                    agent_id,
                    limit,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT * FROM agent_memories
                    WHERE memory_type = $1
                      AND is_archived = FALSE
                    ORDER BY importance_score DESC
                    LIMIT $2
                    """,
                    memory_type.value,
                    limit,
                )
            return [self._row_to_memory(row) for row in rows]

    async def search_by_files(
        self,
        file_paths: list[str],
        agent_id: str | None = None,
        limit: int = 20,
    ) -> list[AgentMemory]:
        """
        Search memories by file paths.

        Args:
            file_paths: File paths to match
            agent_id: Optional agent filter
            limit: Maximum results

        Returns:
            List of matching memories
        """
        async with self.pool.acquire() as conn:
            if agent_id:
                rows = await conn.fetch(
                    """
                    SELECT * FROM agent_memories
                    WHERE file_paths && $1
                      AND (agent_id = $2 OR scope = 'collective')
                      AND is_archived = FALSE
                    ORDER BY importance_score DESC
                    LIMIT $3
                    """,
                    file_paths,
                    agent_id,
                    limit,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT * FROM agent_memories
                    WHERE file_paths && $1
                      AND is_archived = FALSE
                    ORDER BY importance_score DESC
                    LIMIT $2
                    """,
                    file_paths,
                    limit,
                )
            return [self._row_to_memory(row) for row in rows]

    # ==================== HUB OPERATIONS ====================

    async def find_hubs(
        self,
        agent_id: str,
        min_importance: float = 0.5,
        min_access: int = 3,
        min_links: int = 2,
        limit: int = 50,
    ) -> list[AgentMemory]:
        """
        Find hub memories (high connectivity, frequently accessed).

        Used for consolidation candidate identification.

        Args:
            agent_id: Agent identifier
            min_importance: Minimum importance score
            min_access: Minimum access count
            min_links: Minimum inbound link count
            limit: Maximum results

        Returns:
            List of hub memories
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM agent_memories
                WHERE agent_id = $1
                  AND importance_score >= $2
                  AND access_count >= $3
                  AND jsonb_array_length(inbound_links) >= $4
                  AND is_archived = FALSE
                ORDER BY importance_score DESC, jsonb_array_length(inbound_links) DESC
                LIMIT $5
                """,
                agent_id,
                min_importance,
                min_access,
                min_links,
                limit,
            )
            return [self._row_to_memory(row) for row in rows]

    # ==================== ACTIVITY TRACKING ====================

    async def increment_access(
        self,
        memory_id: UUID,
        current_runs: int | None = None,
    ) -> None:
        """
        Record memory access.

        Args:
            memory_id: Memory UUID
            current_runs: Optional override for current run count
        """
        async with self.pool.acquire() as conn:
            if current_runs is None:
                # Get agent_id to fetch current runs
                row = await conn.fetchrow(
                    "SELECT agent_id FROM agent_memories WHERE id = $1",
                    memory_id,
                )
                if not row:
                    return

                current_runs = await self.get_agent_run_count(row["agent_id"])

            await conn.execute(
                """
                UPDATE agent_memories
                SET access_count = access_count + 1,
                    last_accessed = NOW(),
                    runs_at_last_access = $2,
                    updated_at = NOW()
                WHERE id = $1
                """,
                memory_id,
                current_runs,
            )

    async def get_agent_run_count(self, agent_id: str) -> int:
        """
        Get current run count for agent.

        Args:
            agent_id: Agent identifier

        Returns:
            Total runs for agent
        """
        async with self.pool.acquire() as conn:
            result = await conn.fetchval(
                "SELECT total_runs FROM agent_activity_counters WHERE agent_id = $1",
                agent_id,
            )
            return result or 0

    async def increment_agent_runs(self, agent_id: str) -> int:
        """
        Increment agent run counter.

        Args:
            agent_id: Agent identifier

        Returns:
            New run count
        """
        async with self.pool.acquire() as conn:
            result = await conn.fetchval(
                "SELECT increment_agent_runs($1)",
                agent_id,
            )
            return result or 1

    # ==================== LINK OPERATIONS ====================

    async def create_link(self, link: MemoryLink) -> None:
        """
        Create bidirectional link between memories.

        Args:
            link: MemoryLink to create
        """
        outbound_obj = {
            "uuid": str(link.target_id),
            "type": link.link_type.value,
            "confidence": link.confidence,
            "reasoning": link.reasoning,
            "created_at": link.created_at.isoformat(),
        }

        inbound_obj = {
            "uuid": str(link.source_id),
            "type": link.link_type.value,
            "confidence": link.confidence,
            "reasoning": link.reasoning,
            "created_at": link.created_at.isoformat(),
        }

        async with self.transaction() as conn:
            # Add outbound link to source
            await conn.execute(
                """
                UPDATE agent_memories
                SET outbound_links = outbound_links || $2::jsonb,
                    updated_at = NOW()
                WHERE id = $1
                  AND NOT EXISTS (
                      SELECT 1 FROM jsonb_array_elements(outbound_links) AS elem
                      WHERE elem->>'uuid' = $3
                        AND elem->>'type' = $4
                  )
                """,
                link.source_id,
                json.dumps(outbound_obj),
                str(link.target_id),
                link.link_type.value,
            )

            # Add inbound link to target
            await conn.execute(
                """
                UPDATE agent_memories
                SET inbound_links = inbound_links || $2::jsonb,
                    updated_at = NOW()
                WHERE id = $1
                  AND NOT EXISTS (
                      SELECT 1 FROM jsonb_array_elements(inbound_links) AS elem
                      WHERE elem->>'uuid' = $3
                        AND elem->>'type' = $4
                  )
                """,
                link.target_id,
                json.dumps(inbound_obj),
                str(link.source_id),
                link.link_type.value,
            )

    async def create_links_batch(self, links: list[MemoryLink]) -> None:
        """
        Batch create multiple links.

        Args:
            links: List of MemoryLink objects
        """
        for link in links:
            await self.create_link(link)

    async def get_links(self, memory_id: UUID) -> dict[str, list[dict[str, Any]]]:
        """
        Get all links for a memory.

        Args:
            memory_id: Memory UUID

        Returns:
            Dict with 'inbound' and 'outbound' link lists
        """
        memory = await self.get(memory_id)
        if not memory:
            return {"inbound": [], "outbound": []}

        return {
            "inbound": memory.inbound_links,
            "outbound": memory.outbound_links,
        }

    async def heal_dead_links(self, dead_ids: list[UUID]) -> int:
        """
        Remove dead links from all memories.

        Lazy cleanup pattern: call when dead links detected during traversal.

        Args:
            dead_ids: List of dead memory UUIDs

        Returns:
            Number of memories updated
        """
        if not dead_ids:
            return 0

        dead_strs = [str(uid) for uid in dead_ids]

        async with self.pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE agent_memories
                SET
                    inbound_links = (
                        SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
                        FROM jsonb_array_elements(inbound_links) AS elem
                        WHERE elem->>'uuid' != ALL($1)
                    ),
                    outbound_links = (
                        SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
                        FROM jsonb_array_elements(outbound_links) AS elem
                        WHERE elem->>'uuid' != ALL($1)
                    ),
                    updated_at = NOW()
                WHERE EXISTS (
                    SELECT 1 FROM jsonb_array_elements(inbound_links) AS elem
                    WHERE elem->>'uuid' = ANY($1)
                ) OR EXISTS (
                    SELECT 1 FROM jsonb_array_elements(outbound_links) AS elem
                    WHERE elem->>'uuid' = ANY($1)
                )
                """,
                dead_strs,
            )
            count = int(result.split()[-1]) if result else 0
            if count > 0:
                logger.info(f"Cleaned up {count} dead links")
            return count

    # ==================== SCORING OPERATIONS ====================

    async def recalculate_scores(self, agent_id: str) -> int:
        """
        Recalculate importance scores for agent's memories.

        Args:
            agent_id: Agent identifier

        Returns:
            Number of memories updated
        """
        async with self.pool.acquire() as conn:
            result = await conn.fetchval(
                "SELECT recalculate_agent_memory_scores($1)",
                agent_id,
            )
            return result or 0

    async def get_archival_candidates(
        self,
        agent_id: str,
        threshold: float = 0.001,
        limit: int = 100,
    ) -> list[UUID]:
        """
        Find memories below archival threshold.

        Args:
            agent_id: Agent identifier
            threshold: Importance threshold
            limit: Maximum candidates

        Returns:
            List of memory IDs for archival
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id FROM agent_memories
                WHERE agent_id = $1
                  AND importance_score <= $2
                  AND is_archived = FALSE
                LIMIT $3
                """,
                agent_id,
                threshold,
                limit,
            )
            return [row["id"] for row in rows]

    # ==================== BATCH TRACKING ====================

    async def create_extraction_batch(
        self,
        batch: ExtractionBatch,
    ) -> UUID:
        """Create extraction batch tracking record."""
        async with self.pool.acquire() as conn:
            result = await conn.fetchrow(
                """
                INSERT INTO memory_extraction_batches (
                    batch_id, custom_id, agent_id, run_id,
                    request_payload, run_metadata, memory_context,
                    status, submitted_at, expires_at
                ) VALUES (
                    $1, $2, $3, $4,
                    $5, $6, $7,
                    $8, $9, $10
                ) RETURNING id
                """,
                batch.batch_id,
                batch.custom_id,
                batch.agent_id,
                batch.run_id,
                json.dumps(batch.request_payload),
                json.dumps(batch.run_metadata) if batch.run_metadata else None,
                json.dumps(batch.memory_context) if batch.memory_context else None,
                batch.status,
                batch.submitted_at,
                batch.expires_at,
            )
            return result["id"]

    async def get_pending_extraction_batches(
        self,
        agent_id: str | None = None,
    ) -> list[ExtractionBatch]:
        """Get pending extraction batches."""
        async with self.pool.acquire() as conn:
            if agent_id:
                rows = await conn.fetch(
                    """
                    SELECT * FROM memory_extraction_batches
                    WHERE agent_id = $1
                      AND status IN ('submitted', 'processing')
                    ORDER BY created_at
                    """,
                    agent_id,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT * FROM memory_extraction_batches
                    WHERE status IN ('submitted', 'processing')
                    ORDER BY created_at
                    """
                )
            return [self._row_to_extraction_batch(row) for row in rows]

    async def update_extraction_batch(
        self,
        batch_id: UUID,
        updates: dict[str, Any],
    ) -> None:
        """Update extraction batch status."""
        set_parts = []
        values = []
        for i, (field, value) in enumerate(updates.items(), start=2):
            set_parts.append(f"{field} = ${i}")
            values.append(value)

        async with self.pool.acquire() as conn:
            await conn.execute(
                f"""
                UPDATE memory_extraction_batches
                SET {", ".join(set_parts)}
                WHERE id = $1
                """,
                batch_id,
                *values,
            )

    # ==================== HELPER METHODS ====================

    def _row_to_memory(self, row: Any) -> AgentMemory:
        """Convert database row (or dict) to AgentMemory model.

        Args:
            row: asyncpg.Record or dict-like object

        Returns:
            AgentMemory instance
        """

        # Support both asyncpg.Record and plain dict for testing
        def get(key: str, default: Any = None) -> Any:
            try:
                return row[key] if row[key] is not None else default
            except (KeyError, TypeError):
                return default

        return AgentMemory(
            id=row["id"],
            agent_id=row["agent_id"],
            text=row["text"],
            embedding=list(row["embedding"]) if get("embedding") else None,
            importance_score=float(get("importance_score", 0.5)),
            memory_type=MemoryType(row["memory_type"]),
            scope=MemoryScope(get("scope", "individual")),
            created_at=row["created_at"],
            updated_at=get("updated_at"),
            expires_at=get("expires_at"),
            last_accessed=get("last_accessed"),
            happens_at=get("happens_at"),
            access_count=get("access_count", 0),
            mention_count=get("mention_count", 0),
            inbound_links=get("inbound_links") or [],
            outbound_links=get("outbound_links") or [],
            confidence=float(get("confidence", 0.9)),
            is_archived=get("is_archived", False),
            archived_at=get("archived_at"),
            is_refined=get("is_refined", False),
            last_refined_at=get("last_refined_at"),
            refinement_rejection_count=get("refinement_rejection_count", 0),
            runs_at_creation=get("runs_at_creation"),
            runs_at_last_access=get("runs_at_last_access"),
            run_id=get("run_id"),
            world_id=get("world_id"),
            issue_tags=list(get("issue_tags", [])) if get("issue_tags") else [],
            file_paths=list(get("file_paths", [])) if get("file_paths") else [],
        )

    def _memory_to_insert_params(
        self,
        memory: ExtractedMemory,
        agent_id: str,
        embedding: list[float] | None = None,
        current_runs: int = 0,
        run_id: str | None = None,
        world_id: str | None = None,
        scope: MemoryScope = MemoryScope.INDIVIDUAL,
    ) -> dict[str, Any]:
        """Convert ExtractedMemory to INSERT parameters dict.

        Args:
            memory: ExtractedMemory to convert
            agent_id: Agent identifier
            embedding: Optional embedding vector
            current_runs: Current run count for agent
            run_id: Optional run identifier
            world_id: Optional world identifier
            scope: Memory scope

        Returns:
            Dict of column->value for INSERT
        """
        return {
            "agent_id": agent_id,
            "text": memory.text,
            "embedding": embedding,
            "importance_score": memory.importance_score,
            "memory_type": memory.memory_type.value,
            "scope": scope.value,
            "confidence": memory.confidence,
            "expires_at": memory.expires_at,
            "happens_at": memory.happens_at,
            "runs_at_creation": current_runs,
            "runs_at_last_access": current_runs,
            "run_id": run_id,
            "world_id": world_id,
            "issue_tags": memory.issue_tags,
            "file_paths": memory.file_paths,
        }

    def _row_to_extraction_batch(self, row: Any) -> ExtractionBatch:
        """Convert database row to ExtractionBatch model."""
        return ExtractionBatch(
            id=row["id"],
            batch_id=row["batch_id"],
            custom_id=row["custom_id"],
            agent_id=row["agent_id"],
            run_id=row["run_id"],
            request_payload=row["request_payload"] or {},
            run_metadata=row["run_metadata"],
            memory_context=row["memory_context"],
            status=row["status"],
            created_at=row["created_at"],
            submitted_at=row["submitted_at"],
            completed_at=row["completed_at"],
            expires_at=row["expires_at"],
            result_url=row["result_url"],
            result_payload=row["result_payload"],
            extracted_memories=row["extracted_memories"],
            error_message=row["error_message"],
            retry_count=row["retry_count"],
            processing_time_ms=row["processing_time_ms"],
            tokens_used=row["tokens_used"],
        )
