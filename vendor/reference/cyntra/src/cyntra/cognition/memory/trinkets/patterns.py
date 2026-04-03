"""
Patterns Trinket - Surface relevant successful patterns.

Provides memories of what worked in similar contexts.
"""

from __future__ import annotations

from ..models import AgentMemory, MemoryType
from .base import AgentTrinket, RunContext


class PatternsTrinket(AgentTrinket):
    """
    Surface relevant successful patterns for the current task.

    Uses semantic search to find patterns that match:
    - Issue tags
    - File paths
    - Issue content
    """

    priority = 80  # High priority - patterns are valuable

    def __init__(
        self,
        store,  # MemoryStore
        vector_ops=None,  # VectorOps
        max_patterns: int = 5,
        min_importance: float = 0.3,
    ):
        """
        Initialize patterns trinket.

        Args:
            store: MemoryStore for retrieval
            vector_ops: VectorOps for embeddings
            max_patterns: Maximum patterns to include
            min_importance: Minimum importance score
        """
        self.store = store
        self.vector_ops = vector_ops
        self.max_patterns = max_patterns
        self.min_importance = min_importance

    def get_section_name(self) -> str:
        return "Relevant Patterns"

    async def generate_content(self, ctx: RunContext) -> str:
        """Generate content with relevant patterns."""
        patterns = await self._find_patterns(ctx)

        if not patterns:
            return ""

        lines = []
        for i, pattern in enumerate(patterns, 1):
            confidence = f"({pattern.confidence:.0%} confidence)"
            lines.append(f"{i}. {pattern.text} {confidence}")

        return "\n".join(lines)

    async def _find_patterns(self, ctx: RunContext) -> list[AgentMemory]:
        """Find relevant patterns using multi-signal retrieval."""
        patterns = []

        # 1. Search by tags
        if ctx.issue_tags:
            tag_patterns = await self.store.search_by_tags(
                tags=ctx.issue_tags,
                agent_id=ctx.agent_id,
                limit=self.max_patterns,
            )
            patterns.extend([p for p in tag_patterns if p.memory_type == MemoryType.PATTERN])

        # 2. Search by file paths
        if ctx.target_files:
            file_patterns = await self.store.search_by_files(
                file_paths=ctx.target_files,
                agent_id=ctx.agent_id,
                limit=self.max_patterns,
            )
            patterns.extend([p for p in file_patterns if p.memory_type == MemoryType.PATTERN])

        # 3. Semantic search on issue content (title-only is still useful)
        if self.vector_ops and (ctx.issue_title or ctx.issue_body):
            query_text = f"{ctx.issue_title or ''} {ctx.issue_body or ''}".strip()
            embedding = await self.vector_ops.generate_embedding(query_text)

            semantic_patterns = await self.store.search_similar(
                embedding=embedding,
                agent_id=ctx.agent_id,
                limit=self.max_patterns,
                min_importance=self.min_importance,
            )
            patterns.extend([p for p in semantic_patterns if p.memory_type == MemoryType.PATTERN])

        # Deduplicate by ID and sort by importance
        seen_ids = set()
        unique_patterns = []
        for p in patterns:
            if p.id not in seen_ids:
                seen_ids.add(p.id)
                unique_patterns.append(p)

        # Sort by importance and limit
        unique_patterns.sort(key=lambda p: p.importance_score, reverse=True)
        return unique_patterns[: self.max_patterns]
