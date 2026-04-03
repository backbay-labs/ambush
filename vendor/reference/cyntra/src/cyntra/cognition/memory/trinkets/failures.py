"""
Failures Trinket - Surface relevant failure patterns to avoid.

Provides memories of what didn't work and why.
"""

from __future__ import annotations

from ..models import AgentMemory, MemoryType
from .base import AgentTrinket, RunContext


class FailuresTrinket(AgentTrinket):
    """
    Surface relevant failure patterns for the current task.

    Helps agents avoid repeating past mistakes.
    """

    priority = 75  # High priority - failures are important to avoid

    def __init__(
        self,
        store,  # MemoryStore
        vector_ops=None,  # VectorOps
        max_failures: int = 3,
        min_importance: float = 0.2,
    ):
        """
        Initialize failures trinket.

        Args:
            store: MemoryStore for retrieval
            vector_ops: VectorOps for embeddings
            max_failures: Maximum failures to include
            min_importance: Minimum importance score
        """
        self.store = store
        self.vector_ops = vector_ops
        self.max_failures = max_failures
        self.min_importance = min_importance

    def get_section_name(self) -> str:
        return "Known Failures to Avoid"

    async def generate_content(self, ctx: RunContext) -> str:
        """Generate content with relevant failures."""
        failures = await self._find_failures(ctx)

        if not failures:
            return ""

        lines = ["The following approaches have failed in similar contexts:\n"]
        for i, failure in enumerate(failures, 1):
            lines.append(f"{i}. **Avoid**: {failure.text}")

        return "\n".join(lines)

    async def _find_failures(self, ctx: RunContext) -> list[AgentMemory]:
        """Find relevant failures."""
        # Prefer direct type search (simplest and fastest)
        if hasattr(self.store, "search_by_type"):
            failures = await self.store.search_by_type(
                memory_type=MemoryType.FAILURE,
                agent_id=ctx.agent_id,
                limit=self.max_failures,
            )
            return list(failures)

        # Fallback: try tag-based retrieval if available
        if ctx.issue_tags and hasattr(self.store, "search_by_tags"):
            tag_failures = await self.store.search_by_tags(
                tags=ctx.issue_tags,
                agent_id=ctx.agent_id,
                limit=self.max_failures,
            )
            return [f for f in tag_failures if f.memory_type == MemoryType.FAILURE]

        return []

    async def should_include(self, ctx: RunContext) -> bool:
        """Include failures especially on retries."""
        # Always include if this is a retry
        if ctx.retry_count > 0:
            return True
        # Otherwise, only if we have relevant tags/files
        return bool(ctx.issue_tags or ctx.target_files)
