"""
Codebase Trinket - Surface codebase understanding.

Provides architectural context and file-specific knowledge.
"""

from __future__ import annotations

from ..models import AgentMemory, MemoryType
from .base import AgentTrinket, RunContext


class CodebaseTrinket(AgentTrinket):
    """
    Surface relevant codebase context.

    Context memories provide:
    - File and module purposes
    - Architecture understanding
    - Important constraints
    """

    priority = 50  # Medium priority
    cache_policy = True  # Codebase context is relatively stable

    def __init__(
        self,
        store,  # MemoryStore
        max_context: int = 5,
    ):
        """
        Initialize codebase trinket.

        Args:
            store: MemoryStore for retrieval
            max_context: Maximum context items to include
        """
        self.store = store
        self.max_context = max_context

    def get_section_name(self) -> str:
        return "Codebase Context"

    async def generate_content(self, ctx: RunContext) -> str:
        """Generate content with relevant codebase context."""
        context_memories = await self._find_context(ctx)

        if not context_memories:
            return ""

        lines = []
        for memory in context_memories:
            lines.append(f"- {memory.text}")

        return "\n".join(lines)

    async def _find_context(self, ctx: RunContext) -> list[AgentMemory]:
        """Find relevant codebase context."""
        context = []

        # Search by target files
        if ctx.target_files:
            file_context = await self.store.search_by_files(
                file_paths=ctx.target_files,
                agent_id=ctx.agent_id,
                limit=self.max_context,
            )
            context.extend([c for c in file_context if c.memory_type == MemoryType.CONTEXT])

        # Search by tags
        if ctx.issue_tags:
            tag_context = await self.store.search_by_tags(
                tags=ctx.issue_tags,
                agent_id=ctx.agent_id,
                limit=self.max_context,
            )
            context.extend([c for c in tag_context if c.memory_type == MemoryType.CONTEXT])

        # Deduplicate
        seen_ids = set()
        unique_context = []
        for c in context:
            if c.id not in seen_ids:
                seen_ids.add(c.id)
                unique_context.append(c)

        unique_context.sort(key=lambda c: c.importance_score, reverse=True)
        return unique_context[: self.max_context]

    async def should_include(self, ctx: RunContext) -> bool:
        """Include codebase context when we have file targets."""
        return bool(ctx.target_files)
