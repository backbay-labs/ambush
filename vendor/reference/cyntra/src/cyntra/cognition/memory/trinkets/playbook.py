"""
Playbook Trinket - Surface repair instructions for retries.

Provides specific fixes for known failure modes.
"""

from __future__ import annotations

from ..models import AgentMemory, MemoryType
from .base import AgentTrinket, RunContext


class PlaybookTrinket(AgentTrinket):
    """
    Surface repair playbook for retry scenarios.

    Playbooks are specific repair instructions for:
    - Known error codes
    - Common failure patterns
    - Gate failures
    """

    priority = 90  # Highest priority on retries

    def __init__(
        self,
        store,  # MemoryStore
        vector_ops,  # VectorOps
        max_instructions: int = 3,
    ):
        """
        Initialize playbook trinket.

        Args:
            store: MemoryStore for retrieval
            vector_ops: VectorOps for error matching
            max_instructions: Maximum instructions to include
        """
        self.store = store
        self.vector_ops = vector_ops
        self.max_instructions = max_instructions

    def get_section_name(self) -> str:
        return "Repair Instructions"

    async def generate_content(self, ctx: RunContext) -> str:
        """Generate content with repair instructions."""
        if not ctx.last_error and not ctx.last_fail_code:
            return ""

        playbooks = await self._find_playbooks(ctx)

        if not playbooks:
            return ""

        lines = [
            f"Previous attempt failed with: {ctx.last_fail_code or 'unknown error'}",
            "",
            "Follow these repair instructions:",
            "",
        ]

        for i, playbook in enumerate(playbooks, 1):
            lines.append(f"{i}. {playbook.text}")

        return "\n".join(lines)

    async def _find_playbooks(self, ctx: RunContext) -> list[AgentMemory]:
        """Find relevant playbooks for the error."""
        playbooks = []

        # Search by type first
        all_playbooks = await self.store.search_by_type(
            memory_type=MemoryType.PLAYBOOK,
            agent_id=ctx.agent_id,
            limit=20,
        )

        # If we have an error, find matching playbooks
        if ctx.last_error and self.vector_ops:
            error_embedding = await self.vector_ops.generate_embedding(ctx.last_error)

            # Score playbooks by similarity to error
            scored = []
            for pb in all_playbooks:
                if pb.embedding:
                    sim = self.vector_ops.cosine_similarity(error_embedding, pb.embedding)
                    scored.append((pb, sim))

            # Sort by similarity
            scored.sort(key=lambda x: x[1], reverse=True)
            playbooks = [pb for pb, sim in scored[: self.max_instructions] if sim > 0.5]

        # Fallback to highest importance playbooks
        if not playbooks:
            playbooks = sorted(all_playbooks, key=lambda p: p.importance_score, reverse=True)[
                : self.max_instructions
            ]

        return playbooks

    async def should_include(self, ctx: RunContext) -> bool:
        """Only include on retries with errors."""
        return ctx.retry_count > 0 and bool(ctx.last_error or ctx.last_fail_code)
