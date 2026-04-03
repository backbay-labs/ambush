"""
Dynamics Trinket - Surface learned behavioral dynamics.

Provides observations about how the agent or codebase behaves.
"""

from __future__ import annotations

from ..models import AgentMemory, MemoryType
from .base import AgentTrinket, RunContext


class DynamicsTrinket(AgentTrinket):
    """
    Surface relevant behavioral dynamics.

    Dynamics are learned observations about:
    - Build/test behavior
    - Performance characteristics
    - Tooling quirks
    """

    priority = 60  # Medium priority

    def __init__(
        self,
        store,  # MemoryStore
        max_dynamics: int = 3,
        min_confidence: float = 0.7,
    ):
        """
        Initialize dynamics trinket.

        Args:
            store: MemoryStore for retrieval
            max_dynamics: Maximum dynamics to include
            min_confidence: Minimum confidence for inclusion
        """
        self.store = store
        self.max_dynamics = max_dynamics
        self.min_confidence = min_confidence

    def get_section_name(self) -> str:
        return "Behavioral Notes"

    async def generate_content(self, ctx: RunContext) -> str:
        """Generate content with relevant dynamics."""
        dynamics = await self._find_dynamics(ctx)

        if not dynamics:
            return ""

        lines = []
        for dynamic in dynamics:
            lines.append(f"- {dynamic.text}")

        return "\n".join(lines)

    async def _find_dynamics(self, ctx: RunContext) -> list[AgentMemory]:
        """Find relevant dynamics."""
        # Get dynamics by type
        dynamics = await self.store.search_by_type(
            memory_type=MemoryType.DYNAMIC,
            agent_id=ctx.agent_id,
            limit=self.max_dynamics * 2,
        )

        # Filter by confidence
        high_confidence = [d for d in dynamics if d.confidence >= self.min_confidence]

        # Prioritize by relevance to current files
        if ctx.target_files:
            relevant = []
            other = []
            for d in high_confidence:
                if any(f in d.file_paths for f in ctx.target_files):
                    relevant.append(d)
                else:
                    other.append(d)
            result = relevant + other
        else:
            result = high_confidence

        return result[: self.max_dynamics]
