"""
Task Context Trinket - Inject task-specific context.

Provides issue details and previous attempt summaries.
"""

from __future__ import annotations

from .base import AgentTrinket, RunContext


class TaskContextTrinket(AgentTrinket):
    """
    Surface task-specific context.

    Includes:
    - Issue details and tags
    - Previous attempt summaries
    - Retry context
    """

    priority = 100  # Highest priority - always first
    cache_policy = False  # Dynamic per run

    def __init__(
        self,
        max_previous_runs: int = 3,
    ):
        """
        Initialize task context trinket.

        Args:
            max_previous_runs: Maximum previous runs to summarize
        """
        self.max_previous_runs = max_previous_runs

    def get_section_name(self) -> str:
        return "Task Context"

    async def generate_content(self, ctx: RunContext) -> str:
        """Generate task context content."""
        lines = []

        # Issue details
        if ctx.issue_title:
            lines.append(f"**Issue**: {ctx.issue_title}")

        if ctx.issue_tags:
            lines.append(f"**Tags**: {', '.join(ctx.issue_tags)}")

        # Fab World context
        if ctx.world_name:
            lines.append(f"**Fab World**: {ctx.world_name}")

        # Target files
        if ctx.target_files:
            files_str = ", ".join(ctx.target_files[:5])
            if len(ctx.target_files) > 5:
                files_str += f" (+{len(ctx.target_files) - 5} more)"
            lines.append(f"**Target Files**: {files_str}")

        # Retry context
        if ctx.retry_count > 0:
            lines.append("")
            lines.append(f"**Retry #{ctx.retry_count}**")

            if ctx.last_fail_code:
                lines.append(f"Previous failure: {ctx.last_fail_code}")

            if ctx.last_error:
                # Truncate long errors
                error = ctx.last_error[:500]
                if len(ctx.last_error) > 500:
                    error += "..."
                lines.append(f"Error: {error}")

        # Previous run summaries
        if ctx.previous_runs:
            lines.append("")
            lines.append("**Previous Attempts**:")
            for i, run in enumerate(ctx.previous_runs[: self.max_previous_runs]):
                status = run.get("status", "unknown")
                summary = run.get("summary", "No summary available")
                lines.append(f"  {i + 1}. [{status}] {summary[:100]}")

        return "\n".join(lines)

    async def should_include(self, ctx: RunContext) -> bool:
        """Always include task context."""
        return True
