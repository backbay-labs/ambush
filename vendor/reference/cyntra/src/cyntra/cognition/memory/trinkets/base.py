"""
Base classes for working memory trinkets.

Trinkets are modular context providers that generate content for agent prompts.
Each trinket focuses on a specific type of context.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RunContext:
    """
    Context for the current agent run.

    Provides all information needed for trinkets to generate relevant content.
    """

    # Agent identity
    agent_id: str
    run_id: str

    # Task context
    issue_id: str | None = None
    issue_title: str | None = None
    issue_body: str | None = None
    issue_tags: list[str] = field(default_factory=list)

    # Fab World context
    world_id: str | None = None
    world_name: str | None = None

    # Previous run history
    previous_runs: list[dict[str, Any]] = field(default_factory=list)
    retry_count: int = 0

    # Agent activity
    current_runs_count: int = 0

    # File context
    target_files: list[str] = field(default_factory=list)
    modified_files: list[str] = field(default_factory=list)

    # Error context (for retries)
    last_error: str | None = None
    last_fail_code: str | None = None


class AgentTrinket(ABC):
    """
    Base class for working memory trinkets.

    Trinkets generate context sections that are injected into agent prompts.
    They can be cached (stable across runs) or dynamic (regenerated each run).
    """

    # Whether this trinket's output should be cached
    cache_policy: bool = False

    # Priority for ordering (higher = earlier in prompt)
    priority: int = 50

    @abstractmethod
    def get_section_name(self) -> str:
        """
        Return section name for prompt injection.

        Example: "Relevant Patterns", "Known Failures"
        """
        ...

    @abstractmethod
    async def generate_content(self, ctx: RunContext) -> str:
        """
        Generate content for this trinket.

        Args:
            ctx: RunContext with run information

        Returns:
            Content string to inject (empty string if nothing to add)
        """
        ...

    async def should_include(self, ctx: RunContext) -> bool:
        """
        Check if this trinket should be included for this run.

        Override to add conditional logic.

        Args:
            ctx: RunContext with run information

        Returns:
            True if trinket should be included
        """
        return True

    def format_section(self, content: str) -> str:
        """
        Format content as a prompt section.

        Args:
            content: Raw content

        Returns:
            Formatted section with header
        """
        if not content.strip():
            return ""

        name = self.get_section_name()
        return f"\n## {name}\n\n{content.strip()}\n"
