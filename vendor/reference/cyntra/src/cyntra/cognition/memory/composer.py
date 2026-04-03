"""
Agent Prompt Composer - Assemble working memory trinkets.

Handles composition of system prompts by collecting sections from
trinkets and assembling them in priority order with caching awareness.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .trinkets.base import AgentTrinket, RunContext

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class ComposerConfig:
    """Configuration for the agent prompt composer."""

    # Section ordering (by trinket type)
    section_order: list[str] = field(
        default_factory=lambda: [
            # Cached sections (cache_policy=True) - must be first for prefix caching
            "Base System",  # Static base prompt
            "Codebase Context",  # Codebase understanding (changes infrequently)
            "Playbook",  # Repair instructions (stable per retry)
            # Dynamic sections (cache_policy=False)
            "Task Context",  # Issue details, retry context
            "Patterns",  # Relevant successful patterns
            "Failures",  # Failure patterns to avoid
            "Dynamics",  # Behavioral predictions
        ]
    )
    section_separator: str = "\n\n---\n\n"
    strip_empty_sections: bool = True

    # Token limits
    max_cached_tokens: int = 4000
    max_dynamic_tokens: int = 2000


@dataclass
class ComposedPrompt:
    """Result of prompt composition."""

    cached_content: str  # Stable sections (prefix caching)
    dynamic_content: str  # Per-run sections

    # Metadata
    section_count: int = 0
    cached_sections: int = 0
    dynamic_sections: int = 0
    total_chars: int = 0

    def to_system_prompt(self) -> str:
        """Combine into single system prompt."""
        if self.cached_content and self.dynamic_content:
            return f"{self.cached_content}\n\n---\n\n{self.dynamic_content}"
        return self.cached_content or self.dynamic_content


class AgentPromptComposer:
    """
    Composes agent prompts by collecting and ordering trinket sections.

    Features:
    - Priority-based ordering of trinkets
    - Cache-aware grouping for prefix caching
    - Token limit enforcement
    - Dynamic section generation
    """

    def __init__(
        self,
        trinkets: list[AgentTrinket],
        config: ComposerConfig | None = None,
        base_prompt: str | None = None,
    ):
        """
        Initialize the composer with trinkets.

        Args:
            trinkets: List of AgentTrinket instances
            config: Composer configuration
            base_prompt: Optional static base system prompt
        """
        self.trinkets = sorted(trinkets, key=lambda t: t.priority, reverse=True)
        self.config = config or ComposerConfig()
        self.base_prompt = base_prompt

        # Internal section storage
        self._sections: dict[str, str] = {}
        self._cache_policies: dict[str, bool] = {}

        logger.info(f"AgentPromptComposer initialized with {len(trinkets)} trinkets")

    async def compose(self, ctx: RunContext) -> ComposedPrompt:
        """
        Compose the system prompt from all trinkets.

        Args:
            ctx: Run context for dynamic generation

        Returns:
            ComposedPrompt with cached and dynamic content
        """
        self._sections.clear()
        self._cache_policies.clear()

        # Add base prompt if provided
        if self.base_prompt:
            self._sections["Base System"] = self.base_prompt
            self._cache_policies["Base System"] = True

        # Generate content from each trinket
        for trinket in self.trinkets:
            try:
                # Check if trinket should be included
                if not await trinket.should_include(ctx):
                    logger.debug(f"Skipping trinket {trinket.get_section_name()}")
                    continue

                # Generate content
                content = await trinket.generate_content(ctx)
                if not content or not content.strip():
                    continue

                section_name = trinket.get_section_name()
                self._sections[section_name] = content
                self._cache_policies[section_name] = trinket.cache_policy

                logger.debug(
                    f"Added section '{section_name}' "
                    f"({len(content)} chars, cache={trinket.cache_policy})"
                )

            except Exception as e:
                logger.warning(f"Trinket {trinket.__class__.__name__} failed: {e}")

        # Compose into grouped sections
        return self._assemble()

    def _assemble(self) -> ComposedPrompt:
        """Assemble sections into cached/dynamic groups."""
        if not self._sections:
            logger.warning("No sections to compose")
            return ComposedPrompt(
                cached_content="",
                dynamic_content="",
            )

        cached_parts: list[str] = []
        dynamic_parts: list[str] = []

        # Process sections in configured order
        for section_name in self.config.section_order:
            if section_name in self._sections:
                content = self._sections[section_name]
                if self.config.strip_empty_sections and not content.strip():
                    continue

                # Format section with header
                formatted = self._format_section(section_name, content)

                # Group by cache policy
                if self._cache_policies.get(section_name, False):
                    cached_parts.append(formatted)
                else:
                    dynamic_parts.append(formatted)

        # Handle sections not in configured order
        extra_sections = set(self._sections.keys()) - set(self.config.section_order)
        if extra_sections:
            logger.debug(f"Extra sections not in order: {extra_sections}")
            for section_name in sorted(extra_sections):
                content = self._sections[section_name]
                if self.config.strip_empty_sections and not content.strip():
                    continue

                formatted = self._format_section(section_name, content)
                if self._cache_policies.get(section_name, False):
                    cached_parts.append(formatted)
                else:
                    dynamic_parts.append(formatted)

        # Join and clean
        cached_content = self._clean_content(self.config.section_separator.join(cached_parts))
        dynamic_content = self._clean_content(self.config.section_separator.join(dynamic_parts))

        result = ComposedPrompt(
            cached_content=cached_content,
            dynamic_content=dynamic_content,
            section_count=len(self._sections),
            cached_sections=len(cached_parts),
            dynamic_sections=len(dynamic_parts),
            total_chars=len(cached_content) + len(dynamic_content),
        )

        logger.info(
            f"Composed prompt: {result.cached_sections} cached sections "
            f"({len(cached_content)} chars), "
            f"{result.dynamic_sections} dynamic sections "
            f"({len(dynamic_content)} chars)"
        )

        return result

    def _format_section(self, name: str, content: str) -> str:
        """Format a section with header."""
        return f"## {name}\n\n{content}"

    def _clean_content(self, content: str) -> str:
        """Clean up excessive whitespace."""
        # Replace 3+ newlines with exactly 2
        content = re.sub(r"\n{3,}", "\n\n", content)
        return content.strip()

    def add_section(
        self,
        name: str,
        content: str,
        cache_policy: bool = False,
    ) -> None:
        """
        Manually add a section.

        Args:
            name: Section name
            content: Section content
            cache_policy: Whether section should be cached
        """
        if not content or not content.strip():
            return

        self._sections[name] = content
        self._cache_policies[name] = cache_policy

    def clear_sections(self, preserve_base: bool = True) -> None:
        """Clear all sections."""
        base = self._sections.get("Base System") if preserve_base else None
        base_cache = self._cache_policies.get("Base System") if preserve_base else None

        self._sections.clear()
        self._cache_policies.clear()

        if base:
            self._sections["Base System"] = base
            self._cache_policies["Base System"] = base_cache


class TrinketRegistry:
    """
    Registry for available trinkets.

    Provides factory methods for common trinket configurations.
    """

    _trinkets: dict[str, type] = {}

    @classmethod
    def register(cls, name: str, trinket_class: type) -> None:
        """Register a trinket type."""
        cls._trinkets[name] = trinket_class

    @classmethod
    def get(cls, name: str) -> type | None:
        """Get a registered trinket type."""
        return cls._trinkets.get(name)

    @classmethod
    def create_default_set(
        cls,
        store,
        vector_ops=None,
    ) -> list[AgentTrinket]:
        """
        Create the default set of trinkets.

        Args:
            store: MemoryStore for retrieval
            vector_ops: VectorOps for embeddings

        Returns:
            List of initialized trinkets
        """
        from .trinkets.codebase import CodebaseTrinket
        from .trinkets.dynamics import DynamicsTrinket
        from .trinkets.failures import FailuresTrinket
        from .trinkets.patterns import PatternsTrinket
        from .trinkets.playbook import PlaybookTrinket
        from .trinkets.task_context import TaskContextTrinket

        trinkets = [
            TaskContextTrinket(),
            PatternsTrinket(store=store, vector_ops=vector_ops),
            FailuresTrinket(store=store, vector_ops=vector_ops),
            DynamicsTrinket(store=store),
            CodebaseTrinket(store=store),
            PlaybookTrinket(store=store),
        ]

        return trinkets


def create_composer(
    store,
    vector_ops=None,
    base_prompt: str | None = None,
    config: ComposerConfig | None = None,
) -> AgentPromptComposer:
    """
    Factory function to create a fully configured composer.

    Args:
        store: MemoryStore instance
        vector_ops: VectorOps instance
        base_prompt: Optional base system prompt
        config: Optional composer configuration

    Returns:
        Configured AgentPromptComposer
    """
    trinkets = TrinketRegistry.create_default_set(store, vector_ops)
    return AgentPromptComposer(
        trinkets=trinkets,
        config=config,
        base_prompt=base_prompt,
    )
