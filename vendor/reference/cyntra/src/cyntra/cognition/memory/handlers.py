"""
Memory Event Handlers - Process memory system events.

Handles events from kernel lifecycle to trigger memory operations:
- Extraction after runs
- Linking after extraction
- Sleeptime during idle
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from .events import (
    MemoryEvent,
    MemoryExtractionEvent,
    MemoryLinkingEvent,
    RunCompletedEvent,
    SleeptimeCompletedEvent,
)
from .models import MemoryType

logger = logging.getLogger(__name__)


@dataclass
class HandlerResult:
    """Result from event handler execution."""

    success: bool
    event_type: str
    duration_ms: float = 0.0
    items_processed: int = 0
    errors: list[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


EventHandler = Callable[[MemoryEvent], Awaitable[HandlerResult]]


class MemoryEventHandler:
    """
    Central handler for memory system events.

    Coordinates extraction, linking, and maintenance operations
    based on kernel lifecycle events.
    """

    def __init__(
        self,
        store=None,  # MemoryStore
        extractor=None,  # MemoryExtractor
        linking_service=None,  # LinkingService
        sleeptime_processor=None,  # SleeptimeProcessor
        collective_service=None,  # CollectiveMemoryService
    ):
        """
        Initialize event handler.

        Args:
            store: MemoryStore for database access
            extractor: MemoryExtractor for extraction
            linking_service: LinkingService for relationships
            sleeptime_processor: SleeptimeProcessor for maintenance
            collective_service: CollectiveMemoryService for promotion
        """
        self.store = store
        self.extractor = extractor
        self.linking_service = linking_service
        self.sleeptime_processor = sleeptime_processor
        self.collective_service = collective_service

        # Handler registry
        self._handlers: dict[str, list[EventHandler]] = {}
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register default event handlers."""
        self.register("run_completed", self.handle_run_completed)
        self.register("extraction_completed", self.handle_extraction_completed)
        self.register("linking_completed", self.handle_linking_completed)
        self.register("sleeptime_triggered", self.handle_sleeptime_triggered)

    def register(self, event_type: str, handler: EventHandler) -> None:
        """
        Register an event handler.

        Args:
            event_type: Type of event to handle
            handler: Async handler function
        """
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
        logger.debug(f"Registered handler for {event_type}")

    async def handle(self, event: MemoryEvent) -> HandlerResult:
        """
        Handle an event by dispatching to registered handlers.

        Args:
            event: Event to handle

        Returns:
            Combined handler result
        """
        event_type = event.event_type
        handlers = self._handlers.get(event_type, [])

        if not handlers:
            logger.debug(f"No handlers for event type: {event_type}")
            return HandlerResult(
                success=True,
                event_type=event_type,
            )

        start_time = datetime.utcnow()
        errors = []
        items_processed = 0

        for handler in handlers:
            try:
                result = await handler(event)
                items_processed += result.items_processed
                if result.errors:
                    errors.extend(result.errors)
            except Exception as e:
                logger.error(f"Handler failed for {event_type}: {e}")
                errors.append(str(e))

        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

        return HandlerResult(
            success=len(errors) == 0,
            event_type=event_type,
            duration_ms=duration_ms,
            items_processed=items_processed,
            errors=errors,
        )

    async def handle_run_completed(
        self,
        event: RunCompletedEvent,
    ) -> HandlerResult:
        """
        Handle run completion - trigger memory extraction.

        Args:
            event: Run completed event

        Returns:
            Handler result
        """
        if not self.extractor:
            return HandlerResult(
                success=False,
                event_type="run_completed",
                errors=["Extractor not configured"],
            )

        start_time = datetime.utcnow()
        errors = []
        extracted_count = 0

        try:
            # Extract memories from run transcript
            memories = await self.extractor.extract_from_run(
                run_id=event.run_id,
                agent_id=event.agent_id,
                transcript=event.transcript,
                issue_tags=event.issue_tags,
                file_paths=event.file_changes,  # file_changes from RunCompletedEvent
            )

            extracted_count = len(memories)

            # Emit extraction completed event
            if memories:
                extraction_event = MemoryExtractionEvent.create(
                    agent_id=event.agent_id,
                    run_id=event.run_id,
                    batch_id=f"batch_{event.run_id}",
                    memory_count_estimate=extracted_count,
                )
                # Store memory_ids in data for handler access
                extraction_event = MemoryExtractionEvent(
                    agent_id=event.agent_id,
                    run_id=event.run_id,
                    batch_id=f"batch_{event.run_id}",
                    memory_count_estimate=extracted_count,
                    data={"memory_ids": [str(m.id) for m in memories]},
                )
                await self.handle(extraction_event)

            logger.info(f"Extracted {extracted_count} memories from run {event.run_id}")

        except Exception as e:
            logger.error(f"Extraction failed for run {event.run_id}: {e}")
            errors.append(str(e))

        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

        return HandlerResult(
            success=len(errors) == 0,
            event_type="run_completed",
            duration_ms=duration_ms,
            items_processed=extracted_count,
            errors=errors,
        )

    async def handle_extraction_completed(
        self,
        event: MemoryExtractionEvent,
    ) -> HandlerResult:
        """
        Handle extraction completion - trigger linking.

        Args:
            event: Extraction completed event

        Returns:
            Handler result
        """
        if not self.linking_service:
            return HandlerResult(
                success=False,
                event_type="extraction_completed",
                errors=["Linking service not configured"],
            )

        start_time = datetime.utcnow()
        errors = []
        links_created = 0

        try:
            # Get memory IDs from event data
            memory_ids = event.data.get("memory_ids", [])
            if isinstance(memory_ids, list):
                memory_ids = [UUID(mid) if isinstance(mid, str) else mid for mid in memory_ids]

            # Link each extracted memory to existing memories
            for memory_id in memory_ids:
                memory = await self.store.get(memory_id)
                if not memory:
                    continue

                # Find and create links
                candidates = await self.linking_service.find_link_candidates(memory)
                for candidate in candidates:
                    link = await self.linking_service.classify_relationship(memory, candidate)
                    if link:
                        await self.linking_service.create_bidirectional_link(link)
                        links_created += 1

            # Emit linking completed event
            if links_created > 0:
                MemoryLinkingEvent.create(
                    agent_id=event.agent_id,
                    memory_ids=memory_ids,
                    batch_id=event.batch_id,
                    pair_count=links_created,
                )
                # Note: Don't recursively handle to avoid loops
                logger.info(f"Created {links_created} links for {len(memory_ids)} memories")

        except Exception as e:
            logger.error(f"Linking failed: {e}")
            errors.append(str(e))

        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

        return HandlerResult(
            success=len(errors) == 0,
            event_type="extraction_completed",
            duration_ms=duration_ms,
            items_processed=links_created,
            errors=errors,
        )

    async def handle_linking_completed(
        self,
        event: MemoryLinkingEvent,
    ) -> HandlerResult:
        """
        Handle linking completion - check for pattern promotion.

        Args:
            event: Linking completed event

        Returns:
            Handler result
        """
        if not self.collective_service:
            return HandlerResult(
                success=True,
                event_type="linking_completed",
            )

        start_time = datetime.utcnow()
        promoted = 0

        try:
            # Check if any linked memories should be promoted
            for memory_id in event.memory_ids:
                memory = await self.store.get(memory_id)
                if not memory:
                    continue

                # Only check high-importance patterns
                if memory.memory_type == MemoryType.PATTERN and memory.importance_score >= 0.6:
                    similar = await self.collective_service.find_similar_across_agents(memory)
                    if len(similar) >= 2 and await self.collective_service.promote_to_collective(
                        memory_id=memory.id,
                        validation_agents=[s.agent_id for s in similar],
                    ):
                        promoted += 1

        except Exception as e:
            logger.warning(f"Pattern promotion check failed: {e}")

        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

        return HandlerResult(
            success=True,
            event_type="linking_completed",
            duration_ms=duration_ms,
            items_processed=promoted,
        )

    async def handle_sleeptime_triggered(
        self,
        event: MemoryEvent,
    ) -> HandlerResult:
        """
        Handle sleeptime trigger - run maintenance operations.

        Args:
            event: Sleeptime trigger event

        Returns:
            Handler result
        """
        if not self.sleeptime_processor:
            return HandlerResult(
                success=False,
                event_type="sleeptime_triggered",
                errors=["Sleeptime processor not configured"],
            )

        start_time = datetime.utcnow()
        errors = []

        try:
            agent_id = event.data.get("agent_id", "default")
            report = await self.sleeptime_processor.process(agent_id)

            # Emit sleeptime completed event
            SleeptimeCompletedEvent.create(
                agent_id=agent_id,
                memories_consolidated=report.memories_consolidated,
                patterns_discovered=report.patterns_discovered,
                memories_archived=report.memories_archived,
                duration_seconds=report.duration_seconds,
            )

            logger.info(
                f"Sleeptime completed for {agent_id}: "
                f"consolidated={report.memories_consolidated}, "
                f"patterns={report.patterns_discovered}, "
                f"archived={report.memories_archived}"
            )

            if report.errors:
                errors.extend(report.errors)

        except Exception as e:
            logger.error(f"Sleeptime processing failed: {e}")
            errors.append(str(e))

        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

        return HandlerResult(
            success=len(errors) == 0,
            event_type="sleeptime_triggered",
            duration_ms=duration_ms,
            errors=errors,
        )


class MemoryEventBus:
    """
    Simple event bus for memory system events.

    Provides async event publishing and subscription.
    """

    def __init__(self, handler: MemoryEventHandler | None = None):
        """
        Initialize event bus.

        Args:
            handler: Optional default event handler
        """
        self.handler = handler
        self._subscribers: dict[str, list[Callable]] = {}

    def subscribe(
        self,
        event_type: str,
        callback: Callable[[MemoryEvent], Awaitable[None]],
    ) -> None:
        """
        Subscribe to an event type.

        Args:
            event_type: Type of event to subscribe to
            callback: Async callback function
        """
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)

    async def publish(self, event: MemoryEvent) -> list[HandlerResult]:
        """
        Publish an event to all subscribers.

        Args:
            event: Event to publish

        Returns:
            List of handler results
        """
        results = []

        # Call default handler first
        if self.handler:
            result = await self.handler.handle(event)
            results.append(result)

        # Call subscribers
        subscribers = self._subscribers.get(event.event_type, [])
        for callback in subscribers:
            try:
                await callback(event)
            except Exception as e:
                logger.error(f"Event subscriber failed: {e}")
                results.append(
                    HandlerResult(
                        success=False,
                        event_type=event.event_type,
                        errors=[str(e)],
                    )
                )

        return results


# Singleton event bus for global access
_event_bus: MemoryEventBus | None = None


def get_event_bus() -> MemoryEventBus:
    """Get the global event bus instance."""
    global _event_bus
    if _event_bus is None:
        _event_bus = MemoryEventBus()
    return _event_bus


def configure_event_bus(handler: MemoryEventHandler) -> MemoryEventBus:
    """
    Configure the global event bus with a handler.

    Args:
        handler: Event handler to use

    Returns:
        Configured event bus
    """
    global _event_bus
    _event_bus = MemoryEventBus(handler=handler)
    return _event_bus
