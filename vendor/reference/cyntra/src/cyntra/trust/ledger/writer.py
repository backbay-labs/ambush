"""
Ledger Writer - Multi-sink event writer.

Writes ledger events to multiple sinks (JSONL files, databases, WebSocket)
for different observability use cases.
"""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cyntra.trust.ledger.events import LedgerEvent

logger = logging.getLogger(__name__)


class LedgerSink(ABC):
    """
    Abstract base class for ledger event sinks.

    A sink is a destination for ledger events (file, database, WebSocket, etc.).
    """

    name: str

    @abstractmethod
    async def write(self, event: LedgerEvent) -> None:
        """Write an event to this sink."""
        ...

    async def flush(self) -> None:
        """Flush any buffered events. Override if needed."""
        pass

    async def close(self) -> None:
        """Close the sink. Override if cleanup is needed."""
        pass


class LedgerWriter:
    """
    Multi-sink event writer with correlation.

    Writes events to multiple sinks in parallel, with error isolation
    so that one failing sink doesn't affect others.

    Example:
        writer = LedgerWriter([
            JSONLSink(Path("logs/events.jsonl")),
            WebSocketSink(ws_manager),
        ])

        await writer.emit(StepStartedEvent(...))
    """

    def __init__(self, sinks: list[LedgerSink] | None = None):
        """
        Initialize the writer with sinks.

        Args:
            sinks: List of sinks to write to. If None, events are logged only.
        """
        self.sinks = sinks or []
        self._buffer: list[LedgerEvent] = []
        self._buffer_size = 100
        self._lock = asyncio.Lock()

    def add_sink(self, sink: LedgerSink) -> None:
        """Add a sink to the writer."""
        self.sinks.append(sink)

    def remove_sink(self, sink_name: str) -> None:
        """Remove a sink by name."""
        self.sinks = [s for s in self.sinks if s.name != sink_name]

    async def emit(self, event: LedgerEvent) -> None:
        """
        Emit an event to all sinks.

        Events are written to all sinks in parallel. Sink failures are
        logged but don't propagate - the ledger is for observability,
        not critical path.

        Args:
            event: Event to emit
        """
        # Log the event regardless of sinks
        logger.debug(f"Ledger event: {event.type.value} run={event.run_id} step={event.step_id}")

        if not self.sinks:
            return

        # Write to all sinks in parallel
        tasks = [self._write_to_sink(sink, event) for sink in self.sinks]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _write_to_sink(self, sink: LedgerSink, event: LedgerEvent) -> None:
        """Write to a single sink with error handling."""
        try:
            await sink.write(event)
        except Exception as e:
            logger.warning(f"Ledger sink {sink.name} failed: {e}")

    async def flush(self) -> None:
        """Flush all sinks."""
        tasks = [sink.flush() for sink in self.sinks]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def close(self) -> None:
        """Close all sinks."""
        await self.flush()
        tasks = [sink.close() for sink in self.sinks]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def __aenter__(self) -> LedgerWriter:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()


class JSONLSink(LedgerSink):
    """
    Write events to a JSONL file.

    Each event is written as a single JSON line, suitable for
    log aggregation tools and offline analysis.
    """

    name = "jsonl"

    def __init__(self, path: Path, buffer_size: int = 10):
        """
        Initialize the JSONL sink.

        Args:
            path: Path to the JSONL file
            buffer_size: Number of events to buffer before writing
        """
        self.path = path
        self.buffer_size = buffer_size
        self._buffer: list[str] = []
        self._lock = asyncio.Lock()

    async def write(self, event: LedgerEvent) -> None:
        """Write event to buffer, flush if buffer is full."""
        async with self._lock:
            self._buffer.append(event.to_json())

            if len(self._buffer) >= self.buffer_size:
                await self._flush_buffer()

    async def _flush_buffer(self) -> None:
        """Flush buffer to file."""
        if not self._buffer:
            return

        # Ensure parent directory exists
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # Write all buffered events
        async with asyncio.Lock():
            with open(self.path, "a") as f:
                for line in self._buffer:
                    f.write(line + "\n")
            self._buffer.clear()

    async def flush(self) -> None:
        """Flush any remaining events."""
        async with self._lock:
            await self._flush_buffer()


class MemorySink(LedgerSink):
    """
    In-memory sink for testing and debugging.

    Stores all events in a list for later inspection.
    """

    name = "memory"

    def __init__(self, max_events: int = 10000):
        """
        Initialize the memory sink.

        Args:
            max_events: Maximum events to store (oldest dropped when exceeded)
        """
        self.events: list[LedgerEvent] = []
        self.max_events = max_events

    async def write(self, event: LedgerEvent) -> None:
        """Store event in memory."""
        self.events.append(event)

        # Trim if over max
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]

    def get_events(
        self,
        run_id: str | None = None,
        step_id: str | None = None,
        event_type: str | None = None
    ) -> list[LedgerEvent]:
        """
        Query stored events.

        Args:
            run_id: Filter by run ID
            step_id: Filter by step ID
            event_type: Filter by event type

        Returns:
            Matching events
        """
        results = self.events

        if run_id:
            results = [e for e in results if e.run_id == run_id]
        if step_id:
            results = [e for e in results if e.step_id == step_id]
        if event_type:
            results = [e for e in results if e.type.value == event_type]

        return results

    def clear(self) -> None:
        """Clear all stored events."""
        self.events.clear()


class CallbackSink(LedgerSink):
    """
    Sink that calls a callback function for each event.

    Useful for custom integrations and testing.
    """

    name = "callback"

    def __init__(self, callback, name: str = "callback"):
        """
        Initialize the callback sink.

        Args:
            callback: Async function to call with each event
            name: Name for this sink instance
        """
        self.callback = callback
        self.name = name

    async def write(self, event: LedgerEvent) -> None:
        """Call the callback with the event."""
        if asyncio.iscoroutinefunction(self.callback):
            await self.callback(event)
        else:
            self.callback(event)


class FilteredSink(LedgerSink):
    """
    Sink wrapper that filters events before passing to inner sink.
    """

    def __init__(
        self,
        inner: LedgerSink,
        event_types: list[str] | None = None,
        run_ids: list[str] | None = None,
        name: str | None = None
    ):
        """
        Initialize filtered sink.

        Args:
            inner: Inner sink to write filtered events to
            event_types: Only pass events of these types (None = all)
            run_ids: Only pass events for these runs (None = all)
            name: Name for this sink
        """
        self.inner = inner
        self.event_types = set(event_types) if event_types else None
        self.run_ids = set(run_ids) if run_ids else None
        self.name = name or f"filtered:{inner.name}"

    async def write(self, event: LedgerEvent) -> None:
        """Filter and write event."""
        # Check event type filter
        if self.event_types and event.type.value not in self.event_types:
            return

        # Check run ID filter
        if self.run_ids and event.run_id not in self.run_ids:
            return

        await self.inner.write(event)

    async def flush(self) -> None:
        await self.inner.flush()

    async def close(self) -> None:
        await self.inner.close()


# Optional sinks (require additional dependencies)

def get_clickhouse_sink(
    host: str = "localhost",
    port: int = 9000,
    database: str = "cyntra",
    table: str = "events"
):
    """
    Create a ClickHouse sink.

    Requires: clickhouse-connect package

    Args:
        host: ClickHouse host
        port: ClickHouse port
        database: Database name
        table: Table name

    Returns:
        ClickHouseSink instance
    """
    try:
        import clickhouse_connect
    except ImportError:
        raise ImportError("clickhouse-connect required for ClickHouseSink")

    class ClickHouseSink(LedgerSink):
        name = "clickhouse"

        def __init__(self, client, table: str):
            self.client = client
            self.table = table
            self._buffer: list[dict] = []
            self._buffer_size = 100

        async def write(self, event: LedgerEvent) -> None:
            self._buffer.append(event.to_dict())
            if len(self._buffer) >= self._buffer_size:
                await self.flush()

        async def flush(self) -> None:
            if not self._buffer:
                return

            # Run in thread pool since clickhouse-connect is sync
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.insert(
                    self.table,
                    self._buffer,
                    column_names=list(self._buffer[0].keys())
                )
            )
            self._buffer.clear()

    client = clickhouse_connect.get_client(
        host=host,
        port=port,
        database=database
    )
    return ClickHouseSink(client, table)


def get_websocket_sink(ws_manager):
    """
    Create a WebSocket sink for real-time streaming.

    Args:
        ws_manager: WebSocket manager with broadcast capability

    Returns:
        WebSocketSink instance
    """

    class WebSocketSink(LedgerSink):
        name = "websocket"

        def __init__(self, ws_manager):
            self.ws_manager = ws_manager

        async def write(self, event: LedgerEvent) -> None:
            channel = f"run:{event.run_id}"
            await self.ws_manager.broadcast(channel, event.to_dict())

    return WebSocketSink(ws_manager)
