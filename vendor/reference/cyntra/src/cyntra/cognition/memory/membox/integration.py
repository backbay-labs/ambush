from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyntra.cognition.memory.membox.membox_store import MemboxStore
from cyntra.cognition.memory.membox.models import MemboxMessage
from cyntra.cognition.memory.membox.topic_loom import TopicLoom, TopicLoomConfig
from cyntra.cognition.memory.membox.trace_weaver import TraceWeaver, TraceWeaverConfig


@dataclass(frozen=True)
class MemboxKernelBridgeConfig:
    episodes_root: Path = Path(".cyntra/playtest/episodes")


_executor = ThreadPoolExecutor(max_workers=2)


def _run_coro_sync(coro: Any, *, timeout_s: float = 30.0) -> Any:
    """
    Run a coroutine from synchronous code, even if an event loop is already running.

    This matches the pattern used in `cyntra.hooks.runner` to avoid nested event loops.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    future = _executor.submit(lambda: asyncio.run(coro))
    return future.result(timeout=timeout_s)


class MemboxKernelBridge:
    """
    Scaffolding bridge for integrating Membox with Cyntra.

    Phase 1 will wire this into the kernel lifecycle; for now it provides
    explicit ingestion entry points.
    """

    def __init__(
        self,
        *,
        store: MemboxStore | None = None,
        topic_loom: TopicLoom | None = None,
        trace_weaver: TraceWeaver | None = None,
        config: MemboxKernelBridgeConfig | None = None,
    ):
        self.config = config or MemboxKernelBridgeConfig()
        self.store = store or MemboxStore()
        self.topic_loom = topic_loom or TopicLoom(config=TopicLoomConfig())
        self.trace_weaver = trace_weaver or TraceWeaver(config=TraceWeaverConfig())
        try:
            self.trace_weaver.set_traces(self.store.list_traces(limit=1000))
        except Exception:
            pass

    async def ingest_episode_dir(self, episode_dir: Path) -> dict[str, Any]:
        """
        Ingest an EpisodeTrace directory produced by the playability gate.

        Uses `events.jsonl` if present; otherwise falls back to `episode_v1.json`
        (goal description) for a minimal membox.
        """
        episode_dir = episode_dir.resolve()
        events_path = episode_dir / "events.jsonl"
        episode_v1 = episode_dir / "episode_v1.json"

        messages: list[MemboxMessage] = []
        if events_path.exists():
            for line in events_path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except Exception:
                    continue
                desc = str(evt.get("description") or evt.get("event_type") or "").strip()
                if not desc:
                    continue
                messages.append(
                    MemboxMessage(
                        role="event",
                        content=desc,
                        source=f"episode:{episode_dir.name}",
                    )
                )
        elif episode_v1.exists():
            try:
                meta = json.loads(episode_v1.read_text())
            except Exception:
                meta = {}
            goal = meta.get("goal") or {}
            desc = str(goal.get("description") or "").strip()
            if desc:
                messages.append(
                    MemboxMessage(
                        role="episode_goal",
                        content=desc,
                        source=f"episode:{episode_dir.name}",
                    )
                )

        ingest = await self.ingest_messages(messages)
        ingest["episode_dir"] = str(episode_dir)
        return ingest

    async def ingest_episodes_root(self) -> dict[str, Any]:
        root = self.config.episodes_root
        if not root.exists():
            return {"success": False, "error": f"episodes_root not found: {root}"}

        count = 0
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            if child.name == "index.jsonl":
                continue
            await self.ingest_episode_dir(child)
            count += 1
        return {"success": True, "episodes_ingested": count}

    def ingest_episode_dir_sync(self, episode_dir: Path, *, timeout_s: float = 30.0) -> dict[str, Any]:
        return _run_coro_sync(self.ingest_episode_dir(episode_dir), timeout_s=timeout_s)

    def ingest_episodes_root_sync(self, *, timeout_s: float = 60.0) -> dict[str, Any]:
        return _run_coro_sync(self.ingest_episodes_root(), timeout_s=timeout_s)

    async def ingest_messages(self, messages: list[MemboxMessage]) -> dict[str, Any]:
        """
        Ingest an ordered stream of membox messages and persist the resulting memboxes/traces.

        This is the shared ingestion path for both playtest episodes and workcell coding runs.
        """
        messages = [m for m in messages if m.content and m.content.strip()]
        if not messages:
            await self.topic_loom.flush()
            return {"success": True, "messages_ingested": 0, "memboxes_written": 0}

        memboxes_written = 0
        sealed = None
        for msg in messages:
            sealed = await self.topic_loom.process_message(msg) or sealed
            if sealed:
                self.store.upsert_membox(sealed)
                links, traces = await self.trace_weaver.link_membox(sealed)
                for t in traces:
                    self.store.upsert_trace(t)
                for link in links:
                    self.store.add_trace_link(link)
                memboxes_written += 1
                sealed = None

        final_box = await self.topic_loom.flush()
        if final_box:
            self.store.upsert_membox(final_box)
            links, traces = await self.trace_weaver.link_membox(final_box)
            for t in traces:
                self.store.upsert_trace(t)
            for link in links:
                self.store.add_trace_link(link)
            memboxes_written += 1

        return {
            "success": True,
            "messages_ingested": len(messages),
            "memboxes_written": memboxes_written,
        }

    def ingest_messages_sync(self, messages: list[MemboxMessage], *, timeout_s: float = 30.0) -> dict[str, Any]:
        return _run_coro_sync(self.ingest_messages(messages), timeout_s=timeout_s)

    async def ingest_texts(self, *, source: str, texts: list[str], role: str = "note") -> dict[str, Any]:
        messages = [
            MemboxMessage(role=role, content=text, source=source)
            for text in texts
            if isinstance(text, str) and text.strip()
        ]
        return await self.ingest_messages(messages)

    def ingest_texts_sync(
        self, *, source: str, texts: list[str], role: str = "note", timeout_s: float = 30.0
    ) -> dict[str, Any]:
        return _run_coro_sync(self.ingest_texts(source=source, texts=texts, role=role), timeout_s=timeout_s)
