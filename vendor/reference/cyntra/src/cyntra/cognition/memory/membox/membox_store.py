from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cyntra.cognition.memory.membox.models import EventTrace, Membox, TraceLink


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class MemboxStoreConfig:
    db_path: Path = Path(".cyntra/memory/cyntra-mem.db")


class MemboxStore:
    """
    Membox persistence on the existing local Cyntra memory DB (SQLite).

    Creates its own tables inside the same DB file used by `cyntra.memory.database.MemoryDB`.
    """

    def __init__(self, *, config: MemboxStoreConfig | None = None):
        self.config = config or MemboxStoreConfig()
        self.db_path = self.config.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS memboxes (
                id TEXT PRIMARY KEY,
                topic TEXT NOT NULL,
                keywords TEXT,
                events TEXT,
                messages TEXT,
                created_at TEXT NOT NULL,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS event_traces (
                id TEXT PRIMARY KEY,
                summary TEXT NOT NULL,
                events TEXT,
                membox_ids TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS membox_trace_links (
                id TEXT PRIMARY KEY,
                membox_id TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                link_type TEXT NOT NULL,
                confidence REAL DEFAULT 0.0,
                reasoning TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY (membox_id) REFERENCES memboxes(id),
                FOREIGN KEY (trace_id) REFERENCES event_traces(id)
            );

            CREATE INDEX IF NOT EXISTS idx_memboxes_created_at ON memboxes(created_at);
            CREATE INDEX IF NOT EXISTS idx_traces_updated_at ON event_traces(updated_at);
            CREATE INDEX IF NOT EXISTS idx_links_membox_id ON membox_trace_links(membox_id);
            CREATE INDEX IF NOT EXISTS idx_links_trace_id ON membox_trace_links(trace_id);
        """)
        conn.commit()

    def upsert_membox(self, membox: Membox) -> None:
        conn = self._get_conn()
        conn.execute(
            """
            INSERT INTO memboxes (id, topic, keywords, events, messages, created_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                topic=excluded.topic,
                keywords=excluded.keywords,
                events=excluded.events,
                messages=excluded.messages,
                metadata=excluded.metadata
            """,
            (
                membox.id,
                membox.topic,
                json.dumps(membox.keywords, ensure_ascii=False),
                json.dumps(membox.events, ensure_ascii=False),
                json.dumps([m.to_dict() for m in membox.messages], ensure_ascii=False),
                membox.created_at.isoformat(),
                json.dumps(membox.metadata, ensure_ascii=False),
            ),
        )
        conn.commit()

    def get_membox(self, membox_id: str) -> Membox | None:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM memboxes WHERE id = ?", (membox_id,)).fetchone()
        if not row:
            return None
        return self._row_to_membox(dict(row))

    def list_recent_memboxes(self, *, limit: int = 50) -> list[Membox]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM memboxes ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._row_to_membox(dict(r)) for r in rows]

    def count_memboxes(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) AS c FROM memboxes").fetchone()
        if not row:
            return 0
        return int(row["c"])

    def upsert_trace(self, trace: EventTrace) -> None:
        conn = self._get_conn()
        conn.execute(
            """
            INSERT INTO event_traces (id, summary, events, membox_ids, created_at, updated_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                summary=excluded.summary,
                events=excluded.events,
                membox_ids=excluded.membox_ids,
                updated_at=excluded.updated_at,
                metadata=excluded.metadata
            """,
            (
                trace.id,
                trace.summary,
                json.dumps(trace.events, ensure_ascii=False),
                json.dumps(trace.membox_ids, ensure_ascii=False),
                trace.created_at.isoformat(),
                trace.updated_at.isoformat(),
                json.dumps(trace.metadata, ensure_ascii=False),
            ),
        )
        conn.commit()

    def get_trace(self, trace_id: str) -> EventTrace | None:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM event_traces WHERE id = ?", (trace_id,)).fetchone()
        if not row:
            return None
        return self._row_to_trace(dict(row))

    def list_traces(self, *, limit: int = 50) -> list[EventTrace]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM event_traces ORDER BY updated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._row_to_trace(dict(r)) for r in rows]

    def count_traces(self) -> int:
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) AS c FROM event_traces").fetchone()
        if not row:
            return 0
        return int(row["c"])

    def add_trace_link(self, link: TraceLink) -> None:
        conn = self._get_conn()
        link_id = f"link_{link.membox_id}_{link.trace_id}"
        conn.execute(
            """
            INSERT OR REPLACE INTO membox_trace_links
              (id, membox_id, trace_id, link_type, confidence, reasoning, created_at)
            VALUES
              (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                link_id,
                link.membox_id,
                link.trace_id,
                link.link_type,
                link.confidence,
                link.reasoning,
                _utc_now_iso(),
            ),
        )
        conn.commit()

    def list_links_for_membox(self, membox_id: str) -> list[TraceLink]:
        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT membox_id, trace_id, link_type, confidence, reasoning
            FROM membox_trace_links
            WHERE membox_id = ?
            ORDER BY created_at DESC
            """,
            (membox_id,),
        ).fetchall()
        return [TraceLink.from_dict(dict(r)) for r in rows]

    def _row_to_membox(self, row: dict[str, Any]) -> Membox:
        from cyntra.cognition.memory.membox.models import MemboxMessage

        try:
            keywords = json.loads(row.get("keywords") or "[]")
        except Exception:
            keywords = []
        try:
            events = json.loads(row.get("events") or "[]")
        except Exception:
            events = []
        try:
            messages_raw = json.loads(row.get("messages") or "[]")
        except Exception:
            messages_raw = []
        messages = [
            MemboxMessage.from_dict(m) for m in messages_raw if isinstance(m, dict)
        ]
        try:
            metadata = json.loads(row.get("metadata") or "{}")
        except Exception:
            metadata = {}

        created_at_raw = row.get("created_at") or ""
        try:
            created_at = datetime.fromisoformat(created_at_raw.replace("Z", "+00:00"))
        except Exception:
            created_at = datetime.now(UTC)

        return Membox(
            id=str(row.get("id", "")),
            topic=str(row.get("topic", "")),
            keywords=[str(x) for x in keywords if x is not None],
            events=[str(x) for x in events if x is not None],
            messages=messages,
            created_at=created_at,
            metadata=dict(metadata) if isinstance(metadata, dict) else {},
        )

    def _row_to_trace(self, row: dict[str, Any]) -> EventTrace:
        try:
            events = json.loads(row.get("events") or "[]")
        except Exception:
            events = []
        try:
            membox_ids = json.loads(row.get("membox_ids") or "[]")
        except Exception:
            membox_ids = []
        try:
            metadata = json.loads(row.get("metadata") or "{}")
        except Exception:
            metadata = {}

        def _parse_dt(value: Any) -> datetime:
            if isinstance(value, str) and value:
                try:
                    return datetime.fromisoformat(value.replace("Z", "+00:00"))
                except Exception:
                    return datetime.now(UTC)
            return datetime.now(UTC)

        return EventTrace(
            id=str(row.get("id", "")),
            summary=str(row.get("summary", "")),
            events=[str(x) for x in events if x is not None],
            membox_ids=[str(x) for x in membox_ids if x is not None],
            created_at=_parse_dt(row.get("created_at")),
            updated_at=_parse_dt(row.get("updated_at")),
            metadata=dict(metadata) if isinstance(metadata, dict) else {},
        )
