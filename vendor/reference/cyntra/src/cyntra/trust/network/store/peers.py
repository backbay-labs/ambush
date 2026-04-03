"""
Peer registry for CNP network nodes.

Tracks known peers, their capabilities, and connection history.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional


class PeerStatus(str, Enum):
    """Peer connection status."""

    UNKNOWN = "unknown"
    DISCOVERED = "discovered"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    BANNED = "banned"


@dataclass
class Peer:
    """A CNP network peer."""

    # Identity
    peer_id: str  # libp2p peer ID
    public_key: str  # Ed25519 public key (hex)

    # Network
    multiaddrs: list[str] = field(default_factory=list)
    status: PeerStatus = PeerStatus.UNKNOWN

    # Metadata
    agent_version: str = ""
    protocol_version: str = ""
    organization: str = ""  # Optional org identifier

    # Reputation (local view)
    reputation_score: float = 0.5  # 0-1, neutral start
    trails_received: int = 0
    trails_sent: int = 0
    successful_queries: int = 0
    failed_queries: int = 0

    # Timestamps
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_connected: Optional[datetime] = None

    def update_reputation(self, success: bool, weight: float = 0.1) -> None:
        """Update reputation based on interaction outcome."""
        if success:
            self.reputation_score = min(1.0, self.reputation_score + weight * (1 - self.reputation_score))
        else:
            self.reputation_score = max(0.0, self.reputation_score - weight * self.reputation_score)


class PeerStore:
    """SQLite-based peer registry."""

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS peers (
                    peer_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    multiaddrs_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'unknown',
                    agent_version TEXT,
                    protocol_version TEXT,
                    organization TEXT,
                    reputation_score REAL NOT NULL DEFAULT 0.5,
                    trails_received INTEGER NOT NULL DEFAULT 0,
                    trails_sent INTEGER NOT NULL DEFAULT 0,
                    successful_queries INTEGER NOT NULL DEFAULT 0,
                    failed_queries INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_connected TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_peers_status ON peers(status);
                CREATE INDEX IF NOT EXISTS idx_peers_reputation ON peers(reputation_score);
                CREATE INDEX IF NOT EXISTS idx_peers_last_seen ON peers(last_seen);

                -- Connection events log
                CREATE TABLE IF NOT EXISTS peer_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peer_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (peer_id) REFERENCES peers(peer_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_peer_events_peer ON peer_events(peer_id);
            """)
            conn.commit()

    def upsert(self, peer: Peer) -> None:
        """Insert or update a peer."""
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO peers (
                    peer_id, public_key, multiaddrs_json, status,
                    agent_version, protocol_version, organization,
                    reputation_score, trails_received, trails_sent,
                    successful_queries, failed_queries,
                    first_seen, last_seen, last_connected
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(peer_id) DO UPDATE SET
                    multiaddrs_json = excluded.multiaddrs_json,
                    status = excluded.status,
                    agent_version = excluded.agent_version,
                    protocol_version = excluded.protocol_version,
                    reputation_score = excluded.reputation_score,
                    trails_received = excluded.trails_received,
                    trails_sent = excluded.trails_sent,
                    successful_queries = excluded.successful_queries,
                    failed_queries = excluded.failed_queries,
                    last_seen = excluded.last_seen,
                    last_connected = excluded.last_connected
                """,
                (
                    peer.peer_id,
                    peer.public_key,
                    json.dumps(peer.multiaddrs),
                    peer.status.value,
                    peer.agent_version,
                    peer.protocol_version,
                    peer.organization,
                    peer.reputation_score,
                    peer.trails_received,
                    peer.trails_sent,
                    peer.successful_queries,
                    peer.failed_queries,
                    peer.first_seen.isoformat(),
                    peer.last_seen.isoformat(),
                    peer.last_connected.isoformat() if peer.last_connected else None,
                ),
            )
            conn.commit()

    def get(self, peer_id: str) -> Optional[Peer]:
        """Get peer by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM peers WHERE peer_id = ?", (peer_id,)
            ).fetchone()
            if row is None:
                return None
            return self._row_to_peer(row)

    def list_active(self, limit: int = 100) -> list[Peer]:
        """List active peers sorted by reputation."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM peers
                WHERE status IN ('discovered', 'connected')
                ORDER BY reputation_score DESC, last_seen DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [self._row_to_peer(row) for row in rows]

    def list_by_status(self, status: PeerStatus, limit: int = 100) -> list[Peer]:
        """List peers by status."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM peers WHERE status = ? ORDER BY last_seen DESC LIMIT ?",
                (status.value, limit),
            ).fetchall()
            return [self._row_to_peer(row) for row in rows]

    def update_status(self, peer_id: str, status: PeerStatus) -> None:
        """Update peer status."""
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE peers SET status = ?, last_seen = ?,
                    last_connected = CASE WHEN ? = 'connected' THEN ? ELSE last_connected END
                WHERE peer_id = ?
                """,
                (status.value, now, status.value, now, peer_id),
            )
            conn.commit()

    def record_event(self, peer_id: str, event_type: str, details: Optional[dict] = None) -> None:
        """Record a peer event."""
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO peer_events (peer_id, event_type, details_json) VALUES (?, ?, ?)",
                (peer_id, event_type, json.dumps(details) if details else None),
            )
            conn.commit()

    def increment_trails_received(self, peer_id: str, count: int = 1) -> None:
        """Increment trails received counter."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE peers SET trails_received = trails_received + ? WHERE peer_id = ?",
                (count, peer_id),
            )
            conn.commit()

    def increment_trails_sent(self, peer_id: str, count: int = 1) -> None:
        """Increment trails sent counter."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE peers SET trails_sent = trails_sent + ? WHERE peer_id = ?",
                (count, peer_id),
            )
            conn.commit()

    def ban(self, peer_id: str, reason: str) -> None:
        """Ban a peer."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE peers SET status = 'banned' WHERE peer_id = ?",
                (peer_id,),
            )
            self.record_event(peer_id, "banned", {"reason": reason})
            conn.commit()

    def count(self) -> dict[str, int]:
        """Get peer counts by status."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) as count FROM peers GROUP BY status"
            ).fetchall()
            return {row["status"]: row["count"] for row in rows}

    def _row_to_peer(self, row: sqlite3.Row) -> Peer:
        return Peer(
            peer_id=row["peer_id"],
            public_key=row["public_key"],
            multiaddrs=json.loads(row["multiaddrs_json"]),
            status=PeerStatus(row["status"]),
            agent_version=row["agent_version"] or "",
            protocol_version=row["protocol_version"] or "",
            organization=row["organization"] or "",
            reputation_score=row["reputation_score"],
            trails_received=row["trails_received"],
            trails_sent=row["trails_sent"],
            successful_queries=row["successful_queries"],
            failed_queries=row["failed_queries"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            last_connected=datetime.fromisoformat(row["last_connected"]) if row["last_connected"] else None,
        )
