"""
Memory Database - SQLite with FTS5

Follows claude-mem schema patterns:
- sessions: workcell execution sessions
- observations: captured tool uses, decisions, outcomes
- summaries: compressed session summaries for injection

Location: .cyntra/memory/cyntra-mem.db
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# Default location following claude-mem pattern
DEFAULT_DB_PATH = Path(".cyntra/memory/cyntra-mem.db")


class MemoryDB:
    """
    SQLite database for Cyntra memory with FTS5 full-text search.

    Schema follows claude-mem patterns adapted for Cyntra:
    - sessions: workcell execution metadata
    - observations: tool uses, decisions, gate results
    - summaries: AI-compressed session summaries
    """

    def __init__(self, db_path: Path | str | None = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        conn = self._get_conn()

        conn.executescript("""
            -- Sessions table (workcell executions)
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                workcell_id TEXT NOT NULL,
                issue_id TEXT,
                domain TEXT,
                job_type TEXT,
                toolchain TEXT,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                status TEXT,
                token_count INTEGER DEFAULT 0,
                observation_count INTEGER DEFAULT 0,
                UNIQUE(workcell_id)
            );

            -- Observations table (claude-mem style)
            CREATE TABLE IF NOT EXISTS observations (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                type TEXT NOT NULL,
                concept TEXT,
                content TEXT NOT NULL,
                tool_name TEXT,
                tool_args TEXT,
                file_refs TEXT,
                outcome TEXT,
                token_count INTEGER DEFAULT 0,
                importance TEXT DEFAULT 'info',
                created_at TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );

            -- Summaries table (compressed session knowledge)
            CREATE TABLE IF NOT EXISTS summaries (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                summary_type TEXT NOT NULL,
                content TEXT NOT NULL,
                patterns TEXT,
                anti_patterns TEXT,
                key_decisions TEXT,
                token_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );

            -- PSN skill maturity table (global, across sessions)
            CREATE TABLE IF NOT EXISTS skill_maturity (
                skill_id TEXT PRIMARY KEY,
                successes INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            -- Generic kernel state KV store (watermarks, counters)
            CREATE TABLE IF NOT EXISTS state_kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            -- FTS5 virtual table for observations
            CREATE VIRTUAL TABLE IF NOT EXISTS observations_fts USING fts5(
                content,
                tool_name,
                file_refs,
                concept,
                content='observations',
                content_rowid='rowid'
            );

            -- Triggers to keep FTS in sync
            CREATE TRIGGER IF NOT EXISTS observations_ai AFTER INSERT ON observations BEGIN
                INSERT INTO observations_fts(rowid, content, tool_name, file_refs, concept)
                VALUES (new.rowid, new.content, new.tool_name, new.file_refs, new.concept);
            END;

            CREATE TRIGGER IF NOT EXISTS observations_ad AFTER DELETE ON observations BEGIN
                INSERT INTO observations_fts(observations_fts, rowid, content, tool_name, file_refs, concept)
                VALUES ('delete', old.rowid, old.content, old.tool_name, old.file_refs, old.concept);
            END;

            -- UPDATE trigger for observations FTS sync
            CREATE TRIGGER IF NOT EXISTS observations_au AFTER UPDATE ON observations BEGIN
                INSERT INTO observations_fts(observations_fts, rowid, content, tool_name, file_refs, concept)
                VALUES ('delete', old.rowid, old.content, old.tool_name, old.file_refs, old.concept);
                INSERT INTO observations_fts(rowid, content, tool_name, file_refs, concept)
                VALUES (new.rowid, new.content, new.tool_name, new.file_refs, new.concept);
            END;

            -- FTS5 for summaries
            CREATE VIRTUAL TABLE IF NOT EXISTS summaries_fts USING fts5(
                content,
                patterns,
                key_decisions,
                content='summaries',
                content_rowid='rowid'
            );

            CREATE TRIGGER IF NOT EXISTS summaries_ai AFTER INSERT ON summaries BEGIN
                INSERT INTO summaries_fts(rowid, content, patterns, key_decisions)
                VALUES (new.rowid, new.content, new.patterns, new.key_decisions);
            END;

            CREATE TRIGGER IF NOT EXISTS summaries_ad AFTER DELETE ON summaries BEGIN
                INSERT INTO summaries_fts(summaries_fts, rowid, content, patterns, key_decisions)
                VALUES ('delete', old.rowid, old.content, old.patterns, old.key_decisions);
            END;

            CREATE TRIGGER IF NOT EXISTS summaries_au AFTER UPDATE ON summaries BEGIN
                INSERT INTO summaries_fts(summaries_fts, rowid, content, patterns, key_decisions)
                VALUES ('delete', old.rowid, old.content, old.patterns, old.key_decisions);
                INSERT INTO summaries_fts(rowid, content, patterns, key_decisions)
                VALUES (new.rowid, new.content, new.patterns, new.key_decisions);
            END;

            -- Indexes
            CREATE INDEX IF NOT EXISTS idx_observations_session ON observations(session_id);
            CREATE INDEX IF NOT EXISTS idx_observations_type ON observations(type);
            CREATE INDEX IF NOT EXISTS idx_observations_concept ON observations(concept);
            CREATE INDEX IF NOT EXISTS idx_observations_type_outcome_concept_created
                ON observations(type, outcome, concept, created_at);
            CREATE INDEX IF NOT EXISTS idx_sessions_domain ON sessions(domain);
            CREATE INDEX IF NOT EXISTS idx_sessions_issue ON sessions(issue_id);
        """)

        # Best-effort migration from legacy JSON maturity store.
        try:
            maturity_count_row = conn.execute("SELECT COUNT(*) AS c FROM skill_maturity").fetchone()
            maturity_count = int(maturity_count_row["c"]) if maturity_count_row else 0
            if maturity_count == 0:
                legacy_path = self.db_path.parent.parent / "skills" / "maturity.json"
                if legacy_path.exists():
                    legacy = json.loads(legacy_path.read_text(encoding="utf-8"))
                    if isinstance(legacy, dict):
                        now = datetime.now(UTC).isoformat()
                        for skill_id, counts in legacy.items():
                            if not isinstance(skill_id, str) or not isinstance(counts, dict):
                                continue
                            successes = counts.get("successes")
                            failures = counts.get("failures")
                            if not isinstance(successes, int) or not isinstance(failures, int):
                                continue
                            conn.execute(
                                """
                                INSERT INTO skill_maturity (skill_id, successes, failures, updated_at)
                                VALUES (?, ?, ?, ?)
                                ON CONFLICT(skill_id) DO UPDATE SET
                                    successes = excluded.successes,
                                    failures = excluded.failures,
                                    updated_at = excluded.updated_at
                            """,
                                (skill_id, successes, failures, now),
                            )
        except Exception:
            pass

        conn.commit()
        logger.debug("Memory database initialized", path=str(self.db_path))

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    # Session operations

    def create_session(
        self,
        session_id: str,
        workcell_id: str,
        issue_id: str | None = None,
        domain: str | None = None,
        job_type: str | None = None,
        toolchain: str | None = None,
    ) -> None:
        """Create a new session."""
        conn = self._get_conn()
        now = datetime.now(UTC).isoformat()

        conn.execute(
            """
            INSERT OR REPLACE INTO sessions
            (id, workcell_id, issue_id, domain, job_type, toolchain, started_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
        """,
            (session_id, workcell_id, issue_id, domain, job_type, toolchain, now),
        )

        conn.commit()

    def end_session(self, session_id: str, status: str = "completed") -> None:
        """Mark session as ended."""
        conn = self._get_conn()
        now = datetime.now(UTC).isoformat()

        conn.execute(
            """
            UPDATE sessions SET ended_at = ?, status = ? WHERE id = ?
        """,
            (now, status, session_id),
        )

        # Update counts
        conn.execute(
            """
            UPDATE sessions SET
                observation_count = (SELECT COUNT(*) FROM observations WHERE session_id = ?),
                token_count = (SELECT COALESCE(SUM(token_count), 0) FROM observations WHERE session_id = ?)
            WHERE id = ?
        """,
            (session_id, session_id, session_id),
        )

        conn.commit()

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get session by ID."""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        return dict(row) if row else None

    def get_session_by_workcell_id(self, workcell_id: str) -> dict[str, Any] | None:
        """Get session by workcell ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM sessions WHERE workcell_id = ?",
            (workcell_id,),
        ).fetchone()
        return dict(row) if row else None

    # Observation operations

    def add_observation(
        self,
        observation_id: str,
        session_id: str,
        obs_type: str,
        content: str,
        concept: str | None = None,
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
        file_refs: list[str] | None = None,
        outcome: str | None = None,
        importance: str = "info",
        token_count: int = 0,
    ) -> None:
        """Add an observation."""
        conn = self._get_conn()
        now = datetime.now(UTC).isoformat()

        conn.execute(
            """
            INSERT INTO observations
            (id, session_id, type, concept, content, tool_name, tool_args,
             file_refs, outcome, importance, token_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                observation_id,
                session_id,
                obs_type,
                concept,
                content,
                tool_name,
                json.dumps(tool_args) if tool_args else None,
                json.dumps(file_refs) if file_refs else None,
                outcome,
                importance,
                token_count,
                now,
            ),
        )

        conn.commit()

    def get_observations(
        self,
        session_id: str | None = None,
        obs_type: str | None = None,
        concept: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get observations with optional filters."""
        conn = self._get_conn()

        query = "SELECT * FROM observations WHERE 1=1"
        params: list[Any] = []

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if obs_type:
            query += " AND type = ?"
            params.append(obs_type)
        if concept:
            query += " AND concept = ?"
            params.append(concept)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def search_observations(
        self,
        query: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Full-text search over observations."""
        conn = self._get_conn()

        rows = conn.execute(
            """
            SELECT o.*, bm25(observations_fts) as score
            FROM observations_fts
            JOIN observations o ON observations_fts.rowid = o.rowid
            WHERE observations_fts MATCH ?
            ORDER BY score
            LIMIT ?
        """,
            (query, limit),
        ).fetchall()

        return [dict(row) for row in rows]

    # PSN skill maturity operations

    def record_skill_maturity(self, skill_id: str, *, passed: bool) -> dict[str, Any]:
        """Increment successes/failures for a skill and return the updated row."""
        conn = self._get_conn()
        now = datetime.now(UTC).isoformat()
        delta_success = 1 if passed else 0
        delta_failure = 0 if passed else 1

        conn.execute(
            """
            INSERT INTO skill_maturity (skill_id, successes, failures, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(skill_id) DO UPDATE SET
                successes = successes + excluded.successes,
                failures = failures + excluded.failures,
                updated_at = excluded.updated_at
        """,
            (skill_id, delta_success, delta_failure, now),
        )
        conn.commit()

        row = conn.execute(
            "SELECT skill_id, successes, failures, updated_at FROM skill_maturity WHERE skill_id = ?",
            (skill_id,),
        ).fetchone()
        return dict(row) if row else {"skill_id": skill_id, "successes": 0, "failures": 0, "updated_at": now}

    def set_skill_maturity(self, skill_id: str, *, successes: int, failures: int) -> dict[str, Any]:
        """Set maturity counts for a skill (used for migrations/import)."""
        conn = self._get_conn()
        now = datetime.now(UTC).isoformat()
        conn.execute(
            """
            INSERT INTO skill_maturity (skill_id, successes, failures, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(skill_id) DO UPDATE SET
                successes = excluded.successes,
                failures = excluded.failures,
                updated_at = excluded.updated_at
        """,
            (skill_id, int(successes), int(failures), now),
        )
        conn.commit()
        row = conn.execute(
            "SELECT skill_id, successes, failures, updated_at FROM skill_maturity WHERE skill_id = ?",
            (skill_id,),
        ).fetchone()
        return dict(row) if row else {"skill_id": skill_id, "successes": successes, "failures": failures, "updated_at": now}

    def get_skill_maturity(
        self,
        *,
        skill_id: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Return maturity rows (optionally filtered by skill_id)."""
        conn = self._get_conn()
        query = "SELECT skill_id, successes, failures, updated_at FROM skill_maturity"
        params: list[Any] = []
        if skill_id:
            query += " WHERE skill_id = ?"
            params.append(skill_id)
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # Generic state KV operations (watermarks, counters)

    def get_state_value(self, key: str) -> str | None:
        """Get a stored state value by key."""
        conn = self._get_conn()
        row = conn.execute("SELECT value FROM state_kv WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def set_state_value(self, key: str, value: str) -> None:
        """Set a stored state value by key."""
        conn = self._get_conn()
        now = datetime.now(UTC).isoformat()
        conn.execute(
            """
            INSERT INTO state_kv (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
        """,
            (key, value, now),
        )
        conn.commit()

    def increment_state_counter(self, key: str, *, delta: int = 1) -> int:
        """Increment an integer counter stored in state_kv and return the new value."""
        current_raw = self.get_state_value(key)
        try:
            current = int(current_raw) if current_raw is not None else 0
        except ValueError:
            current = 0
        updated = current + int(delta)
        self.set_state_value(key, str(updated))
        return updated

    # Summary operations

    def add_summary(
        self,
        summary_id: str,
        session_id: str,
        summary_type: str,
        content: str,
        patterns: list[str] | None = None,
        anti_patterns: list[str] | None = None,
        key_decisions: list[str] | None = None,
        token_count: int = 0,
    ) -> None:
        """Add a session summary."""
        conn = self._get_conn()
        now = datetime.now(UTC).isoformat()

        conn.execute(
            """
            INSERT INTO summaries
            (id, session_id, summary_type, content, patterns, anti_patterns,
             key_decisions, token_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                summary_id,
                session_id,
                summary_type,
                content,
                json.dumps(patterns) if patterns else None,
                json.dumps(anti_patterns) if anti_patterns else None,
                json.dumps(key_decisions) if key_decisions else None,
                token_count,
                now,
            ),
        )

        conn.commit()

    def search_summaries(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """Full-text search over summaries."""
        conn = self._get_conn()

        rows = conn.execute(
            """
            SELECT s.*, bm25(summaries_fts) as score
            FROM summaries_fts
            JOIN summaries s ON summaries_fts.rowid = s.rowid
            WHERE summaries_fts MATCH ?
            ORDER BY score
            LIMIT ?
        """,
            (query, limit),
        ).fetchall()

        return [dict(row) for row in rows]

    def get_recent_summaries(
        self,
        domain: str | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Get recent summaries, optionally filtered by domain."""
        conn = self._get_conn()

        if domain:
            rows = conn.execute(
                """
                SELECT s.* FROM summaries s
                JOIN sessions sess ON s.session_id = sess.id
                WHERE sess.domain = ?
                ORDER BY s.created_at DESC
                LIMIT ?
            """,
                (domain, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM summaries
                ORDER BY created_at DESC
                LIMIT ?
            """,
                (limit,),
            ).fetchall()

        return [dict(row) for row in rows]

    # Context injection (progressive disclosure Layer 1)

    def get_context_for_injection(
        self,
        domain: str | None = None,
        max_observations: int = 50,
        max_tokens: int = 2000,
    ) -> dict[str, Any]:
        """
        Get memory context for injection at session start.

        Progressive disclosure Layer 1: Index of available observations
        with token costs, plus recent summaries.
        """
        conn = self._get_conn()

        # Get recent summaries (highest value, compressed knowledge)
        summaries = self.get_recent_summaries(domain=domain, limit=5)

        # Get observation index (type counts, recent important ones)
        if domain:
            obs_rows = conn.execute(
                """
                SELECT o.id, o.type, o.concept, o.importance, o.token_count,
                       substr(o.content, 1, 100) as preview
                FROM observations o
                JOIN sessions s ON o.session_id = s.id
                WHERE s.domain = ? AND o.importance IN ('critical', 'decision')
                ORDER BY o.created_at DESC
                LIMIT ?
            """,
                (domain, max_observations),
            ).fetchall()
        else:
            obs_rows = conn.execute(
                """
                SELECT id, type, concept, importance, token_count,
                       substr(content, 1, 100) as preview
                FROM observations
                WHERE importance IN ('critical', 'decision')
                ORDER BY created_at DESC
                LIMIT ?
            """,
                (max_observations,),
            ).fetchall()

        observation_index = [dict(row) for row in obs_rows]

        # Calculate token budget
        summary_tokens = sum(s.get("token_count", 0) for s in summaries)
        remaining_tokens = max_tokens - summary_tokens

        return {
            "summaries": summaries,
            "observation_index": observation_index,
            "total_observations": len(observation_index),
            "token_budget": {
                "summaries": summary_tokens,
                "remaining": remaining_tokens,
            },
        }
