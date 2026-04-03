"""EngagementStore - SQLite registry for multi-tenant engagement tracking."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL DEFAULT '',
    target_url TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'running',
    created_at TEXT NOT NULL,
    completed_at TEXT,
    output_dir TEXT NOT NULL DEFAULT '',
    vulns_found INTEGER NOT NULL DEFAULT 0,
    exit_code INTEGER,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_engagements_project ON engagements (project_id);
CREATE INDEX IF NOT EXISTS idx_engagements_target ON engagements (target_url);
CREATE INDEX IF NOT EXISTS idx_engagements_status ON engagements (status);
"""


@dataclass
class EngagementRecord:
    """A single engagement record from the store."""

    id: str
    project_id: str
    target_url: str
    config_json: str
    status: str
    created_at: str
    completed_at: str | None
    output_dir: str
    vulns_found: int
    exit_code: int | None
    error: str | None


class EngagementStore:
    """
    SQLite-backed central engagement registry.

    Default location: ~/.hellcat/engagements.db
    """

    DEFAULT_PATH = Path.home() / ".hellcat" / "engagements.db"

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else self.DEFAULT_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        self.conn.close()

    def _init_schema(self) -> None:
        self.conn.executescript(_SCHEMA_SQL)
        self.conn.commit()

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_engagement(
        self,
        target_url: str,
        config: dict[str, Any] | None = None,
        engagement_id: str | None = None,
        project_id: str | None = None,
        output_dir: str = "",
    ) -> EngagementRecord:
        """Register a new engagement.

        Args:
            target_url: The target being tested.
            config: Engagement config dict (serialized as JSON).
            engagement_id: Optional explicit ID; auto-generated if omitted.
            project_id: Optional project grouping key.
            output_dir: Path to output artifacts.

        Returns:
            The created EngagementRecord.
        """
        eid = engagement_id or uuid.uuid4().hex[:16]
        pid = project_id or ""
        config_json = json.dumps(config or {})
        now = datetime.now(UTC).isoformat()

        self.conn.execute(
            """
            INSERT INTO engagements
                (id, project_id, target_url, config_json, status,
                 created_at, output_dir)
            VALUES (?, ?, ?, ?, 'running', ?, ?)
            """,
            (eid, pid, target_url, config_json, now, output_dir),
        )
        self.conn.commit()

        logger.debug(
            "store.engagement_created",
            engagement_id=eid,
            project_id=pid,
            target_url=target_url,
        )

        return EngagementRecord(
            id=eid,
            project_id=pid,
            target_url=target_url,
            config_json=config_json,
            status="running",
            created_at=now,
            completed_at=None,
            output_dir=output_dir,
            vulns_found=0,
            exit_code=None,
            error=None,
        )

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_status(
        self,
        engagement_id: str,
        status: str,
        vulns_found: int | None = None,
        exit_code: int | None = None,
        error: str | None = None,
    ) -> None:
        """Update an engagement's status and optional outcome fields.

        Args:
            engagement_id: The engagement to update.
            status: New status (running, completed, failed).
            vulns_found: Number of vulnerabilities discovered.
            exit_code: Process exit code.
            error: Error message if failed.
        """
        sets = ["status = ?"]
        params: list[Any] = [status]

        if status in ("completed", "failed"):
            sets.append("completed_at = ?")
            params.append(datetime.now(UTC).isoformat())

        if vulns_found is not None:
            sets.append("vulns_found = ?")
            params.append(vulns_found)

        if exit_code is not None:
            sets.append("exit_code = ?")
            params.append(exit_code)

        if error is not None:
            sets.append("error = ?")
            params.append(error)

        params.append(engagement_id)

        self.conn.execute(
            f"UPDATE engagements SET {', '.join(sets)} WHERE id = ?",
            params,
        )
        self.conn.commit()

        logger.debug(
            "store.engagement_updated",
            engagement_id=engagement_id,
            status=status,
        )

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_engagement(self, engagement_id: str) -> EngagementRecord | None:
        """Fetch a single engagement by ID."""
        row = self.conn.execute(
            "SELECT * FROM engagements WHERE id = ?",
            (engagement_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def list_engagements(
        self,
        project_id: str | None = None,
        target_url: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[EngagementRecord]:
        """List engagements with optional filters.

        Args:
            project_id: Filter by project.
            target_url: Filter by target URL.
            status: Filter by status.
            limit: Maximum records to return.

        Returns:
            List of matching EngagementRecords, newest first.
        """
        clauses: list[str] = []
        params: list[Any] = []

        if project_id is not None:
            clauses.append("project_id = ?")
            params.append(project_id)

        if target_url is not None:
            clauses.append("target_url = ?")
            params.append(target_url)

        if status is not None:
            clauses.append("status = ?")
            params.append(status)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        rows = self.conn.execute(
            f"SELECT * FROM engagements {where} ORDER BY created_at DESC LIMIT ?",
            params,
        ).fetchall()

        return [self._row_to_record(row) for row in rows]

    # ------------------------------------------------------------------
    # Compare
    # ------------------------------------------------------------------

    def compare_engagements(self, id1: str, id2: str) -> dict[str, Any]:
        """Compare two engagements side-by-side.

        Returns a dict with 'engagement_1', 'engagement_2', and 'delta' keys.
        """
        e1 = self.get_engagement(id1)
        e2 = self.get_engagement(id2)

        if e1 is None:
            raise ValueError(f"Engagement not found: {id1}")
        if e2 is None:
            raise ValueError(f"Engagement not found: {id2}")

        def _record_summary(rec: EngagementRecord) -> dict[str, Any]:
            return {
                "id": rec.id,
                "target_url": rec.target_url,
                "status": rec.status,
                "vulns_found": rec.vulns_found,
                "exit_code": rec.exit_code,
                "created_at": rec.created_at,
                "completed_at": rec.completed_at,
            }

        return {
            "engagement_1": _record_summary(e1),
            "engagement_2": _record_summary(e2),
            "delta": {
                "vulns_found": e2.vulns_found - e1.vulns_found,
                "same_target": e1.target_url == e2.target_url,
                "same_project": e1.project_id == e2.project_id,
            },
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> EngagementRecord:
        return EngagementRecord(
            id=row["id"],
            project_id=row["project_id"],
            target_url=row["target_url"],
            config_json=row["config_json"],
            status=row["status"],
            created_at=row["created_at"],
            completed_at=row["completed_at"],
            output_dir=row["output_dir"],
            vulns_found=row["vulns_found"],
            exit_code=row["exit_code"],
            error=row["error"],
        )
