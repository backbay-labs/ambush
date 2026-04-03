"""
EngagementHistory - SQLite-backed history of continuous engagement runs.

Tracks each re-engagement run with trigger info, timing, results, and
cost. Also stores surface snapshots for trend analysis.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    trigger_type    TEXT NOT NULL,
    trigger_data    TEXT NOT NULL DEFAULT '{}',
    started_at      REAL NOT NULL,
    completed_at    REAL,
    vulns_found     INTEGER NOT NULL DEFAULT 0,
    vulns_new       INTEGER NOT NULL DEFAULT 0,
    cost_usd        REAL NOT NULL DEFAULT 0.0,
    status          TEXT NOT NULL DEFAULT 'running',
    error           TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_runs_started
    ON runs (started_at);

CREATE TABLE IF NOT EXISTS surface_snapshots (
    snapshot_id     TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL,
    graph_hash      TEXT NOT NULL,
    endpoint_count  INTEGER NOT NULL DEFAULT 0,
    tech_stack_json TEXT NOT NULL DEFAULT '[]',
    captured_at     REAL NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_snapshots_run
    ON surface_snapshots (run_id);
"""


@dataclass
class RunRecord:
    """A single continuous engagement run record."""

    run_id: str
    trigger_type: str
    trigger_data: dict[str, Any]
    started_at: float
    completed_at: float | None = None
    vulns_found: int = 0
    vulns_new: int = 0
    cost_usd: float = 0.0
    status: str = "running"
    error: str = ""


@dataclass
class SnapshotRecord:
    """A surface snapshot associated with a run."""

    snapshot_id: str
    run_id: str
    graph_hash: str
    endpoint_count: int = 0
    tech_stack: list[str] = field(default_factory=list)
    captured_at: float = 0.0


@dataclass
class TrendPoint:
    """Single data point in a vulnerability trend."""

    timestamp: float
    vulns_found: int
    vulns_new: int
    cost_usd: float
    endpoint_count: int


class EngagementHistory:
    """SQLite-backed history of continuous engagement runs.

    Usage::

        history = EngagementHistory(Path(".hellcat/continuous.db"))
        run_id = history.record_run_start("polling", {"url": "..."})
        history.record_snapshot(run_id, "abc123", 42, ["django"])
        history.record_run_complete(run_id, vulns_found=3, vulns_new=1, cost_usd=0.50)
        records = history.get_history(since=time.time() - 86400)
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
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
    # Recording
    # ------------------------------------------------------------------

    def record_run_start(
        self,
        trigger_type: str,
        trigger_data: dict[str, Any] | None = None,
        run_id: str | None = None,
    ) -> str:
        """Record the start of a continuous engagement run.

        Args:
            trigger_type: Type of trigger that initiated the run.
            trigger_data: Metadata from the trigger event.
            run_id: Optional explicit run ID (auto-generated if None).

        Returns:
            The run_id.
        """
        import uuid

        if run_id is None:
            run_id = str(uuid.uuid4())

        now = time.time()
        self.conn.execute(
            """
            INSERT INTO runs (run_id, trigger_type, trigger_data, started_at, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                run_id,
                trigger_type,
                json.dumps(trigger_data or {}),
                now,
                "running",
            ),
        )
        self.conn.commit()

        logger.info(
            "history.run_started",
            run_id=run_id,
            trigger_type=trigger_type,
        )
        return run_id

    def record_run_complete(
        self,
        run_id: str,
        *,
        vulns_found: int = 0,
        vulns_new: int = 0,
        cost_usd: float = 0.0,
        error: str = "",
    ) -> None:
        """Record the completion of a run.

        Args:
            run_id: The run to update.
            vulns_found: Total vulnerabilities found.
            vulns_new: New vulnerabilities (not seen in previous run).
            cost_usd: Total cost of the run.
            error: Error message if the run failed.
        """
        now = time.time()
        status = "error" if error else "completed"

        self.conn.execute(
            """
            UPDATE runs SET
                completed_at = ?,
                vulns_found = ?,
                vulns_new = ?,
                cost_usd = ?,
                status = ?,
                error = ?
            WHERE run_id = ?
            """,
            (now, vulns_found, vulns_new, cost_usd, status, error, run_id),
        )
        self.conn.commit()

        logger.info(
            "history.run_complete",
            run_id=run_id,
            status=status,
            vulns_found=vulns_found,
            vulns_new=vulns_new,
            cost_usd=cost_usd,
        )

    def record_snapshot(
        self,
        run_id: str,
        graph_hash: str,
        endpoint_count: int = 0,
        tech_stack: list[str] | None = None,
        snapshot_id: str | None = None,
    ) -> str:
        """Record a surface snapshot for a run.

        Args:
            run_id: The associated run.
            graph_hash: Hash of the TargetGraph state.
            endpoint_count: Number of target endpoints.
            tech_stack: List of technologies detected.
            snapshot_id: Optional explicit snapshot ID.

        Returns:
            The snapshot_id.
        """
        import uuid

        if snapshot_id is None:
            snapshot_id = str(uuid.uuid4())

        now = time.time()
        self.conn.execute(
            """
            INSERT INTO surface_snapshots
                (snapshot_id, run_id, graph_hash, endpoint_count, tech_stack_json, captured_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                run_id,
                graph_hash,
                endpoint_count,
                json.dumps(tech_stack or []),
                now,
            ),
        )
        self.conn.commit()
        return snapshot_id

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def get_history(
        self,
        since: float | None = None,
        limit: int = 50,
    ) -> list[RunRecord]:
        """Get recent run history.

        Args:
            since: Only return runs started after this Unix timestamp.
            limit: Maximum number of records to return.

        Returns:
            List of RunRecord sorted by started_at descending.
        """
        if since is not None:
            rows = self.conn.execute(
                """
                SELECT * FROM runs
                WHERE started_at >= ?
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT * FROM runs
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            RunRecord(
                run_id=row["run_id"],
                trigger_type=row["trigger_type"],
                trigger_data=json.loads(row["trigger_data"]),
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                vulns_found=row["vulns_found"],
                vulns_new=row["vulns_new"],
                cost_usd=row["cost_usd"],
                status=row["status"],
                error=row["error"],
            )
            for row in rows
        ]

    def get_run(self, run_id: str) -> RunRecord | None:
        """Get a single run by ID."""
        row = self.conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return None
        return RunRecord(
            run_id=row["run_id"],
            trigger_type=row["trigger_type"],
            trigger_data=json.loads(row["trigger_data"]),
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            vulns_found=row["vulns_found"],
            vulns_new=row["vulns_new"],
            cost_usd=row["cost_usd"],
            status=row["status"],
            error=row["error"],
        )

    def get_snapshots(self, run_id: str) -> list[SnapshotRecord]:
        """Get surface snapshots for a run."""
        rows = self.conn.execute(
            "SELECT * FROM surface_snapshots WHERE run_id = ? ORDER BY captured_at",
            (run_id,),
        ).fetchall()
        return [
            SnapshotRecord(
                snapshot_id=row["snapshot_id"],
                run_id=row["run_id"],
                graph_hash=row["graph_hash"],
                endpoint_count=row["endpoint_count"],
                tech_stack=json.loads(row["tech_stack_json"]),
                captured_at=row["captured_at"],
            )
            for row in rows
        ]

    def get_trend(
        self,
        since: float | None = None,
        limit: int = 100,
    ) -> list[TrendPoint]:
        """Get vulnerability trend over time.

        Args:
            since: Only include runs after this timestamp.
            limit: Maximum data points.

        Returns:
            List of TrendPoint sorted by time ascending.
        """
        if since is not None:
            rows = self.conn.execute(
                """
                SELECT r.started_at, r.vulns_found, r.vulns_new, r.cost_usd,
                       COALESCE(s.endpoint_count, 0) as endpoint_count
                FROM runs r
                LEFT JOIN surface_snapshots s ON s.run_id = r.run_id
                WHERE r.started_at >= ? AND r.status = 'completed'
                ORDER BY r.started_at ASC
                LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT r.started_at, r.vulns_found, r.vulns_new, r.cost_usd,
                       COALESCE(s.endpoint_count, 0) as endpoint_count
                FROM runs r
                LEFT JOIN surface_snapshots s ON s.run_id = r.run_id
                WHERE r.status = 'completed'
                ORDER BY r.started_at ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            TrendPoint(
                timestamp=row["started_at"],
                vulns_found=row["vulns_found"],
                vulns_new=row["vulns_new"],
                cost_usd=row["cost_usd"],
                endpoint_count=row["endpoint_count"],
            )
            for row in rows
        ]

    def get_stats(self) -> dict[str, Any]:
        """Get overall continuous engagement statistics."""
        total = self.conn.execute("SELECT COUNT(*) as c FROM runs").fetchone()["c"]
        completed = self.conn.execute(
            "SELECT COUNT(*) as c FROM runs WHERE status = 'completed'"
        ).fetchone()["c"]
        total_cost = self.conn.execute(
            "SELECT COALESCE(SUM(cost_usd), 0) as c FROM runs"
        ).fetchone()["c"]
        total_vulns = self.conn.execute(
            "SELECT COALESCE(SUM(vulns_found), 0) as c FROM runs WHERE status = 'completed'"
        ).fetchone()["c"]
        total_new_vulns = self.conn.execute(
            "SELECT COALESCE(SUM(vulns_new), 0) as c FROM runs WHERE status = 'completed'"
        ).fetchone()["c"]

        return {
            "total_runs": total,
            "completed_runs": completed,
            "total_cost_usd": round(total_cost, 4),
            "total_vulns_found": total_vulns,
            "total_new_vulns": total_new_vulns,
        }
