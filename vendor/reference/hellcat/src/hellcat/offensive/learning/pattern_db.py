"""
AttackPatternDB - Persistent cross-engagement learning database.

Accumulates knowledge about which techniques work against which tech stacks,
enabling Hellcat to improve across engagements. SQLite-backed, following the
same pattern as TargetGraph.

Key capabilities:
  - Record attempt outcomes (technique, vuln_type, tech_stack, success/failure)
  - Query best techniques for a given vuln_type + tech_stack
  - Retrieve known-working payloads
  - Suggest technique ordering based on historical success rates
  - Export stats for reporting
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS attempts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique       TEXT NOT NULL,
    vuln_type       TEXT NOT NULL,
    tech_stack      TEXT NOT NULL DEFAULT '',
    success         INTEGER NOT NULL DEFAULT 0,
    payload         TEXT NOT NULL DEFAULT '',
    evasion_attempts INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT NOT NULL DEFAULT '',
    engagement_id   TEXT NOT NULL DEFAULT '',
    recorded_at     REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attempts_technique_vuln
    ON attempts (technique, vuln_type);

CREATE INDEX IF NOT EXISTS idx_attempts_tech_stack
    ON attempts (tech_stack);

CREATE TABLE IF NOT EXISTS payloads (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique       TEXT NOT NULL,
    vuln_type       TEXT NOT NULL,
    tech_stack      TEXT NOT NULL DEFAULT '',
    payload         TEXT NOT NULL,
    success_count   INTEGER NOT NULL DEFAULT 1,
    last_used       REAL NOT NULL,
    UNIQUE(technique, vuln_type, tech_stack, payload)
);

CREATE INDEX IF NOT EXISTS idx_payloads_lookup
    ON payloads (technique, vuln_type, tech_stack);
"""


@dataclass
class AttackPattern:
    """Aggregated pattern data for a technique + vuln_type + tech_stack combination."""

    technique: str
    vuln_type: str
    tech_stack: str
    success_rate: float
    attempts: int
    last_used: float
    avg_evasion_attempts: float
    payloads: list[str] = field(default_factory=list)


class AttackPatternDB:
    """
    SQLite-backed persistent database for cross-engagement learning.

    Records attempt outcomes and provides query methods for historical
    success rates, known-working payloads, and technique ordering.
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
    # Record
    # ------------------------------------------------------------------

    def record_attempt(
        self,
        technique: str,
        vuln_type: str,
        tech_stack: str = "",
        success: bool = False,
        payload: str = "",
        evasion_attempts: int = 0,
        error_message: str = "",
        engagement_id: str = "",
    ) -> None:
        """
        Log a single attempt outcome.

        If the attempt was successful and included a payload, also upserts
        into the payloads table for future retrieval.
        """
        now = time.time()

        self.conn.execute(
            """
            INSERT INTO attempts
                (technique, vuln_type, tech_stack, success, payload,
                 evasion_attempts, error_message, engagement_id, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                technique, vuln_type, tech_stack, int(success), payload,
                evasion_attempts, error_message, engagement_id, now,
            ),
        )

        # Track successful payloads
        if success and payload:
            self.conn.execute(
                """
                INSERT INTO payloads (technique, vuln_type, tech_stack, payload, success_count, last_used)
                VALUES (?, ?, ?, ?, 1, ?)
                ON CONFLICT(technique, vuln_type, tech_stack, payload)
                DO UPDATE SET
                    success_count = success_count + 1,
                    last_used = excluded.last_used
                """,
                (technique, vuln_type, tech_stack, payload, now),
            )

        self.conn.commit()

        logger.debug(
            "learning.attempt_recorded",
            technique=technique,
            vuln_type=vuln_type,
            tech_stack=tech_stack,
            success=success,
        )

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_best_techniques(
        self,
        vuln_type: str,
        tech_stack: str = "",
        min_attempts: int = 1,
        engagement_ids: list[str] | None = None,
    ) -> list[AttackPattern]:
        """
        Get techniques sorted by success rate for a vuln_type + tech_stack.

        Only includes techniques with at least ``min_attempts`` recorded attempts.
        If tech_stack is provided, includes both stack-specific and generic results.
        If engagement_ids is provided, only considers attempts from those engagements.
        """
        eid_clause, eid_params = self._engagement_filter(engagement_ids)

        if tech_stack:
            rows = self.conn.execute(
                f"""
                SELECT technique, vuln_type, tech_stack,
                       COUNT(*) as attempts,
                       SUM(success) as successes,
                       MAX(recorded_at) as last_used,
                       AVG(evasion_attempts) as avg_evasion
                FROM attempts
                WHERE vuln_type = ? AND (tech_stack = ? OR tech_stack = '')
                {eid_clause}
                GROUP BY technique, vuln_type, tech_stack
                HAVING attempts >= ?
                ORDER BY CAST(successes AS REAL) / attempts DESC
                """,
                (vuln_type, tech_stack, *eid_params, min_attempts),
            ).fetchall()
        else:
            rows = self.conn.execute(
                f"""
                SELECT technique, vuln_type, tech_stack,
                       COUNT(*) as attempts,
                       SUM(success) as successes,
                       MAX(recorded_at) as last_used,
                       AVG(evasion_attempts) as avg_evasion
                FROM attempts
                WHERE vuln_type = ?
                {eid_clause}
                GROUP BY technique, vuln_type, tech_stack
                HAVING attempts >= ?
                ORDER BY CAST(successes AS REAL) / attempts DESC
                """,
                (vuln_type, *eid_params, min_attempts),
            ).fetchall()

        patterns: list[AttackPattern] = []
        for row in rows:
            attempts = row["attempts"]
            successes = row["successes"]
            rate = successes / attempts if attempts > 0 else 0.0

            # Fetch payloads for this pattern
            payloads = self._get_payloads_for(
                row["technique"], row["vuln_type"], row["tech_stack"],
            )

            patterns.append(AttackPattern(
                technique=row["technique"],
                vuln_type=row["vuln_type"],
                tech_stack=row["tech_stack"],
                success_rate=round(rate, 3),
                attempts=attempts,
                last_used=row["last_used"],
                avg_evasion_attempts=round(row["avg_evasion"] or 0.0, 1),
                payloads=payloads,
            ))

        return patterns

    def get_payloads(
        self,
        technique: str,
        vuln_type: str,
        tech_stack: str = "",
        engagement_ids: list[str] | None = None,
    ) -> list[str]:
        """Get known-working payloads for a technique + vuln_type, ordered by success count.

        If engagement_ids is provided, only retrieves payloads from successful attempts
        recorded in those engagements (falls back to the payloads table when unscoped).
        """
        if engagement_ids is not None:
            placeholders = ",".join("?" * len(engagement_ids))
            if tech_stack:
                rows = self.conn.execute(
                    f"""
                    SELECT DISTINCT payload FROM attempts
                    WHERE technique = ? AND vuln_type = ?
                      AND (tech_stack = ? OR tech_stack = '')
                      AND success = 1 AND payload != ''
                      AND engagement_id IN ({placeholders})
                    ORDER BY recorded_at DESC
                    """,
                    (technique, vuln_type, tech_stack, *engagement_ids),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    f"""
                    SELECT DISTINCT payload FROM attempts
                    WHERE technique = ? AND vuln_type = ?
                      AND success = 1 AND payload != ''
                      AND engagement_id IN ({placeholders})
                    ORDER BY recorded_at DESC
                    """,
                    (technique, vuln_type, *engagement_ids),
                ).fetchall()
        elif tech_stack:
            rows = self.conn.execute(
                """
                SELECT payload FROM payloads
                WHERE technique = ? AND vuln_type = ? AND (tech_stack = ? OR tech_stack = '')
                ORDER BY success_count DESC
                """,
                (technique, vuln_type, tech_stack),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT payload FROM payloads
                WHERE technique = ? AND vuln_type = ?
                ORDER BY success_count DESC
                """,
                (technique, vuln_type),
            ).fetchall()

        return [row["payload"] for row in rows]

    def suggest_order(
        self,
        vuln_type: str,
        tech_stack: str = "",
        engagement_ids: list[str] | None = None,
    ) -> list[str]:
        """
        Return an ordered list of techniques to try for a vuln_type + tech_stack.

        Ordered by success rate descending, with a minimum of 2 attempts
        to avoid noise from single-attempt outliers.
        If engagement_ids is provided, only considers attempts from those engagements.
        """
        patterns = self.get_best_techniques(
            vuln_type, tech_stack, min_attempts=2, engagement_ids=engagement_ids,
        )
        return [p.technique for p in patterns]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def export_stats(self) -> dict[str, Any]:
        """Export a summary of the pattern database for reporting."""
        total_attempts = self.conn.execute(
            "SELECT COUNT(*) as c FROM attempts"
        ).fetchone()["c"]

        total_successes = self.conn.execute(
            "SELECT COUNT(*) as c FROM attempts WHERE success = 1"
        ).fetchone()["c"]

        total_payloads = self.conn.execute(
            "SELECT COUNT(*) as c FROM payloads"
        ).fetchone()["c"]

        # Top techniques by success rate (min 3 attempts)
        top_rows = self.conn.execute(
            """
            SELECT technique, vuln_type,
                   COUNT(*) as attempts,
                   SUM(success) as successes
            FROM attempts
            GROUP BY technique, vuln_type
            HAVING attempts >= 3
            ORDER BY CAST(successes AS REAL) / attempts DESC
            LIMIT 10
            """,
        ).fetchall()

        top_techniques = [
            {
                "technique": r["technique"],
                "vuln_type": r["vuln_type"],
                "attempts": r["attempts"],
                "successes": r["successes"],
                "success_rate": round(r["successes"] / r["attempts"], 3),
            }
            for r in top_rows
        ]

        # Unique tech stacks seen
        tech_stacks = self.conn.execute(
            "SELECT DISTINCT tech_stack FROM attempts WHERE tech_stack != ''"
        ).fetchall()

        return {
            "total_attempts": total_attempts,
            "total_successes": total_successes,
            "overall_success_rate": round(
                total_successes / total_attempts, 3
            ) if total_attempts > 0 else 0.0,
            "total_payloads": total_payloads,
            "top_techniques": top_techniques,
            "tech_stacks_seen": [r["tech_stack"] for r in tech_stacks],
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _engagement_filter(
        engagement_ids: list[str] | None,
    ) -> tuple[str, tuple[str, ...]]:
        """Build a SQL clause and params for engagement_id filtering."""
        if not engagement_ids:
            return "", ()
        placeholders = ",".join("?" * len(engagement_ids))
        return f"AND engagement_id IN ({placeholders})", tuple(engagement_ids)

    def _get_payloads_for(
        self,
        technique: str,
        vuln_type: str,
        tech_stack: str,
    ) -> list[str]:
        """Fetch up to 5 top payloads for a pattern."""
        rows = self.conn.execute(
            """
            SELECT payload FROM payloads
            WHERE technique = ? AND vuln_type = ? AND tech_stack = ?
            ORDER BY success_count DESC
            LIMIT 5
            """,
            (technique, vuln_type, tech_stack),
        ).fetchall()
        return [r["payload"] for r in rows]
