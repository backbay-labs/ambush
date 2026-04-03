"""
SQLite-based trail storage with LSH indexing.

Provides efficient storage and similarity-based querying of trails.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from cyntra.trust.network.schemas import (
    ActionType,
    StateFeatures,
    TaskComplexity,
    Trail,
    TrailContext,
    TrailOutcome,
    TrailQuery,
)


class TrailStore:
    """
    SQLite-based storage for stigmergic trails.

    Provides:
    - Persistent storage of trails
    - Similarity-based querying via LSH
    - Automatic strength decay
    - Citation tracking
    """

    SCHEMA_VERSION = 1

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                );

                CREATE TABLE IF NOT EXISTS trails (
                    id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    state_hash TEXT NOT NULL,
                    state_features_json TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    action_description TEXT NOT NULL,
                    action_embedding_json TEXT,
                    outcome_json TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    strength REAL NOT NULL DEFAULT 1.0,
                    citations INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    last_cited_at TEXT,
                    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                -- Indexes for efficient querying
                CREATE INDEX IF NOT EXISTS idx_trails_state_hash ON trails(state_hash);
                CREATE INDEX IF NOT EXISTS idx_trails_action_type ON trails(action_type);
                CREATE INDEX IF NOT EXISTS idx_trails_strength ON trails(strength);
                CREATE INDEX IF NOT EXISTS idx_trails_created_at ON trails(created_at);
                CREATE INDEX IF NOT EXISTS idx_trails_worker_id ON trails(worker_id);

                -- LSH buckets for similarity search
                CREATE TABLE IF NOT EXISTS trail_lsh_buckets (
                    trail_id TEXT NOT NULL,
                    bucket_id TEXT NOT NULL,
                    band INTEGER NOT NULL,
                    PRIMARY KEY (trail_id, band),
                    FOREIGN KEY (trail_id) REFERENCES trails(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_lsh_bucket ON trail_lsh_buckets(bucket_id, band);

                -- Citation log for reinforcement learning
                CREATE TABLE IF NOT EXISTS citations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trail_id TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    outcome_json TEXT,
                    worker_id TEXT NOT NULL,
                    cited_at TEXT NOT NULL,
                    FOREIGN KEY (trail_id) REFERENCES trails(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_citations_trail ON citations(trail_id);
            """)
            conn.commit()

    def insert(self, trail: Trail) -> None:
        """Insert a trail into the store."""
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO trails (
                    id, version, state_hash, state_features_json,
                    action_type, action_description, action_embedding_json,
                    outcome_json, context_json, worker_id, receipt_hash,
                    signature, strength, citations, created_at, last_cited_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    trail.id,
                    trail.version,
                    trail.state_hash,
                    self._serialize_state_features(trail.state_features),
                    trail.action_type.value,
                    trail.action_description,
                    json.dumps(trail.action_embedding) if trail.action_embedding else None,
                    self._serialize_outcome(trail.outcome),
                    self._serialize_context(trail.context),
                    trail.worker_id,
                    trail.receipt_hash,
                    trail.signature,
                    trail.strength,
                    trail.citations,
                    trail.created_at.isoformat(),
                    trail.last_cited_at.isoformat() if trail.last_cited_at else None,
                ),
            )

            # Update LSH buckets for similarity search
            self._update_lsh_buckets(conn, trail)
            conn.commit()

    def get(self, trail_id: str) -> Optional[Trail]:
        """Get a trail by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM trails WHERE id = ?",
                (trail_id,),
            ).fetchone()

            if row is None:
                return None

            return self._row_to_trail(row)

    def query(self, query: TrailQuery) -> list[Trail]:
        """Query trails with filtering and similarity matching."""
        conditions: list[str] = []
        params: list = []

        # Basic filters
        if query.state_hash:
            conditions.append("state_hash = ?")
            params.append(query.state_hash)

        if query.action_type:
            conditions.append("action_type = ?")
            params.append(query.action_type.value)

        if query.min_strength > 0:
            conditions.append("strength >= ?")
            params.append(query.min_strength)

        if query.min_citations > 0:
            conditions.append("citations >= ?")
            params.append(query.min_citations)

        if query.require_success:
            conditions.append("json_extract(outcome_json, '$.success') = 1")

        if query.language:
            conditions.append("json_extract(context_json, '$.language') = ?")
            params.append(query.language)

        if query.framework:
            conditions.append("json_extract(context_json, '$.framework') = ?")
            params.append(query.framework)

        # Build query
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        sql = f"""
            SELECT * FROM trails
            WHERE {where_clause}
            ORDER BY strength DESC, citations DESC
            LIMIT ? OFFSET ?
        """
        params.extend([query.limit, query.offset])

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            trails = [self._row_to_trail(row) for row in rows]

        # If similarity search requested, filter by LSH
        if query.state_features:
            trails = self._filter_by_similarity(
                trails, query.state_features, query.similarity_threshold
            )

        return trails

    def find_similar(
        self,
        state_features: StateFeatures,
        limit: int = 10,
        min_similarity: float = 0.7,
    ) -> list[tuple[Trail, float]]:
        """Find trails with similar state features."""
        # Get candidate trails from LSH buckets
        buckets = self._compute_lsh_buckets(state_features)

        with self._conn() as conn:
            # Find trails sharing at least one bucket
            placeholders = ",".join("?" * len(buckets))
            rows = conn.execute(
                f"""
                SELECT DISTINCT t.* FROM trails t
                JOIN trail_lsh_buckets b ON t.id = b.trail_id
                WHERE b.bucket_id IN ({placeholders})
                AND t.strength >= 0.1
                ORDER BY t.strength DESC, t.citations DESC
                LIMIT ?
                """,
                (*buckets, limit * 3),  # Fetch extra for filtering
            ).fetchall()

        # Compute exact similarity and filter
        results: list[tuple[Trail, float]] = []
        query_vector = state_features.to_vector()

        for row in rows:
            trail = self._row_to_trail(row)
            trail_vector = trail.state_features.to_vector()
            similarity = self._cosine_similarity(query_vector, trail_vector)

            if similarity >= min_similarity:
                results.append((trail, similarity))

        # Sort by similarity and return top N
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:limit]

    def cite(self, trail_id: str, success: bool, worker_id: str, outcome_json: Optional[str] = None) -> None:
        """Record a citation (trail was followed)."""
        with self._conn() as conn:
            now = datetime.now(timezone.utc).isoformat()

            # Log citation
            conn.execute(
                """
                INSERT INTO citations (trail_id, success, outcome_json, worker_id, cited_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (trail_id, 1 if success else 0, outcome_json, worker_id, now),
            )

            # Update trail
            if success:
                conn.execute(
                    """
                    UPDATE trails
                    SET citations = citations + 1,
                        strength = MIN(1.0, strength * 1.1),
                        last_cited_at = ?
                    WHERE id = ?
                    """,
                    (now, trail_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE trails
                    SET strength = strength * 0.95,
                        last_cited_at = ?
                    WHERE id = ?
                    """,
                    (now, trail_id),
                )

            conn.commit()

    def decay_all(self, lambda_: float = 0.01) -> int:
        """Apply decay to all trails. Returns count of updated trails."""
        with self._conn() as conn:
            # Decay based on days since last activity
            result = conn.execute(
                """
                UPDATE trails
                SET strength = strength * POWER(1 - ?,
                    (julianday('now') - julianday(COALESCE(last_cited_at, created_at))))
                WHERE strength > 0.01
                """,
                (lambda_,),
            )
            conn.commit()
            return result.rowcount

    def prune(self, min_strength: float = 0.01) -> int:
        """Remove trails below strength threshold. Returns count of pruned trails."""
        with self._conn() as conn:
            result = conn.execute(
                "DELETE FROM trails WHERE strength < ?",
                (min_strength,),
            )
            conn.commit()
            return result.rowcount

    def count(self) -> int:
        """Get total trail count."""
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM trails").fetchone()[0]

    def stats(self) -> dict:
        """Get storage statistics."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM trails").fetchone()[0]
            by_action = dict(
                conn.execute(
                    "SELECT action_type, COUNT(*) FROM trails GROUP BY action_type"
                ).fetchall()
            )
            avg_strength = conn.execute(
                "SELECT AVG(strength) FROM trails"
            ).fetchone()[0] or 0.0
            total_citations = conn.execute(
                "SELECT SUM(citations) FROM trails"
            ).fetchone()[0] or 0

            return {
                "total_trails": total,
                "by_action_type": by_action,
                "avg_strength": avg_strength,
                "total_citations": total_citations,
            }

    # --- Serialization helpers ---

    def _serialize_state_features(self, features: StateFeatures) -> str:
        return json.dumps({
            "languages": features.languages,
            "frameworks": features.frameworks,
            "file_count": features.file_count,
            "avg_file_size": features.avg_file_size,
            "test_ratio": features.test_ratio,
            "cyclomatic_avg": features.cyclomatic_avg,
            "depth_avg": features.depth_avg,
        })

    def _deserialize_state_features(self, data: str) -> StateFeatures:
        d = json.loads(data)
        return StateFeatures(
            languages=d.get("languages", {}),
            frameworks=d.get("frameworks", []),
            file_count=d.get("file_count", 0),
            avg_file_size=d.get("avg_file_size", 0),
            test_ratio=d.get("test_ratio", 0.0),
            cyclomatic_avg=d.get("cyclomatic_avg", 0.0),
            depth_avg=d.get("depth_avg", 0.0),
        )

    def _serialize_outcome(self, outcome: TrailOutcome) -> str:
        return json.dumps({
            "success": outcome.success,
            "tests_passed": outcome.tests_passed,
            "tests_failed": outcome.tests_failed,
            "coverage": outcome.coverage,
            "token_count": outcome.token_count,
            "duration_ms": outcome.duration_ms,
            "gates_passed": outcome.gates_passed,
            "gates_failed": outcome.gates_failed,
        })

    def _deserialize_outcome(self, data: str) -> TrailOutcome:
        d = json.loads(data)
        return TrailOutcome(
            success=d.get("success", False),
            tests_passed=d.get("tests_passed", 0),
            tests_failed=d.get("tests_failed", 0),
            coverage=d.get("coverage", 0.0),
            token_count=d.get("token_count", 0),
            duration_ms=d.get("duration_ms", 0),
            gates_passed=d.get("gates_passed", []),
            gates_failed=d.get("gates_failed", []),
        )

    def _serialize_context(self, context: TrailContext) -> str:
        return json.dumps({
            "language": context.language,
            "framework": context.framework,
            "task_complexity": context.task_complexity.value,
            "tags": context.tags,
        })

    def _deserialize_context(self, data: str) -> TrailContext:
        d = json.loads(data)
        return TrailContext(
            language=d.get("language", "unknown"),
            framework=d.get("framework"),
            task_complexity=TaskComplexity(d.get("task_complexity", "moderate")),
            tags=d.get("tags", []),
        )

    def _row_to_trail(self, row: sqlite3.Row) -> Trail:
        """Convert a database row to a Trail object."""
        return Trail(
            id=row["id"],
            version=row["version"],
            state_hash=row["state_hash"],
            state_features=self._deserialize_state_features(row["state_features_json"]),
            action_type=ActionType(row["action_type"]),
            action_description=row["action_description"],
            action_embedding=json.loads(row["action_embedding_json"]) if row["action_embedding_json"] else [],
            outcome=self._deserialize_outcome(row["outcome_json"]),
            context=self._deserialize_context(row["context_json"]),
            worker_id=row["worker_id"],
            receipt_hash=row["receipt_hash"],
            signature=row["signature"],
            strength=row["strength"],
            citations=row["citations"],
            created_at=datetime.fromisoformat(row["created_at"]),
            last_cited_at=datetime.fromisoformat(row["last_cited_at"]) if row["last_cited_at"] else None,
        )

    # --- LSH helpers ---

    def _compute_lsh_buckets(self, features: StateFeatures, num_bands: int = 4) -> list[str]:
        """Compute LSH bucket IDs for similarity search."""
        import hashlib

        vector = features.to_vector()
        buckets = []

        # Simple LSH: hash segments of the feature vector
        band_size = len(vector) // num_bands
        for band in range(num_bands):
            start = band * band_size
            end = start + band_size if band < num_bands - 1 else len(vector)
            segment = vector[start:end]

            # Quantize and hash
            quantized = tuple(int(v * 10) for v in segment)
            bucket_hash = hashlib.sha256(
                f"{band}:{quantized}".encode()
            ).hexdigest()[:16]
            buckets.append(f"b{band}_{bucket_hash}")

        return buckets

    def _update_lsh_buckets(self, conn: sqlite3.Connection, trail: Trail) -> None:
        """Update LSH buckets for a trail."""
        # Remove old buckets
        conn.execute("DELETE FROM trail_lsh_buckets WHERE trail_id = ?", (trail.id,))

        # Insert new buckets
        buckets = self._compute_lsh_buckets(trail.state_features)
        for band, bucket_id in enumerate(buckets):
            conn.execute(
                "INSERT INTO trail_lsh_buckets (trail_id, bucket_id, band) VALUES (?, ?, ?)",
                (trail.id, bucket_id, band),
            )

    def _filter_by_similarity(
        self,
        trails: list[Trail],
        query_features: StateFeatures,
        threshold: float,
    ) -> list[Trail]:
        """Filter trails by cosine similarity."""
        query_vector = query_features.to_vector()
        return [
            t for t in trails
            if self._cosine_similarity(query_vector, t.state_features.to_vector()) >= threshold
        ]

    def _cosine_similarity(self, a: list[float], b: list[float]) -> float:
        """Compute cosine similarity between two vectors."""
        if len(a) != len(b) or not a:
            return 0.0

        dot = sum(x * y for x, y in zip(a, b))
        norm_a = sum(x * x for x in a) ** 0.5
        norm_b = sum(x * x for x in b) ** 0.5

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot / (norm_a * norm_b)
