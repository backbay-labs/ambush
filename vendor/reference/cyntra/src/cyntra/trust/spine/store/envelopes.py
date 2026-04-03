"""SQLite-backed store for Spine signed envelopes."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


@dataclass
class EnvelopeIngestResult:
    inserted: bool
    duplicate: bool
    fork_detected: bool
    out_of_order: bool
    extended_contiguous_chain: bool
    reason: str | None = None


class EnvelopeStore:
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
                CREATE TABLE IF NOT EXISTS envelopes (
                    envelope_hash TEXT PRIMARY KEY,
                    issuer TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    prev_envelope_hash TEXT,
                    issued_at TEXT NOT NULL,
                    fact_schema TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    received_from TEXT,
                    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_envelopes_issuer_seq
                    ON envelopes(issuer, seq);

                CREATE INDEX IF NOT EXISTS idx_envelopes_fact_schema
                    ON envelopes(fact_schema);

                -- Tracks a best-effort contiguous chain head for each issuer.
                CREATE TABLE IF NOT EXISTS issuer_chain (
                    issuer TEXT PRIMARY KEY,
                    contiguous_seq INTEGER NOT NULL DEFAULT -1,
                    contiguous_head_hash TEXT,
                    fork_detected INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()

    def insert(self, envelope: dict[str, Any], received_from: str | None = None) -> EnvelopeIngestResult:
        env_hash = str(envelope.get("envelope_hash", ""))
        issuer = str(envelope.get("issuer", ""))
        seq = int(envelope.get("seq", -1))
        prev = envelope.get("prev_envelope_hash")
        issued_at = str(envelope.get("issued_at", ""))
        fact_schema = str(envelope.get("fact", {}).get("schema", ""))

        with self._conn() as conn:
            # Dedupe by envelope hash
            existing = conn.execute(
                "SELECT envelope_hash FROM envelopes WHERE envelope_hash = ?",
                (env_hash,),
            ).fetchone()
            if existing is not None:
                return EnvelopeIngestResult(
                    inserted=False,
                    duplicate=True,
                    fork_detected=False,
                    out_of_order=False,
                    extended_contiguous_chain=False,
                    reason="duplicate_envelope_hash",
                )

            # Fork detection: same (issuer, seq) but different hash already stored
            fork_row = conn.execute(
                "SELECT envelope_hash FROM envelopes WHERE issuer = ? AND seq = ? LIMIT 1",
                (issuer, seq),
            ).fetchone()
            fork_detected = fork_row is not None

            # Insert envelope
            conn.execute(
                """
                INSERT INTO envelopes (
                    envelope_hash, issuer, seq, prev_envelope_hash, issued_at,
                    fact_schema, envelope_json, received_from
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    env_hash,
                    issuer,
                    seq,
                    prev,
                    issued_at,
                    fact_schema,
                    json.dumps(envelope, separators=(",", ":"), sort_keys=True),
                    received_from,
                ),
            )

            # Update chain state
            chain = conn.execute(
                "SELECT contiguous_seq, contiguous_head_hash, fork_detected FROM issuer_chain WHERE issuer = ?",
                (issuer,),
            ).fetchone()
            if chain is None:
                conn.execute(
                    """
                    INSERT INTO issuer_chain (issuer, contiguous_seq, contiguous_head_hash, fork_detected)
                    VALUES (?, -1, NULL, 0)
                    """,
                    (issuer,),
                )
                contiguous_seq = -1
                contiguous_head = None
                prior_fork = 0
            else:
                contiguous_seq = int(chain["contiguous_seq"])
                contiguous_head = chain["contiguous_head_hash"]
                prior_fork = int(chain["fork_detected"])

            out_of_order = True
            extended = False

            # Extend contiguous chain only if this is exactly the next expected seq and prev matches.
            if seq == contiguous_seq + 1:
                if contiguous_seq == -1:
                    # First envelope we accept for this issuer.
                    if prev in (None, "", "null"):
                        out_of_order = False
                        extended = True
                else:
                    if prev == contiguous_head:
                        out_of_order = False
                        extended = True

            if extended:
                conn.execute(
                    """
                    UPDATE issuer_chain
                    SET contiguous_seq = ?, contiguous_head_hash = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE issuer = ?
                    """,
                    (seq, env_hash, issuer),
                )

            # Mark fork if detected
            if fork_detected or prior_fork:
                conn.execute(
                    """
                    UPDATE issuer_chain
                    SET fork_detected = 1, updated_at = CURRENT_TIMESTAMP
                    WHERE issuer = ?
                    """,
                    (issuer,),
                )

            conn.commit()

        return EnvelopeIngestResult(
            inserted=True,
            duplicate=False,
            fork_detected=fork_detected,
            out_of_order=out_of_order,
            extended_contiguous_chain=extended,
            reason="ok",
        )

    def get(self, envelope_hash: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT envelope_json FROM envelopes WHERE envelope_hash = ?",
                (envelope_hash,),
            ).fetchone()
            if row is None:
                return None
            return json.loads(row["envelope_json"])

    def list_range(self, issuer: str, from_seq: int, to_seq: int) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT envelope_json FROM envelopes
                WHERE issuer = ? AND seq >= ? AND seq <= ?
                ORDER BY seq ASC
                """,
                (issuer, from_seq, to_seq),
            ).fetchall()
            return [json.loads(r["envelope_json"]) for r in rows]

    def list_hashes_by_issuer_seq(self, issuer: str, seq: int) -> list[str]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT envelope_hash FROM envelopes
                WHERE issuer = ? AND seq = ?
                ORDER BY received_at ASC
                """,
                (issuer, seq),
            ).fetchall()
            return [str(r["envelope_hash"]) for r in rows]

    def get_contiguous_head(self, issuer: str) -> tuple[int, str] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT contiguous_seq, contiguous_head_hash FROM issuer_chain WHERE issuer = ?",
                (issuer,),
            ).fetchone()
            if row is None or row["contiguous_seq"] < 0 or row["contiguous_head_hash"] is None:
                return None
            return int(row["contiguous_seq"]), str(row["contiguous_head_hash"])

    def count_total(self) -> int:
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM envelopes").fetchone()
            return int(row["c"]) if row else 0

    def count_by_issuer(self, issuer: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM envelopes WHERE issuer = ?",
                (issuer,),
            ).fetchone()
            return int(row["c"]) if row else 0

    def count_excluding_issuers(self, trusted_issuers: list[str]) -> int:
        if not trusted_issuers:
            return self.count_total()

        placeholders = ",".join(["?"] * len(trusted_issuers))
        query = f"SELECT COUNT(*) AS c FROM envelopes WHERE issuer NOT IN ({placeholders})"
        with self._conn() as conn:
            row = conn.execute(query, tuple(trusted_issuers)).fetchone()
            return int(row["c"]) if row else 0

    def count_by_fact_schema(self, fact_schema: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM envelopes WHERE fact_schema = ?",
                (fact_schema,),
            ).fetchone()
            return int(row["c"]) if row else 0
