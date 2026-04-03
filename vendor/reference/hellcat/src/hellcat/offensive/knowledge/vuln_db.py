"""VulnKnowledgeBase - SQLite-backed vulnerability intelligence store with FTS5 search."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from hellcat.offensive.tools.osint.kev import KevEntry

logger = structlog.get_logger()

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cve_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL DEFAULT '',
    cvss            REAL NOT NULL DEFAULT 0.0,
    affected_products TEXT NOT NULL DEFAULT '[]',
    references_json TEXT NOT NULL DEFAULT '[]',
    vuln_type       TEXT NOT NULL DEFAULT '',
    published_date  TEXT NOT NULL DEFAULT '',
    ingested_at     REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_vuln_type
    ON cve_entries (vuln_type);

CREATE TABLE IF NOT EXISTS exploit_techniques (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id    TEXT NOT NULL UNIQUE,
    vuln_type       TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    payload_template TEXT NOT NULL DEFAULT '',
    context         TEXT NOT NULL DEFAULT '',
    success_rate    REAL NOT NULL DEFAULT 0.0,
    source          TEXT NOT NULL DEFAULT '',
    tags            TEXT NOT NULL DEFAULT '[]',
    ingested_at     REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_technique_vuln_type
    ON exploit_techniques (vuln_type);

CREATE TABLE IF NOT EXISTS tech_signatures (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tech_stack      TEXT NOT NULL UNIQUE,
    common_vulns    TEXT NOT NULL DEFAULT '[]',
    default_configs TEXT NOT NULL DEFAULT '{}',
    detection_hints TEXT NOT NULL DEFAULT '[]',
    ingested_at     REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tech_stack
    ON tech_signatures (tech_stack);

CREATE TABLE IF NOT EXISTS defense_signatures (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    defense_id      TEXT NOT NULL UNIQUE,
    defense_type    TEXT NOT NULL DEFAULT '',
    product         TEXT NOT NULL DEFAULT '',
    detection_patterns TEXT NOT NULL DEFAULT '[]',
    known_bypasses  TEXT NOT NULL DEFAULT '[]',
    evasion_techniques TEXT NOT NULL DEFAULT '[]',
    confidence_indicators TEXT NOT NULL DEFAULT '[]',
    severity        TEXT NOT NULL DEFAULT 'medium',
    ingested_at     REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_defense_type
    ON defense_signatures (defense_type);

CREATE INDEX IF NOT EXISTS idx_defense_product
    ON defense_signatures (product);

CREATE TABLE IF NOT EXISTS kev_entries (
    cve_id TEXT PRIMARY KEY,
    date_added TEXT NOT NULL,
    due_date TEXT NOT NULL,
    vendor TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    vulnerability_name TEXT NOT NULL DEFAULT '',
    short_description TEXT NOT NULL DEFAULT '',
    required_action TEXT NOT NULL DEFAULT '',
    ingested_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kev_cve_id ON kev_entries(cve_id);
"""

_FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
    cve_id,
    description,
    affected_products,
    vuln_type,
    content='cve_entries',
    content_rowid='id',
    tokenize='porter unicode61'
);

CREATE TRIGGER IF NOT EXISTS cve_ai AFTER INSERT ON cve_entries BEGIN
    INSERT INTO cve_fts(rowid, cve_id, description, affected_products, vuln_type)
    VALUES (new.id, new.cve_id, new.description, new.affected_products, new.vuln_type);
END;

CREATE TRIGGER IF NOT EXISTS cve_ad AFTER DELETE ON cve_entries BEGIN
    INSERT INTO cve_fts(cve_fts, rowid, cve_id, description, affected_products, vuln_type)
    VALUES ('delete', old.id, old.cve_id, old.description, old.affected_products, old.vuln_type);
END;

CREATE VIRTUAL TABLE IF NOT EXISTS technique_fts USING fts5(
    technique_id,
    name,
    description,
    payload_template,
    context,
    vuln_type,
    tags,
    content='exploit_techniques',
    content_rowid='id',
    tokenize='porter unicode61'
);

CREATE TRIGGER IF NOT EXISTS tech_ai AFTER INSERT ON exploit_techniques BEGIN
    INSERT INTO technique_fts(rowid, technique_id, name, description, payload_template, context, vuln_type, tags)
    VALUES (new.id, new.technique_id, new.name, new.description, new.payload_template, new.context, new.vuln_type, new.tags);
END;

CREATE TRIGGER IF NOT EXISTS tech_ad AFTER DELETE ON exploit_techniques BEGIN
    INSERT INTO technique_fts(technique_fts, rowid, technique_id, name, description, payload_template, context, vuln_type, tags)
    VALUES ('delete', old.id, old.technique_id, old.name, old.description, old.payload_template, old.context, old.vuln_type, old.tags);
END;

CREATE VIRTUAL TABLE IF NOT EXISTS defense_fts USING fts5(
    defense_id,
    defense_type,
    product,
    detection_patterns,
    known_bypasses,
    evasion_techniques,
    confidence_indicators,
    content='defense_signatures',
    content_rowid='id',
    tokenize='porter unicode61'
);

CREATE TRIGGER IF NOT EXISTS defense_ai AFTER INSERT ON defense_signatures BEGIN
    INSERT INTO defense_fts(rowid, defense_id, defense_type, product, detection_patterns, known_bypasses, evasion_techniques, confidence_indicators)
    VALUES (new.id, new.defense_id, new.defense_type, new.product, new.detection_patterns, new.known_bypasses, new.evasion_techniques, new.confidence_indicators);
END;

CREATE TRIGGER IF NOT EXISTS defense_ad AFTER DELETE ON defense_signatures BEGIN
    INSERT INTO defense_fts(defense_fts, rowid, defense_id, defense_type, product, detection_patterns, known_bypasses, evasion_techniques, confidence_indicators)
    VALUES ('delete', old.id, old.defense_id, old.defense_type, old.product, old.detection_patterns, old.known_bypasses, old.evasion_techniques, old.confidence_indicators);
END;
"""


@dataclass
class CveEntry:
    """A CVE record."""

    cve_id: str
    description: str = ""
    cvss: float = 0.0
    affected_products: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    vuln_type: str = ""
    published_date: str = ""


@dataclass
class ExploitTechnique:
    """A curated exploit technique with payload template."""

    technique_id: str
    vuln_type: str
    name: str = ""
    description: str = ""
    payload_template: str = ""
    context: str = ""
    success_rate: float = 0.0
    source: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class TechSignature:
    """Tech stack fingerprint mapping to common vulnerabilities."""

    tech_stack: str
    common_vulns: list[str] = field(default_factory=list)
    default_configs: dict[str, Any] = field(default_factory=dict)
    detection_hints: list[str] = field(default_factory=list)


@dataclass
class DefenseSignature:
    """A defense product signature with detection patterns and bypass techniques."""

    defense_id: str
    defense_type: str  # waf, edr, ids, ips, apparmor, seccomp, egress_proxy, mcp_guard, rate_limiter, captcha, bot_detection
    product: str  # e.g. "ModSecurity", "CloudFlare", "CrowdStrike Falcon"
    detection_patterns: list[str] = field(default_factory=list)  # response signatures
    known_bypasses: list[str] = field(default_factory=list)
    evasion_techniques: list[str] = field(default_factory=list)
    confidence_indicators: list[str] = field(default_factory=list)  # fingerprinting signals
    severity: str = "medium"  # easy/medium/hard/extreme


@dataclass
class SearchResult:
    """A unified search result from any table."""

    source: str  # "cve", "technique", "tech_signature", or "defense"
    score: float
    data: dict[str, Any] = field(default_factory=dict)


class VulnKnowledgeBase:
    """
    SQLite-backed vulnerability knowledge base with FTS5 search.

    Stores CVE entries, exploit techniques, and tech stack signatures.
    Provides full-text search across all tables for RAG enrichment.
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
        self.conn.executescript(_FTS_SQL)
        self.conn.commit()

    def ingest_cve(self, entry: CveEntry) -> None:
        """Insert or replace a single CVE entry."""
        now = time.time()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO cve_entries
                (cve_id, description, cvss, affected_products, references_json,
                 vuln_type, published_date, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.cve_id,
                entry.description,
                entry.cvss,
                json.dumps(entry.affected_products),
                json.dumps(entry.references),
                entry.vuln_type,
                entry.published_date,
                now,
            ),
        )
        self.conn.commit()

    def ingest_cve_feed(self, entries: list[CveEntry]) -> int:
        """Bulk-ingest a list of CVE entries. Returns count ingested."""
        now = time.time()
        rows = [
            (
                e.cve_id, e.description, e.cvss,
                json.dumps(e.affected_products), json.dumps(e.references),
                e.vuln_type, e.published_date, now,
            )
            for e in entries
        ]
        self.conn.executemany(
            """
            INSERT OR REPLACE INTO cve_entries
                (cve_id, description, cvss, affected_products, references_json,
                 vuln_type, published_date, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self.conn.commit()
        logger.debug("knowledge.cve_feed_ingested", count=len(rows))
        return len(rows)

    def ingest_technique(self, technique: ExploitTechnique) -> None:
        """Insert or replace a single exploit technique."""
        now = time.time()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO exploit_techniques
                (technique_id, vuln_type, name, description, payload_template,
                 context, success_rate, source, tags, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                technique.technique_id,
                technique.vuln_type,
                technique.name,
                technique.description,
                technique.payload_template,
                technique.context,
                technique.success_rate,
                technique.source,
                json.dumps(technique.tags),
                now,
            ),
        )
        self.conn.commit()

    def ingest_techniques(self, techniques: list[ExploitTechnique]) -> int:
        """Bulk-ingest exploit techniques. Returns count ingested."""
        now = time.time()
        rows = [
            (
                t.technique_id, t.vuln_type, t.name, t.description,
                t.payload_template, t.context, t.success_rate, t.source,
                json.dumps(t.tags), now,
            )
            for t in techniques
        ]
        self.conn.executemany(
            """
            INSERT OR REPLACE INTO exploit_techniques
                (technique_id, vuln_type, name, description, payload_template,
                 context, success_rate, source, tags, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self.conn.commit()
        logger.debug("knowledge.techniques_ingested", count=len(rows))
        return len(rows)

    def ingest_tech_signature(self, sig: TechSignature) -> None:
        """Insert or replace a tech stack signature."""
        now = time.time()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO tech_signatures
                (tech_stack, common_vulns, default_configs, detection_hints, ingested_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                sig.tech_stack,
                json.dumps(sig.common_vulns),
                json.dumps(sig.default_configs),
                json.dumps(sig.detection_hints),
                now,
            ),
        )
        self.conn.commit()

    def ingest_defense_signature(self, sig: DefenseSignature) -> None:
        """Insert or replace a defense signature."""
        now = time.time()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO defense_signatures
                (defense_id, defense_type, product, detection_patterns,
                 known_bypasses, evasion_techniques, confidence_indicators,
                 severity, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sig.defense_id,
                sig.defense_type,
                sig.product,
                json.dumps(sig.detection_patterns),
                json.dumps(sig.known_bypasses),
                json.dumps(sig.evasion_techniques),
                json.dumps(sig.confidence_indicators),
                sig.severity,
                now,
            ),
        )
        self.conn.commit()

    def ingest_kev_entry(self, entry: KevEntry) -> None:
        """Insert or replace a single CISA KEV entry."""
        now = time.time()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO kev_entries
                (cve_id, date_added, due_date, vendor, product,
                 vulnerability_name, short_description, required_action, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.cve_id,
                entry.date_added,
                entry.due_date,
                entry.vendor,
                entry.product,
                entry.vulnerability_name,
                entry.short_description,
                entry.required_action,
                now,
            ),
        )
        self.conn.commit()

    def ingest_kev_feed(self, entries: list[KevEntry]) -> int:
        """Bulk-ingest KEV entries. Returns count ingested."""
        now = time.time()
        rows = [
            (
                e.cve_id, e.date_added, e.due_date, e.vendor, e.product,
                e.vulnerability_name, e.short_description, e.required_action, now,
            )
            for e in entries
        ]
        self.conn.executemany(
            """
            INSERT OR REPLACE INTO kev_entries
                (cve_id, date_added, due_date, vendor, product,
                 vulnerability_name, short_description, required_action, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self.conn.commit()
        logger.debug("knowledge.kev_feed_ingested", count=len(rows))
        return len(rows)

    def get_kev(self, cve_id: str) -> KevEntry | None:
        """Look up a single KEV entry by CVE ID."""
        row = self.conn.execute(
            "SELECT * FROM kev_entries WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if not row:
            return None
        from hellcat.offensive.tools.osint.kev import KevEntry as _KevEntry

        return _KevEntry(
            cve_id=row["cve_id"],
            date_added=row["date_added"],
            due_date=row["due_date"],
            vendor=row["vendor"],
            product=row["product"],
            vulnerability_name=row["vulnerability_name"],
            short_description=row["short_description"],
            required_action=row["required_action"],
        )

    def is_kev(self, cve_id: str) -> bool:
        """Return True if the given CVE ID exists in the KEV table."""
        row = self.conn.execute(
            "SELECT 1 FROM kev_entries WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        return row is not None

    def get_cve(self, cve_id: str) -> CveEntry | None:
        """Look up a single CVE by ID."""
        row = self.conn.execute(
            "SELECT * FROM cve_entries WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_cve(row)

    def get_technique(self, technique_id: str) -> ExploitTechnique | None:
        """Look up a single technique by ID."""
        row = self.conn.execute(
            "SELECT * FROM exploit_techniques WHERE technique_id = ?",
            (technique_id,),
        ).fetchone()
        if not row:
            return None
        return self._row_to_technique(row)

    def get_techniques_for_vuln_type(
        self, vuln_type: str, limit: int = 20,
    ) -> list[ExploitTechnique]:
        """Get all techniques for a given vulnerability type, ordered by success rate."""
        rows = self.conn.execute(
            """
            SELECT * FROM exploit_techniques
            WHERE vuln_type = ?
            ORDER BY success_rate DESC
            LIMIT ?
            """,
            (vuln_type, limit),
        ).fetchall()
        return [self._row_to_technique(r) for r in rows]

    def get_tech_signature(self, tech_stack: str) -> TechSignature | None:
        """Look up a tech stack signature."""
        row = self.conn.execute(
            "SELECT * FROM tech_signatures WHERE tech_stack = ?",
            (tech_stack,),
        ).fetchone()
        if not row:
            return None
        return self._row_to_tech_sig(row)

    def get_defense(self, defense_id: str) -> DefenseSignature | None:
        """Look up a single defense signature by ID."""
        row = self.conn.execute(
            "SELECT * FROM defense_signatures WHERE defense_id = ?",
            (defense_id,),
        ).fetchone()
        if not row:
            return None
        return self._row_to_defense(row)

    def search_defenses(
        self,
        query: str,
        defense_type: str = "",
        limit: int = 20,
    ) -> list[SearchResult]:
        """
        Search defense signatures via FTS5 full-text search.

        Optionally filter by defense_type.
        """
        if defense_type:
            rows = self.conn.execute(
                """
                SELECT d.*, f.rank
                FROM defense_fts f
                JOIN defense_signatures d ON d.id = f.rowid
                WHERE defense_fts MATCH ? AND d.defense_type = ?
                ORDER BY f.rank
                LIMIT ?
                """,
                (query, defense_type, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT d.*, f.rank
                FROM defense_fts f
                JOIN defense_signatures d ON d.id = f.rowid
                WHERE defense_fts MATCH ?
                ORDER BY f.rank
                LIMIT ?
                """,
                (query, limit),
            ).fetchall()

        results: list[SearchResult] = []
        for row in rows:
            score = -row["rank"] if row["rank"] else 0.0
            sig = self._row_to_defense(row)
            results.append(SearchResult(
                source="defense",
                score=score,
                data={
                    "defense_id": sig.defense_id,
                    "defense_type": sig.defense_type,
                    "product": sig.product,
                    "known_bypasses": sig.known_bypasses,
                    "evasion_techniques": sig.evasion_techniques,
                    "severity": sig.severity,
                },
            ))
        return results

    def get_bypasses_for_defense(self, defense_id: str) -> list[str]:
        """Return known bypass techniques for a specific defense."""
        sig = self.get_defense(defense_id)
        if not sig:
            return []
        return sig.known_bypasses

    def identify_defense(
        self,
        response_headers: dict[str, str] | None = None,
        status_code: int | None = None,
        body_snippet: str = "",
    ) -> list[tuple[DefenseSignature, float]]:
        """
        Identify which defense product(s) match observed response signals.

        Returns a list of (DefenseSignature, confidence) tuples sorted by
        confidence descending.
        """
        headers = response_headers or {}
        search_text = "\n".join([
            str(status_code or ""),
            " ".join(f"{k}: {v}" for k, v in headers.items()),
            body_snippet[:4000],
        ]).lower()

        rows = self.conn.execute(
            "SELECT * FROM defense_signatures"
        ).fetchall()

        matches: list[tuple[DefenseSignature, float]] = []
        for row in rows:
            sig = self._row_to_defense(row)
            match_count = 0
            total_patterns = len(sig.detection_patterns) + len(sig.confidence_indicators)
            if total_patterns == 0:
                continue

            for pattern in sig.detection_patterns:
                if pattern.lower() in search_text:
                    match_count += 1
            for indicator in sig.confidence_indicators:
                if indicator.lower() in search_text:
                    match_count += 1

            if match_count > 0:
                confidence = min(match_count / max(total_patterns, 1), 1.0)
                matches.append((sig, confidence))

        matches.sort(key=lambda x: x[1], reverse=True)
        return matches

    def get_cves_for_vuln_type(
        self, vuln_type: str, limit: int = 20,
    ) -> list[CveEntry]:
        """Get CVEs for a given vulnerability type, ordered by CVSS descending."""
        rows = self.conn.execute(
            """
            SELECT * FROM cve_entries
            WHERE vuln_type = ?
            ORDER BY cvss DESC
            LIMIT ?
            """,
            (vuln_type, limit),
        ).fetchall()
        return [self._row_to_cve(r) for r in rows]

    def search(
        self,
        query: str,
        vuln_type: str = "",
        tech_stack: str = "",
        limit: int = 20,
    ) -> list[SearchResult]:
        """
        Search across CVEs and techniques using FTS5 full-text search.

        Optionally filter by vuln_type and/or tech_stack.
        Results are ranked by FTS5 relevance score.
        """
        results: list[SearchResult] = []

        # Search CVEs
        cve_results = self._search_cves(query, vuln_type, limit)
        results.extend(cve_results)

        # Search techniques
        tech_results = self._search_techniques(query, vuln_type, limit)
        results.extend(tech_results)

        # If tech_stack is provided, also include matching tech signatures
        if tech_stack:
            sig = self.get_tech_signature(tech_stack)
            if sig:
                results.append(SearchResult(
                    source="tech_signature",
                    score=1.0,
                    data={
                        "tech_stack": sig.tech_stack,
                        "common_vulns": sig.common_vulns,
                        "default_configs": sig.default_configs,
                        "detection_hints": sig.detection_hints,
                    },
                ))

        # Sort by score descending, truncate
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]

    def _search_cves(
        self, query: str, vuln_type: str, limit: int,
    ) -> list[SearchResult]:
        """FTS5 search over CVE entries."""
        if vuln_type:
            rows = self.conn.execute(
                """
                SELECT c.*, f.rank
                FROM cve_fts f
                JOIN cve_entries c ON c.id = f.rowid
                WHERE cve_fts MATCH ? AND c.vuln_type = ?
                ORDER BY f.rank
                LIMIT ?
                """,
                (query, vuln_type, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT c.*, f.rank
                FROM cve_fts f
                JOIN cve_entries c ON c.id = f.rowid
                WHERE cve_fts MATCH ?
                ORDER BY f.rank
                LIMIT ?
                """,
                (query, limit),
            ).fetchall()

        results: list[SearchResult] = []
        for row in rows:
            # FTS5 rank is negative (closer to 0 = better)
            score = -row["rank"] if row["rank"] else 0.0
            cve = self._row_to_cve(row)
            results.append(SearchResult(
                source="cve",
                score=score,
                data={
                    "cve_id": cve.cve_id,
                    "description": cve.description,
                    "cvss": cve.cvss,
                    "vuln_type": cve.vuln_type,
                    "affected_products": cve.affected_products,
                },
            ))
        return results

    def _search_techniques(
        self, query: str, vuln_type: str, limit: int,
    ) -> list[SearchResult]:
        """FTS5 search over exploit techniques."""
        if vuln_type:
            rows = self.conn.execute(
                """
                SELECT t.*, f.rank
                FROM technique_fts f
                JOIN exploit_techniques t ON t.id = f.rowid
                WHERE technique_fts MATCH ? AND t.vuln_type = ?
                ORDER BY f.rank
                LIMIT ?
                """,
                (query, vuln_type, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT t.*, f.rank
                FROM technique_fts f
                JOIN exploit_techniques t ON t.id = f.rowid
                WHERE technique_fts MATCH ?
                ORDER BY f.rank
                LIMIT ?
                """,
                (query, limit),
            ).fetchall()

        results: list[SearchResult] = []
        for row in rows:
            score = -row["rank"] if row["rank"] else 0.0
            tech = self._row_to_technique(row)
            results.append(SearchResult(
                source="technique",
                score=score,
                data={
                    "technique_id": tech.technique_id,
                    "name": tech.name,
                    "description": tech.description,
                    "vuln_type": tech.vuln_type,
                    "payload_template": tech.payload_template,
                    "success_rate": tech.success_rate,
                    "tags": tech.tags,
                },
            ))
        return results

    def stats(self) -> dict[str, Any]:
        """Return summary statistics about the knowledge base."""
        cve_count = self.conn.execute(
            "SELECT COUNT(*) as c FROM cve_entries"
        ).fetchone()["c"]
        technique_count = self.conn.execute(
            "SELECT COUNT(*) as c FROM exploit_techniques"
        ).fetchone()["c"]
        sig_count = self.conn.execute(
            "SELECT COUNT(*) as c FROM tech_signatures"
        ).fetchone()["c"]
        defense_count = self.conn.execute(
            "SELECT COUNT(*) as c FROM defense_signatures"
        ).fetchone()["c"]

        vuln_types = self.conn.execute(
            "SELECT DISTINCT vuln_type FROM exploit_techniques ORDER BY vuln_type"
        ).fetchall()

        return {
            "cve_count": cve_count,
            "technique_count": technique_count,
            "tech_signature_count": sig_count,
            "defense_signature_count": defense_count,
            "vuln_types": [r["vuln_type"] for r in vuln_types],
        }

    def _row_to_cve(self, row: sqlite3.Row) -> CveEntry:
        return CveEntry(
            cve_id=row["cve_id"],
            description=row["description"],
            cvss=row["cvss"],
            affected_products=json.loads(row["affected_products"]),
            references=json.loads(row["references_json"]),
            vuln_type=row["vuln_type"],
            published_date=row["published_date"],
        )

    def _row_to_technique(self, row: sqlite3.Row) -> ExploitTechnique:
        return ExploitTechnique(
            technique_id=row["technique_id"],
            vuln_type=row["vuln_type"],
            name=row["name"],
            description=row["description"],
            payload_template=row["payload_template"],
            context=row["context"],
            success_rate=row["success_rate"],
            source=row["source"],
            tags=json.loads(row["tags"]),
        )

    def _row_to_tech_sig(self, row: sqlite3.Row) -> TechSignature:
        return TechSignature(
            tech_stack=row["tech_stack"],
            common_vulns=json.loads(row["common_vulns"]),
            default_configs=json.loads(row["default_configs"]),
            detection_hints=json.loads(row["detection_hints"]),
        )

    def _row_to_defense(self, row: sqlite3.Row) -> DefenseSignature:
        return DefenseSignature(
            defense_id=row["defense_id"],
            defense_type=row["defense_type"],
            product=row["product"],
            detection_patterns=json.loads(row["detection_patterns"]),
            known_bypasses=json.loads(row["known_bypasses"]),
            evasion_techniques=json.loads(row["evasion_techniques"]),
            confidence_indicators=json.loads(row["confidence_indicators"]),
            severity=row["severity"],
        )
