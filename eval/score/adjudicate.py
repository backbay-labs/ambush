"""Two-annotator blind adjudication store (sqlite) + Cohen's kappa.

Every TP/FP/near_miss is labeled by two annotators blind to arm; a third breaks ties.
The adjudicated set is the labeled corpus the product gate is later tuned on. Target
inter-annotator kappa >= 0.7.
"""

from __future__ import annotations

import sqlite3
from collections import Counter

SCHEMA = """
CREATE TABLE IF NOT EXISTS adjudication (
  finding_id TEXT, task_id TEXT, annotator TEXT,
  label TEXT,                          -- TP | FP | near_miss
  note TEXT,
  PRIMARY KEY (finding_id, annotator)
);
"""


def connect(path: str = "results/adjudication.sqlite") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute(SCHEMA)
    return conn


def record(conn: sqlite3.Connection, finding_id: str, task_id: str,
           annotator: str, label: str, note: str = "") -> None:
    conn.execute(
        "INSERT OR REPLACE INTO adjudication VALUES (?,?,?,?,?)",
        (finding_id, task_id, annotator, label, note),
    )
    conn.commit()


def cohen_kappa(labels_a: list[str], labels_b: list[str]) -> float:
    """Cohen's kappa between two annotators' label sequences (aligned by finding)."""
    assert len(labels_a) == len(labels_b)
    n = len(labels_a)
    if n == 0:
        return 1.0
    po = sum(1 for x, y in zip(labels_a, labels_b) if x == y) / n
    ca, cb = Counter(labels_a), Counter(labels_b)
    cats = set(ca) | set(cb)
    pe = sum((ca.get(c, 0) / n) * (cb.get(c, 0) / n) for c in cats)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)
