"""
Append-only JSONL writer for crash-safe audit logging.

Each line is atomically written with fsync to ensure crash safety.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class AuditWriter:
    """Crash-safe append-only JSONL audit log writer.

    Writes to ``.hellcat/audit/<engagement-id>.jsonl``.
    Each entry is written as a single JSON line followed by a newline,
    then flushed and fsynced.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fd = open(self.path, "a", encoding="utf-8")  # noqa: SIM115

    def write(self, record: dict[str, Any]) -> None:
        """Write a single audit record as a JSON line (atomic: flush + fsync)."""
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        self._fd.write(line + "\n")
        self._fd.flush()
        os.fsync(self._fd.fileno())

    def read_all(self) -> list[dict[str, Any]]:
        """Read all records from the audit log."""
        records: list[dict[str, Any]] = []
        if not self.path.exists():
            return records
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def close(self) -> None:
        """Close the underlying file handle."""
        self._fd.close()
