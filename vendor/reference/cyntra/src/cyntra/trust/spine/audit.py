"""Minimal audit logging for Spine transport events.

This is intentionally small and dependency-free:
- JSONL output for easy ingestion
- Hash-chained entries for basic tamper evidence
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cyntra.trust.primitives.canonical_json import canonicalize as canonicalize_json


def _now_iso_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_hex_prefixed(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()


def _read_last_jsonl_line(path: Path, *, max_bytes: int = 8192) -> str | None:
    if not path.exists():
        return None

    size = path.stat().st_size
    if size == 0:
        return None

    with open(path, "rb") as f:
        f.seek(max(0, size - max_bytes))
        chunk = f.read()

    lines = [ln.strip() for ln in chunk.splitlines() if ln.strip()]
    if not lines:
        return None
    try:
        return lines[-1].decode("utf-8")
    except Exception:
        return None


@dataclass
class AuditLog:
    path: Path
    last_hash: str = "0x" + "00" * 32

    @classmethod
    def open(cls, path: Path) -> "AuditLog":
        path.parent.mkdir(parents=True, exist_ok=True)
        last_line = _read_last_jsonl_line(path)
        if last_line:
            try:
                d = json.loads(last_line)
                last_hash = str(d.get("hash") or cls.last_hash)
                return cls(path=path, last_hash=last_hash)
            except Exception:
                pass
        return cls(path=path)

    def append(self, event: dict[str, Any]) -> None:
        """Append an event, adding `ts`, `prev_hash`, and `hash`."""
        record = dict(event)
        record.setdefault("ts", _now_iso_z())
        record["prev_hash"] = self.last_hash

        unsigned = dict(record)
        unsigned.pop("hash", None)

        h = _sha256_hex_prefixed(canonicalize_json(unsigned).encode("utf-8"))
        record["hash"] = h

        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")

        self.last_hash = h

