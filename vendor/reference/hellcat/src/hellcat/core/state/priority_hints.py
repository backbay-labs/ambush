"""
PriorityHintStore - Side-channel priority hints from sleeptime consolidation.

Reads/writes `.hellcat/state/priority_hints.json` so the scheduler can boost
or deprioritize issues based on patterns discovered during consolidation.

The file is intentionally separate from .hellcat/issues.jsonl to avoid
modifying the Issue model and to keep the hint lifecycle independent.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class PriorityHint:
    """A single priority adjustment hint for an issue."""

    issue_id: str
    source: str  # e.g. "sleeptime", "kernelgen"
    weight: float  # positive = deprioritize, negative = boost
    reason: str = ""
    created_at: float = field(default_factory=time.time)
    ttl_seconds: float = 3600.0  # default 1 hour

    @property
    def expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_seconds

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PriorityHint:
        return cls(
            issue_id=str(data.get("issue_id", "")),
            source=str(data.get("source", "")),
            weight=float(data.get("weight", 0.0)),
            reason=str(data.get("reason", "")),
            created_at=float(data.get("created_at", time.time())),
            ttl_seconds=float(data.get("ttl_seconds", 3600.0)),
        )


class PriorityHintStore:
    """
    Persistent store for priority hints at `.hellcat/state/priority_hints.json`.

    Thread-safe for single-writer scenarios (sleeptime is the only writer).
    The scheduler is a read-only consumer.
    """

    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / "priority_hints.json"

    def load(self) -> list[PriorityHint]:
        """Load all non-expired hints."""
        if not self._path.exists():
            return []
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            hints = [PriorityHint.from_dict(h) for h in raw if isinstance(h, dict)]
            return [h for h in hints if not h.expired]
        except (json.JSONDecodeError, OSError) as e:
            logger.debug("Failed to load priority hints", error=str(e))
            return []

    def save(self, hints: list[PriorityHint]) -> None:
        """Persist hints, pruning expired entries."""
        active = [h for h in hints if not h.expired]
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps([asdict(h) for h in active], indent=2),
            encoding="utf-8",
        )

    def add_hint(self, hint: PriorityHint) -> None:
        """Add a hint, replacing any existing hint for the same issue+source."""
        hints = self.load()
        hints = [h for h in hints if not (h.issue_id == hint.issue_id and h.source == hint.source)]
        hints.append(hint)
        self.save(hints)

    def add_hints(self, new_hints: list[PriorityHint]) -> None:
        """Add multiple hints in one write, deduplicating by issue_id+source."""
        hints = self.load()
        new_keys = {(h.issue_id, h.source) for h in new_hints}
        hints = [h for h in hints if (h.issue_id, h.source) not in new_keys]
        hints.extend(new_hints)
        self.save(hints)

    def get_weight_map(self) -> dict[str, float]:
        """
        Return a {issue_id: total_weight} map for the scheduler.

        Multiple hints for the same issue are summed.
        """
        hints = self.load()
        weights: dict[str, float] = {}
        for h in hints:
            weights[h.issue_id] = weights.get(h.issue_id, 0.0) + h.weight
        return weights

    def clear(self) -> None:
        """Remove all hints."""
        if self._path.exists():
            self._path.unlink()
