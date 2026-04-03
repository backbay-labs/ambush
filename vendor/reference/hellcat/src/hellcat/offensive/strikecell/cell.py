"""
StrikeCell model and lifecycle states.

A StrikeCell is a Docker-isolated (or subprocess-based) execution environment
in which a single security operator runs against an authorized target.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path

from hellcat.offensive.strikecell.manifest import StrikeManifest


class StrikeCellState(str, enum.Enum):
    """Lifecycle states for a StrikeCell."""

    CREATING = "creating"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CLEANED = "cleaned"


@dataclass
class StrikeCell:
    """An isolated execution environment for a single operator run."""

    id: str
    operator_name: str
    target_url: str
    state: StrikeCellState
    container_id: str | None
    created_at: str
    completed_at: str | None
    manifest: StrikeManifest
    logs_dir: Path
    artifacts_dir: Path
    metadata: dict = field(default_factory=dict)


@dataclass
class StrikeCellResult:
    """Outcome of a StrikeCell execution."""

    cell_id: str
    success: bool
    exit_code: int
    duration_ms: int
    proof_path: Path | None
    logs_path: Path
    artifacts: list[str] = field(default_factory=list)
    error: str | None = None
