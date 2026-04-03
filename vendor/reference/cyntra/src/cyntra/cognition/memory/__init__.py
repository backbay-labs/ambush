"""
Cyntra Memory System

Persistent memory compression for Cyntra agents, following claude-mem patterns.
See: https://github.com/thedotmack/claude-mem

Architecture:
- 5 Lifecycle Hooks: WorkcellStart, ToolUse, GateResult, Summary, WorkcellEnd
- SQLite + FTS5 for observations/sessions
- Progressive disclosure: Index → Details → Evidence
"""

from cyntra.cognition.memory.database import MemoryDB
from cyntra.cognition.memory.hooks import MemoryHooks
from cyntra.cognition.memory.observations import (
    Concept,
    Importance,
    Observation,
    ObservationType,
)

__all__ = [
    "MemoryDB",
    "MemoryHooks",
    "Observation",
    "ObservationType",
    "Concept",
    "Importance",
]
