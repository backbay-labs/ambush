"""
State - Beads integration and state management.

Modules:
    manager     - Atomic read/write to Beads
    beads       - Beads CLI wrapper
    models      - Issue, Dep, and related data models
    ephemeral   - Ephemeral running state (gitignored)
    transitions - Status state machine transitions
"""

from cyntra.core.state.ephemeral import EphemeralState
from cyntra.core.state.manager import StateManager
from cyntra.core.state.models import VersionConflictError

__all__ = ["StateManager", "VersionConflictError", "EphemeralState"]
