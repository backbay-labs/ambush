"""
Workcell - Isolated execution environment management.

Modules:
    manager     - Create, cleanup, list workcells (git worktrees)
    templates   - Workcell templates for scoped contexts
    isolation   - Sandboxing and security
    cli         - Workcell CLI entry point
    cleanup     - Workcell cleanup logic
    list        - List active workcells
"""

from cyntra.core.workcell.manager import WorkcellManager
from cyntra.core.workcell.templates import (
    BUILTIN_TEMPLATES,
    TemplateApplicator,
    WorkcellSecretManager,
    WorkcellTemplate,
)

__all__ = [
    "WorkcellManager",
    "WorkcellTemplate",
    "TemplateApplicator",
    "WorkcellSecretManager",
    "BUILTIN_TEMPLATES",
]
