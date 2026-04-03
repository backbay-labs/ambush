"""
Gates - Quality gate execution and verification.

Modules:
    runner      - Execute quality gates (test, lint, typecheck, build)
    flaky       - Flaky test detection and handling
    diff_check  - Diff-based gates (forbidden paths, max size)
"""

from hellcat.core.gates.registry import (
    GateRegistryEntry,
    list_gate_registry,
    list_gate_registry_dict,
)
from hellcat.core.gates.runner import GateRunner

__all__ = [
    "GateRunner",
    "GateRegistryEntry",
    "list_gate_registry",
    "list_gate_registry_dict",
]
