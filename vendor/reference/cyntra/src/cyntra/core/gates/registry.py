"""
Gate registry - canonical metadata for known gate names.

This file is the source of truth for UI/Docs integrations.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List


@dataclass(frozen=True)
class GateRegistryEntry:
    name: str
    gate_type: str
    description: str
    owner: str
    blocking_default: bool = True
    source: str | None = None

    def to_dict(self) -> dict[str, str | bool | None]:
        return {
            "name": self.name,
            "gate_type": self.gate_type,
            "description": self.description,
            "owner": self.owner,
            "blocking_default": self.blocking_default,
            "source": self.source,
        }


BASE_GATE_REGISTRY: list[GateRegistryEntry] = [
    # === Code Quality Gates ===
    GateRegistryEntry(
        name="test",
        gate_type="code",
        description="Run project tests",
        owner="kernel",
    ),
    GateRegistryEntry(
        name="typecheck",
        gate_type="code",
        description="Static type checking",
        owner="kernel",
    ),
    GateRegistryEntry(
        name="lint",
        gate_type="code",
        description="Lint/style checks",
        owner="kernel",
    ),
    GateRegistryEntry(
        name="build",
        gate_type="code",
        description="Build/compile step",
        owner="kernel",
    ),
    GateRegistryEntry(
        name="max-diff-size",
        gate_type="diff-check",
        description="Block diffs that exceed size thresholds",
        owner="kernel",
    ),
    GateRegistryEntry(
        name="secret-detection",
        gate_type="diff-check",
        description="Scan changed files for likely secrets",
        owner="kernel",
    ),
    GateRegistryEntry(
        name="fab-realism",
        gate_type="fab",
        description="Run Fab realism critics",
        owner="fab",
    ),
    GateRegistryEntry(
        name="fab-godot",
        gate_type="fab",
        description="Validate Godot integration",
        owner="fab",
    ),
    GateRegistryEntry(
        name="fab-playability",
        gate_type="fab",
        description="Run playability/playtest gate",
        owner="fab",
    ),
    GateRegistryEntry(
        name="backbay-test",
        gate_type="code",
        description="Backbay Imperium tests",
        owner="backbay",
    ),
    GateRegistryEntry(
        name="backbay-qa",
        gate_type="code",
        description="Backbay Imperium QA + visual checks",
        owner="backbay",
    ),
    GateRegistryEntry(
        name="forbidden_paths",
        gate_type="policy",
        description="Forbidden path modification check",
        owner="kernel",
    ),
    GateRegistryEntry(
        name="psn-maturity-lockdown",
        gate_type="policy",
        description="Block edits to mature skills without override tag",
        owner="psn",
    ),
    GateRegistryEntry(
        name="psn-skill-tests",
        gate_type="psn",
        description="Strict example tests for modified PSN skills",
        owner="psn",
    ),
    GateRegistryEntry(
        name="drill-score",
        gate_type="provider",
        description="Range/drill scoring gate",
        owner="range",
    ),
    GateRegistryEntry(
        name="workbench-score",
        gate_type="provider",
        description="Workbench scoring gate",
        owner="workbench",
    ),
    # === Integration Invariant Gates (Autonomous) ===
    # These gates cannot be skipped - they catch "built but not wired" failures
    GateRegistryEntry(
        name="exports-have-importers",
        gate_type="integration",
        description="Verify new exports are imported somewhere",
        owner="kernel",
        blocking_default=True,
    ),
    GateRegistryEntry(
        name="components-are-rendered",
        gate_type="integration",
        description="Verify new React components are rendered",
        owner="kernel",
        blocking_default=True,
    ),
    GateRegistryEntry(
        name="hooks-are-called",
        gate_type="integration",
        description="Verify new React hooks are called",
        owner="kernel",
        blocking_default=True,
    ),
    GateRegistryEntry(
        name="integration-review",
        gate_type="review",
        description="Integration reviewer agent verification",
        owner="kernel",
        blocking_default=True,
    ),
    GateRegistryEntry(
        name="adversarial-review",
        gate_type="review",
        description="Adversarial 'break it' reviewer agent",
        owner="kernel",
        blocking_default=False,
    ),
    # === Pre-Flight Validation ===
    GateRegistryEntry(
        name="preflight",
        gate_type="validation",
        description="Validate spec has outcomes, integrations, acceptance criteria",
        owner="kernel",
        blocking_default=True,
    ),
    GateRegistryEntry(
        name="escape-hatch-detection",
        gate_type="validation",
        description="Detect agent rationalization for skipping work",
        owner="kernel",
        blocking_default=True,
    ),
    # === Canary/Smoke Tests ===
    GateRegistryEntry(
        name="canary",
        gate_type="e2e",
        description="Run canary smoke tests with agent-browser",
        owner="kernel",
        blocking_default=True,
    ),
    GateRegistryEntry(
        name="visual-regression",
        gate_type="e2e",
        description="Visual regression screenshot comparison",
        owner="kernel",
        blocking_default=False,
    ),
]


def _load_fab_gate_entries(repo_root: Path) -> list[GateRegistryEntry]:
    gates_dir = repo_root / "fab" / "gates"
    if not gates_dir.exists():
        return []
    entries: list[GateRegistryEntry] = []
    for path in sorted(gates_dir.glob("*.yaml")):
            entries.append(
                GateRegistryEntry(
                    name=path.stem,
                    gate_type="fab-config",
                    description=f"Fab gate config {path.name}",
                    owner="fab",
                    source=str(path.relative_to(repo_root)),
                )
            )
    return entries


def list_gate_registry(repo_root: Path | None = None) -> list[GateRegistryEntry]:
    """Return the canonical registry, optionally extended with fab gate configs."""
    entries = list(BASE_GATE_REGISTRY)
    if repo_root:
        entries.extend(_load_fab_gate_entries(repo_root))
    return entries


def list_gate_registry_dict(repo_root: Path | None = None) -> list[dict[str, str | bool | None]]:
    return [entry.to_dict() for entry in list_gate_registry(repo_root)]
