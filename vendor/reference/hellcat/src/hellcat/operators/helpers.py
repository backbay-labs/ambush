"""Shared utilities for operator implementations."""

from __future__ import annotations

from pathlib import Path

from hellcat.offensive.operator_base import AttackManifest
from hellcat.core.manifests.attack_proof import (
    AttackProof,
    DefenseObservation,
    ExploitationResult,
    VulnerabilityFinding,
)
from hellcat.operators.executor import ExecutionResult


def find_repo_root() -> Path:
    """Locate the Hellcat repo root containing ``prompts/``.

    Search order:
    1. ``/opt/hellcat`` (Docker StrikeCell convention)
    2. Walk up from this file's location
    3. Current working directory
    """
    # Docker container path
    docker_root = Path("/opt/hellcat")
    if (docker_root / "prompts").exists():
        return docker_root

    # Walk up from this file
    cursor = Path(__file__).resolve().parent
    for _ in range(10):
        if (cursor / "prompts").exists():
            return cursor
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent

    # Fallback: cwd
    cwd = Path.cwd()
    if (cwd / "prompts").exists():
        return cwd

    raise FileNotFoundError(
        "Cannot find repo root with prompts/. "
        "Set HELLCAT_ROOT env var or run from the repo directory."
    )


def build_proof(
    operator_name: str,
    manifest: AttackManifest,
    result: ExecutionResult,
    vulns: list[VulnerabilityFinding] | None = None,
    exploits: list[ExploitationResult] | None = None,
    defenses: list[DefenseObservation] | None = None,
) -> AttackProof:
    """Construct an :class:`AttackProof` from execution results.

    Determines status from the combination of findings, errors, and
    stop reason.
    """
    has_vulns = bool(vulns)
    has_exploits = bool(exploits)
    # Timeout/max_turns errors are soft — the agent did partial work
    has_hard_errors = bool(result.errors) and result.stop_reason not in (
        "timeout", "max_turns",
    )

    if has_exploits:
        status = "success"
        confidence = 0.9
    elif has_vulns:
        status = "success"
        confidence = 0.7
    elif result.stop_reason in ("timeout", "max_turns"):
        status = "partial"
        confidence = 0.3
    elif has_hard_errors:
        status = "failed"
        confidence = 0.1
    else:
        # Agent finished normally but found nothing — still a valid result
        status = "success"
        confidence = 0.5

    return AttackProof(
        strike_cell_id=manifest.strike_cell_id,
        target_id=manifest.target_id,
        operator_name=operator_name,
        status=status,
        vulnerabilities_found=vulns or [],
        exploitation_results=exploits or [],
        defense_observations=defenses or [],
        evidence={
            "final_text": result.final_text[:10_000],
            "tool_calls_count": len(result.tool_calls),
        },
        metadata={
            "turns": result.turns,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "cost_usd": result.cost_usd,
            "stop_reason": result.stop_reason,
            "model": manifest.model,
            "errors": result.errors,
        },
        confidence=confidence,
    )
