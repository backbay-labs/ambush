"""StrikeCell entry point — bridge between StrikeCellManager and operator classes.

Invoked as ``python -m hellcat.operators.run --manifest <path>``.
The StrikeCellManager sets environment variables (CELL_ID, TARGET_URL,
OPERATOR_NAME, STRIKECELL_ARTIFACTS, STRIKECELL_LOGS) before calling this.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hellcat.offensive.operator_base import AttackManifest

import structlog

logger = structlog.get_logger()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a Hellcat security operator inside a StrikeCell."
    )
    parser.add_argument(
        "--manifest",
        required=True,
        help="Path to manifest.json",
    )
    return parser.parse_args()


def _load_manifest(path: str) -> dict:
    manifest_path = Path(path)
    if not manifest_path.exists():
        logger.error("run.manifest_not_found", path=path)
        sys.exit(1)
    return json.loads(manifest_path.read_text())


def _manifest_to_attack_manifest(raw: dict) -> AttackManifest:
    """Convert a StrikeManifest dict to an AttackManifest."""
    from hellcat.offensive.operator_base import AttackManifest

    cell_id = os.environ.get("CELL_ID", raw.get("operator_name", "unknown"))
    target_url = os.environ.get("TARGET_URL", raw.get("target_url", ""))

    resolved_model, resolved_provider = _resolve_model_from_manifest(raw)

    return AttackManifest(
        strike_cell_id=cell_id,
        target_id=raw.get("vuln_node_id", ""),
        target_url=target_url,
        model=resolved_model,
        provider=resolved_provider,
        timeout_seconds=raw.get("timeout_seconds", 600),
        rules_avoid=raw.get("rules_avoid"),
        rules_focus=raw.get("rules_focus"),
        login_instructions=raw.get("login_instructions"),
        credentials=raw.get("credentials"),
        scope_includes=raw.get("scope_includes") or raw.get("allowed_hosts"),
        scope_excludes=raw.get("scope_excludes"),
        deliverables_dir=raw.get("deliverables_dir"),
        upstream_findings={"prior_findings": raw.get("prior_findings", [])},
        authorization_ref=raw.get("authorization_ref"),
        global_disable=raw.get("global_disable", False),
        disabled_tools=raw.get("disabled_tools"),
        disabled_phases=raw.get("disabled_phases"),
    )


def _resolve_model_from_manifest(raw: dict) -> tuple[str, str]:
    """Pick model and provider from manifest with precedence:

    1. manifest.model_config.model_id (set by ModelRouter via dispatch)
    2. manifest.model (backward compat)
    3. HELLCAT_MODEL env var or default "sonnet"

    Returns (model_id, provider) tuple.
    """
    model_config = raw.get("model_config")
    if model_config and model_config.get("model_id"):
        resolved = model_config["model_id"]
        provider = model_config.get("provider", "anthropic")
        logger.info(
            "run.model_resolved",
            source="model_config",
            model_id=resolved,
            provider=provider,
        )
        return resolved, provider

    model = raw.get("model")
    if model:
        logger.info(
            "run.model_resolved",
            source="manifest.model",
            model_id=model,
        )
        return model, "anthropic"

    fallback = os.environ.get("HELLCAT_MODEL", "sonnet")
    logger.info(
        "run.model_resolved",
        source="env_or_default",
        model_id=fallback,
    )
    return fallback, "anthropic"


def main() -> None:
    args = _parse_args()
    raw_manifest = _load_manifest(args.manifest)

    operator_name = os.environ.get(
        "OPERATOR_NAME", raw_manifest.get("operator_name", "")
    )
    if not operator_name:
        logger.error("run.no_operator_name")
        sys.exit(1)

    artifacts_dir = Path(
        os.environ.get("STRIKECELL_ARTIFACTS", "/artifacts")
    )
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    logger.info(
        "run.starting",
        operator=operator_name,
        target=raw_manifest.get("target_url"),
        cell_id=os.environ.get("CELL_ID"),
    )

    # Import and instantiate operator
    from hellcat.offensive.operator_registry import get_operator

    try:
        operator = get_operator(operator_name)
    except (KeyError, ImportError) as exc:
        logger.error("run.operator_load_failed", error=str(exc))
        sys.exit(1)

    attack_manifest = _manifest_to_attack_manifest(raw_manifest)

    # Execute
    try:
        proof = asyncio.run(operator.execute(attack_manifest))
    except Exception as exc:
        logger.error("run.execution_failed", error=str(exc), exc_info=True)

        # Write a failure proof
        from hellcat.core.manifests.attack_proof import AttackProof

        proof = AttackProof(
            strike_cell_id=attack_manifest.strike_cell_id,
            target_id=attack_manifest.target_id,
            operator_name=operator_name,
            status="failed",
            metadata={"error": str(exc)},
        )

    # Write proof.json
    proof_path = artifacts_dir / "proof.json"
    proof_path.write_text(json.dumps(proof.to_dict(), indent=2))
    logger.info("run.proof_written", path=str(proof_path))

    # Write cost.json
    cost_data = {
        "operator": operator_name,
        "model": attack_manifest.model,
        "input_tokens": proof.metadata.get("input_tokens", 0),
        "output_tokens": proof.metadata.get("output_tokens", 0),
        "cost_usd": proof.metadata.get("cost_usd", 0.0),
        "turns": proof.metadata.get("turns", 0),
    }
    cost_path = artifacts_dir / "cost.json"
    cost_path.write_text(json.dumps(cost_data, indent=2))
    logger.info("run.cost_written", path=str(cost_path))

    # Exit code based on status
    if proof.status in ("success", "partial"):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
