"""
Recon Operator - Attack surface mapping and intelligence gathering.

Performs white-box analysis of the target application: correlating
external scan data, live application behavior, and source code to
produce a comprehensive attack surface map that all other operators
depend on.
"""

from __future__ import annotations

import os
from pathlib import Path

import structlog

from hellcat.core.adapters.base import CostEstimate
from hellcat.offensive.operator_base import (
    AttackManifest,
    OperatorType,
    SecurityOperator,
    VulnerabilityCategory,
)
from hellcat.core.manifests.attack_proof import AttackProof

logger = structlog.get_logger()


class ReconOperator(SecurityOperator):
    """Reconnaissance and attack surface mapping operator.

    Combines pre-recon (automated scanning + code analysis)
    and recon (interactive exploration + source correlation) phases
    into a single operator that produces the foundational intelligence
    map for all downstream vulnerability analysis operators.

    Outputs:
    - Technology and service map
    - Authentication and session management flow
    - API endpoint inventory with authorization details
    - Input vectors for vulnerability analysis
    - Network and interaction map with security boundaries
    - Role and privilege architecture
    - Authorization vulnerability candidates
    - Injection source catalog
    """

    name = "recon"
    prompt_templates = [
        "pre-recon-code.txt",
        "recon.txt",
    ]

    @property
    def operator_type(self) -> OperatorType:
        return "recon"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "general"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        from hellcat.operators.executor import AgentExecutor, ExecutionConfig, resolve_model
        from hellcat.operators.helpers import build_proof, find_repo_root
        from hellcat.operators.prompt_loader import build_variables_from_manifest, load_prompt
        from hellcat.operators.tools import ToolContext, get_tools_for_operator

        repo_root = find_repo_root()
        variables = build_variables_from_manifest(manifest)
        system_prompt = load_prompt("prompts/recon.txt", repo_root, variables)

        artifacts_dir = Path(os.environ.get("STRIKECELL_ARTIFACTS", "/artifacts"))
        workspace_dir = Path(os.environ.get("STRIKECELL_WORKSPACE", "."))
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        ctx = ToolContext(
            workspace_dir=workspace_dir,
            artifacts_dir=artifacts_dir,
            allowed_hosts=manifest.scope_includes or [],
        )

        config = ExecutionConfig(
            model=resolve_model(manifest.model),
            max_turns=manifest.toolchain_config.get("max_turns", 100)
            if manifest.toolchain_config
            else 100,
            timeout_seconds=manifest.timeout_seconds,
            system_prompt=system_prompt,
            tools=get_tools_for_operator("recon"),
        )

        initial_message = (
            f"Begin reconnaissance of {manifest.target_url}. "
            "Map the full attack surface: technology stack, endpoints, "
            "authentication flows, input vectors, and security boundaries. "
            "Save your deliverable using the save_deliverable tool with type RECON."
        )

        logger.info("recon.starting", target=manifest.target_url)

        executor = AgentExecutor(ctx)
        try:
            result = executor.run(config, initial_message)
        finally:
            ctx.close()

        logger.info(
            "recon.finished",
            turns=result.turns,
            cost=f"${result.cost_usd:.4f}",
            stop_reason=result.stop_reason,
        )

        return build_proof(
            operator_name=self.name,
            manifest=manifest,
            result=result,
        )

    async def health_check(self) -> bool:
        return True

    def estimate_cost(self, manifest: AttackManifest) -> CostEstimate:
        """Recon is the most token-intensive phase due to broad exploration."""
        return CostEstimate(
            estimated_tokens=150_000,
            estimated_cost_usd=2.25,
            model=manifest.model,
        )
