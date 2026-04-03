"""
Report Operator - Executive summary and final report generation.

Consumes all exploitation evidence from upstream operators and
produces a comprehensive security assessment report with executive
summary, vulnerability overview, and remediation guidance.
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


class ReportOperator(SecurityOperator):
    """Report generation operator.

    Reads the concatenated exploitation evidence from all upstream
    operators and produces a polished security assessment report for
    technical leadership (CTOs, CISOs, Engineering VPs).

    Responsibilities:
    - Add executive summary with vulnerability type breakdown
    - Add network reconnaissance section (scan findings)
    - Clean exploitation evidence sections (remove hallucinated content)
    - Produce final comprehensive_security_assessment_report.md
    """

    name = "report"
    prompt_templates = [
        "report-executive.txt",
    ]

    @property
    def operator_type(self) -> OperatorType:
        return "reporting"

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
        system_prompt = load_prompt("prompts/report-executive.txt", repo_root, variables)

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
            tools=get_tools_for_operator("reporting"),
        )

        initial_message = (
            f"Generate a comprehensive security assessment report for {manifest.target_url}. "
            "Read all exploitation evidence and deliverables in the deliverables/ directory. "
            "Synthesize an executive summary, vulnerability breakdown by type and severity, "
            "network reconnaissance findings, and remediation guidance. "
            "Save the final report with save_deliverable type REPORT."
        )

        logger.info("report.starting", target=manifest.target_url)

        executor = AgentExecutor(ctx)
        try:
            result = executor.run(config, initial_message)
        finally:
            ctx.close()

        logger.info(
            "report.finished",
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
        """Report generation is relatively lightweight (synthesis only)."""
        return CostEstimate(
            estimated_tokens=50_000,
            estimated_cost_usd=0.75,
            model=manifest.model,
        )
