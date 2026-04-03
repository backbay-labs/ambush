"""
Binary Analysis Operator - Automated reverse engineering with Ghidra.

Drives Ghidra's headless analyzer for automated binary analysis including
decompilation, function enumeration, string extraction, cross-reference
analysis, and vulnerability pattern detection. Supports ELF, PE, Mach-O,
WebAssembly, and firmware images.

Phase: vuln_analysis
"""

from __future__ import annotations

import json
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
from hellcat.core.manifests.attack_proof import AttackProof, VulnerabilityFinding

logger = structlog.get_logger()


def _parse_binary_findings(workspace_dir: Path) -> list[VulnerabilityFinding]:
    """Parse binary analysis deliverable for vulnerability findings."""
    findings: list[VulnerabilityFinding] = []

    queue_path = workspace_dir / "deliverables" / "binary_exploitation_queue.json"
    if not queue_path.exists():
        return findings

    try:
        data = json.loads(queue_path.read_text())
        for i, v in enumerate(data.get("vulnerabilities", [])):
            findings.append(VulnerabilityFinding(
                vuln_id=v.get("id", f"BIN-{i+1:03d}"),
                vuln_type=v.get("type", "binary-vulnerability"),
                severity=v.get("severity", "medium"),
                title=v.get("title", "Binary vulnerability"),
                description=v.get("description", ""),
                endpoint=v.get("function", v.get("endpoint", "")),
                parameter=v.get("address"),
                evidence_summary=v.get("evidence", ""),
                cwe_id=v.get("cwe_id"),
            ))
    except Exception as exc:
        logger.warning("binary_analysis.parse_findings_failed", error=str(exc))

    return findings


class BinaryAnalysisOperator(SecurityOperator):
    """Binary analysis operator using Ghidra headless analyzer.

    Performs automated reverse engineering of compiled binaries, firmware,
    and native extensions to identify security vulnerabilities.

    Analysis categories:
    - Decompilation: Automated function decompilation and analysis
    - Unsafe functions: strcpy, sprintf, gets, system, exec families
    - Hardcoded secrets: Credentials, keys, and tokens in strings/data
    - Buffer overflows: Stack-based and heap-based overflow patterns
    - Crypto weaknesses: Weak algorithms, hardcoded keys, poor randomness
    - Format strings: printf-family format string vulnerabilities
    - Integer issues: Overflow/underflow patterns
    - Import/export: Attack surface mapping via symbol analysis

    Supported formats: ELF, PE, Mach-O, WebAssembly, firmware images

    Methodology:
    1. Import binary into Ghidra headless project for automated analysis.
    2. Enumerate functions, strings, imports, and exports.
    3. Decompile critical functions and analyze for vulnerability patterns.
    4. Cross-reference unsafe function calls and data flow.
    5. Extract hardcoded credentials and cryptographic material.
    6. Map attack surface from binary interface analysis.
    """

    name = "binary-analysis"
    prompt_templates = [
        "binary-analysis.txt",
    ]

    @property
    def operator_type(self) -> OperatorType:
        return "vuln_analysis"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "binary"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        from hellcat.operators.executor import AgentExecutor, ExecutionConfig, resolve_model
        from hellcat.operators.helpers import build_proof, find_repo_root
        from hellcat.operators.prompt_loader import build_variables_from_manifest, load_prompt
        from hellcat.operators.tools import ToolContext, get_tools_for_operator

        repo_root = find_repo_root()
        variables = build_variables_from_manifest(manifest)

        # Inject binary context
        if manifest.target_repo:
            variables["BINARY_CONTEXT"] = (
                f"Target repository with binaries is available at: {manifest.target_repo}\n"
                "Search for compiled binaries, shared libraries, firmware images, "
                "and native extensions within the repository."
            )
        else:
            variables["BINARY_CONTEXT"] = (
                "No repository provided. Analyze binaries discovered during "
                "prior recon phases or downloaded from the target."
            )

        # Inject upstream recon/vuln context
        workspace_dir = Path(os.environ.get("STRIKECELL_WORKSPACE", "."))
        recon_path = workspace_dir / "deliverables" / "recon_deliverable.md"
        net_recon_path = workspace_dir / "deliverables" / "network_recon_deliverable.md"
        prior_parts = []
        if recon_path.exists():
            prior_parts.append(
                "Application recon deliverable: deliverables/recon_deliverable.md"
            )
        if net_recon_path.exists():
            prior_parts.append(
                "Network recon deliverable: deliverables/network_recon_deliverable.md"
            )
        variables["PRIOR_FINDINGS"] = (
            "\n".join(prior_parts) if prior_parts
            else "No prior recon deliverables available."
        )

        system_prompt = load_prompt("prompts/binary-analysis.txt", repo_root, variables)

        artifacts_dir = Path(os.environ.get("STRIKECELL_ARTIFACTS", "/artifacts"))
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        ctx = ToolContext(
            workspace_dir=workspace_dir,
            artifacts_dir=artifacts_dir,
            allowed_hosts=manifest.scope_includes or [],
        )

        config = ExecutionConfig(
            model=resolve_model(manifest.model),
            max_turns=manifest.toolchain_config.get("max_turns", 80)
            if manifest.toolchain_config
            else 80,
            timeout_seconds=manifest.timeout_seconds,
            system_prompt=system_prompt,
            tools=get_tools_for_operator("vuln_analysis"),
        )

        initial_message = (
            f"Analyze binaries associated with {manifest.target_url}. "
            "Use Ghidra headless analyzer for decompilation and function analysis. "
            "Look for unsafe function calls, hardcoded secrets, buffer overflow "
            "patterns, crypto weaknesses, and format string vulnerabilities. "
            "Read any available recon deliverables first. "
            "Save your analysis with save_deliverable type BINARY_ANALYSIS."
        )

        logger.info("binary_analysis.starting", target=manifest.target_url)

        executor = AgentExecutor(ctx)
        try:
            result = executor.run(config, initial_message)
        finally:
            ctx.close()

        findings = _parse_binary_findings(workspace_dir)

        logger.info(
            "binary_analysis.finished",
            turns=result.turns,
            cost=f"${result.cost_usd:.4f}",
            findings=len(findings),
        )

        return build_proof(
            operator_name=self.name,
            manifest=manifest,
            result=result,
            vulns=findings,
        )

    async def health_check(self) -> bool:
        """Check if Ghidra headless analyzer is available."""
        import shutil

        return shutil.which("analyzeHeadless") is not None

    def estimate_cost(self, manifest: AttackManifest) -> CostEstimate:
        """Binary analysis is moderately token-intensive."""
        return CostEstimate(
            estimated_tokens=100_000,
            estimated_cost_usd=1.50,
            model=manifest.model,
        )
