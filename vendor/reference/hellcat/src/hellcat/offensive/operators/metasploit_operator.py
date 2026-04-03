"""
Metasploit Operator - Framework-based exploitation via msfconsole.

Wraps the MetasploitClient to run Metasploit modules against targets
discovered during reconnaissance. Creates SESSION nodes and
EXPLOITED_VIA edges in the TargetGraph when sessions are obtained.

Phase: exploitation
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
from hellcat.core.manifests.attack_proof import (
    AttackProof,
    ExploitationResult,
    VulnerabilityFinding,
)

logger = structlog.get_logger()


def _parse_metasploit_findings(workspace_dir: Path) -> tuple[
    list[VulnerabilityFinding], list[ExploitationResult]
]:
    """Parse metasploit exploitation deliverable for findings and proofs."""
    vulns: list[VulnerabilityFinding] = []
    exploits: list[ExploitationResult] = []

    evidence_path = workspace_dir / "deliverables" / "metasploit_exploitation_evidence.md"
    if not evidence_path.exists():
        return vulns, exploits

    try:
        evidence_text = evidence_path.read_text()

        findings_path = workspace_dir / "deliverables" / "metasploit_findings.json"
        if findings_path.exists():
            data = json.loads(findings_path.read_text())
            for i, v in enumerate(data.get("vulnerabilities", [])):
                vulns.append(VulnerabilityFinding(
                    vuln_id=v.get("id", f"MSF-{i+1:03d}"),
                    vuln_type=v.get("type", "metasploit-exploit"),
                    severity=v.get("severity", "high"),
                    title=v.get("title", "Metasploit finding"),
                    description=v.get("description", ""),
                    endpoint=v.get("endpoint", ""),
                    parameter=v.get("parameter"),
                    evidence_summary=v.get("evidence", ""),
                    cwe_id=v.get("cwe_id"),
                ))

        if "SESSION" in evidence_text.upper() and "OPENED" in evidence_text.upper():
            exploits.append(ExploitationResult(
                vuln_id="MSF-AUTO",
                proof_level="L4",
                reproducible=True,
                response_summary=evidence_text[:2000],
                impact_description="Metasploit session obtained. See full evidence.",
            ))

    except Exception as exc:
        logger.warning("metasploit.parse_findings_failed", error=str(exc))

    return vulns, exploits


class MetasploitOperator(SecurityOperator):
    """Metasploit Framework exploitation operator.

    Uses msfconsole to run exploit modules against discovered services
    and vulnerabilities. Creates SESSION nodes in the TargetGraph when
    sessions are obtained and links them via EXPLOITED_VIA edges.

    Methodology:
    1. Ingest recon and vulnerability findings.
    2. Search for matching Metasploit modules.
    3. Configure and execute exploits against vulnerable targets.
    4. Track obtained sessions and post-exploitation opportunities.
    5. Harvest credentials for lateral movement.
    """

    name = "metasploit"
    prompt_templates = [
        "exploit-metasploit.txt",
    ]

    @property
    def operator_type(self) -> OperatorType:
        return "exploitation"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "service"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        from hellcat.operators.executor import AgentExecutor, ExecutionConfig, resolve_model
        from hellcat.operators.helpers import build_proof, find_repo_root
        from hellcat.operators.prompt_loader import build_variables_from_manifest, load_prompt
        from hellcat.operators.tools import ToolContext, get_tools_for_operator

        repo_root = find_repo_root()
        variables = build_variables_from_manifest(manifest)

        workspace_dir = Path(os.environ.get("STRIKECELL_WORKSPACE", "."))
        recon_path = workspace_dir / "deliverables" / "network_recon_deliverable.md"
        if recon_path.exists():
            variables["PRIOR_FINDINGS"] = (
                "Network reconnaissance results are available at "
                "deliverables/network_recon_deliverable.md"
            )
        else:
            variables["PRIOR_FINDINGS"] = "No prior network recon available."

        system_prompt = load_prompt(
            "prompts/exploit-metasploit.txt", repo_root, variables,
        )

        artifacts_dir = Path(os.environ.get("STRIKECELL_ARTIFACTS", "/artifacts"))
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        ctx = ToolContext(
            workspace_dir=workspace_dir,
            artifacts_dir=artifacts_dir,
            allowed_hosts=manifest.scope_includes or [],
        )

        config = ExecutionConfig(
            model=resolve_model(manifest.model),
            max_turns=manifest.toolchain_config.get("max_turns", 120)
            if manifest.toolchain_config
            else 120,
            timeout_seconds=manifest.timeout_seconds,
            system_prompt=system_prompt,
            tools=get_tools_for_operator("exploitation"),
        )

        initial_message = (
            f"Exploit targets on {manifest.target_url} using Metasploit Framework. "
            "Review the recon deliverable at "
            "deliverables/network_recon_deliverable.md for the service inventory. "
            "Search for matching modules, configure exploits, and obtain sessions. "
            "Save your evidence with save_deliverable type METASPLOIT_EVIDENCE."
        )

        logger.info("metasploit.starting", target=manifest.target_url)

        executor = AgentExecutor(ctx)
        try:
            result = executor.run(config, initial_message)
        finally:
            ctx.close()

        vulns, exploits = _parse_metasploit_findings(workspace_dir)

        logger.info(
            "metasploit.finished",
            turns=result.turns,
            cost=f"${result.cost_usd:.4f}",
            findings=len(vulns),
            exploits=len(exploits),
        )

        return build_proof(
            operator_name=self.name,
            manifest=manifest,
            result=result,
            vulns=vulns,
            exploits=exploits,
        )

    async def health_check(self) -> bool:
        """Check that msfconsole is available."""
        import shutil

        return shutil.which("msfconsole") is not None

    def estimate_cost(self, manifest: AttackManifest) -> CostEstimate:
        """Metasploit exploitation is moderately token-intensive."""
        return CostEstimate(
            estimated_tokens=120_000,
            estimated_cost_usd=1.80,
            model=manifest.model,
        )
