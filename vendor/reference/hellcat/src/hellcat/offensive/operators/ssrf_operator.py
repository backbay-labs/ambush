"""
SSRF Operator - Server-side request forgery analysis and exploitation.

Identifies where untrusted user input influences outbound server-side
HTTP requests, enabling access to internal services, cloud metadata
endpoints, or arbitrary external resources.
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


def _parse_ssrf_findings(workspace_dir: Path) -> list[VulnerabilityFinding]:
    """Try to parse the ssrf_exploitation_queue.json deliverable."""
    queue_path = workspace_dir / "deliverables" / "ssrf_exploitation_queue.json"
    if not queue_path.exists():
        return []
    try:
        data = json.loads(queue_path.read_text())
        vulns = data.get("vulnerabilities", [])
        findings: list[VulnerabilityFinding] = []
        for i, v in enumerate(vulns):
            findings.append(VulnerabilityFinding(
                vuln_id=v.get("id", f"SSRF-{i+1:03d}"),
                vuln_type=v.get("type", "ssrf"),
                severity=v.get("severity", "medium"),
                title=v.get("title", v.get("name", "SSRF vulnerability")),
                description=v.get("description", ""),
                endpoint=v.get("endpoint", v.get("url", "")),
                parameter=v.get("parameter"),
                evidence_summary=v.get("evidence", ""),
                cwe_id=v.get("cwe_id"),
            ))
        return findings
    except Exception as exc:
        logger.warning("ssrf.parse_queue_failed", error=str(exc))
        return []


class SSRFVulnOperator(SecurityOperator):
    """SSRF vulnerability analysis operator.

    Traces how user input flows into outbound HTTP requests made by
    the server, identifying where URLs, hostnames, ports, or request
    parameters can be manipulated.

    Focus areas:
    - URL parameter injection into fetch/request calls
    - Hostname/IP manipulation for internal service access
    - Cloud metadata endpoint access (169.254.169.254)
    - Protocol smuggling (file://, gopher://, dict://)
    - DNS rebinding vectors
    - Redirect-based SSRF chains
    - PDF/image rendering SSRF (server-side rendering of user URLs)
    """

    name = "ssrf-vuln"
    prompt_templates = [
        "vuln-ssrf.txt",
    ]

    @property
    def operator_type(self) -> OperatorType:
        return "vuln_analysis"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "ssrf"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        from hellcat.operators.executor import AgentExecutor, ExecutionConfig, resolve_model
        from hellcat.operators.helpers import build_proof, find_repo_root
        from hellcat.operators.prompt_loader import build_variables_from_manifest, load_prompt
        from hellcat.operators.tools import ToolContext, get_tools_for_operator

        repo_root = find_repo_root()
        variables = build_variables_from_manifest(manifest)
        system_prompt = load_prompt("prompts/vuln-ssrf.txt", repo_root, variables)

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
            tools=get_tools_for_operator("vuln_analysis"),
        )

        initial_message = (
            f"Analyze {manifest.target_url} for SSRF vulnerabilities "
            "(URL injection, internal service access, cloud metadata, "
            "protocol smuggling, DNS rebinding, redirect chains). "
            "Read the recon deliverable at deliverables/recon_deliverable.md first. "
            "Save your analysis with save_deliverable type SSRF_ANALYSIS, "
            "and the exploitation queue with type SSRF_QUEUE."
        )

        logger.info("ssrf_vuln.starting", target=manifest.target_url)

        executor = AgentExecutor(ctx)
        try:
            result = executor.run(config, initial_message)
        finally:
            ctx.close()

        findings = _parse_ssrf_findings(workspace_dir)

        logger.info(
            "ssrf_vuln.finished",
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
        return True

    def estimate_cost(self, manifest: AttackManifest) -> CostEstimate:
        return CostEstimate(
            estimated_tokens=80_000,
            estimated_cost_usd=1.20,
            model=manifest.model,
        )


class SSRFExploitOperator(SecurityOperator):
    """SSRF exploitation operator.

    Takes confirmed SSRF vulnerabilities and demonstrates real
    impact: internal service access, cloud metadata extraction,
    or network scanning via the application server.
    """

    name = "ssrf-exploit"
    prompt_templates = [
        "exploit-ssrf.txt",
    ]

    @property
    def operator_type(self) -> OperatorType:
        return "exploitation"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "ssrf"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        from hellcat.core.manifests.attack_proof import ExploitationResult
        from hellcat.operators.executor import AgentExecutor, ExecutionConfig, resolve_model
        from hellcat.operators.helpers import build_proof, find_repo_root
        from hellcat.operators.prompt_loader import build_variables_from_manifest, load_prompt
        from hellcat.operators.tools import ToolContext, get_tools_for_operator

        repo_root = find_repo_root()
        variables = build_variables_from_manifest(manifest)
        system_prompt = load_prompt("prompts/exploit-ssrf.txt", repo_root, variables)

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
            tools=get_tools_for_operator("exploitation"),
        )

        initial_message = (
            f"Exploit SSRF vulnerabilities in {manifest.target_url}. "
            "Read the exploitation queue at deliverables/ssrf_exploitation_queue.json "
            "and the intelligence files in deliverables/. "
            "Pursue every vulnerability to a definitive conclusion. "
            "Save your evidence with save_deliverable type SSRF_EVIDENCE."
        )

        logger.info("ssrf_exploit.starting", target=manifest.target_url)

        executor = AgentExecutor(ctx)
        try:
            result = executor.run(config, initial_message)
        finally:
            ctx.close()

        exploits: list[ExploitationResult] = []
        evidence_path = workspace_dir / "deliverables" / "ssrf_exploitation_evidence.md"
        if evidence_path.exists():
            evidence_text = evidence_path.read_text()
            if "EXPLOITED" in evidence_text.upper():
                exploits.append(ExploitationResult(
                    vuln_id="SSRF-AUTO",
                    proof_level="L3",
                    reproducible=True,
                    response_summary=evidence_text[:2000],
                    impact_description="See full evidence report.",
                ))

        vulns = _parse_ssrf_findings(workspace_dir)

        logger.info(
            "ssrf_exploit.finished",
            turns=result.turns,
            cost=f"${result.cost_usd:.4f}",
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
        return True

    def estimate_cost(self, manifest: AttackManifest) -> CostEstimate:
        return CostEstimate(
            estimated_tokens=60_000,
            estimated_cost_usd=0.90,
            model=manifest.model,
        )
