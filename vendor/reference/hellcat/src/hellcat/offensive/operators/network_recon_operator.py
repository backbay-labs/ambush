"""
Network Recon Operator - Port scanning, service detection, and OS fingerprinting.

Drives nmap and masscan for network-level reconnaissance. Discovers open
ports, running services, and operating system information across target
hosts and networks. Outputs TargetNodes for each discovered service
(host:port + service metadata).

Phase: recon (pre-recon / recon)
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


def _parse_network_findings(workspace_dir: Path) -> list[VulnerabilityFinding]:
    """Try to parse the network recon deliverable for vulnerability findings."""
    deliverable_path = workspace_dir / "deliverables" / "network_recon_deliverable.md"
    if not deliverable_path.exists():
        return []
    try:
        deliverable_path.read_text()
        findings: list[VulnerabilityFinding] = []
        # Parse any critical/high severity services from the deliverable
        # The LLM agent writes structured findings; we look for JSON blocks
        queue_path = workspace_dir / "deliverables" / "network_recon_services.json"
        if queue_path.exists():
            data = json.loads(queue_path.read_text())
            services = data.get("services", [])
            for i, svc in enumerate(services):
                if svc.get("risk", "info") in ("high", "critical"):
                    findings.append(VulnerabilityFinding(
                        vuln_id=svc.get("id", f"NET-{i+1:03d}"),
                        vuln_type="network-exposure",
                        severity=svc.get("risk", "medium"),
                        title=svc.get("title", f"Exposed service: {svc.get('service', 'unknown')}"),
                        description=svc.get("description", ""),
                        endpoint=f"{svc.get('host', '')}:{svc.get('port', '')}",
                        evidence_summary=svc.get("evidence", ""),
                    ))
        return findings
    except Exception as exc:
        logger.warning("network_recon.parse_findings_failed", error=str(exc))
        return []


class NetworkReconOperator(SecurityOperator):
    """Network reconnaissance operator.

    Performs host discovery, port scanning, service detection, and OS
    fingerprinting across target networks using nmap and masscan. Builds
    a comprehensive map of network-accessible services that feeds into
    downstream service exploitation and vulnerability analysis operators.

    Outputs:
    - Host discovery (live hosts on target network)
    - Open ports and protocols per host
    - Service identification with version detection
    - OS fingerprinting results
    - Network topology observations
    - High-risk service exposure findings
    """

    name = "network-recon"
    prompt_templates = [
        "network-recon.txt",
    ]

    @property
    def operator_type(self) -> OperatorType:
        return "recon"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "network"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        from hellcat.operators.executor import AgentExecutor, ExecutionConfig, resolve_model
        from hellcat.operators.helpers import build_proof, find_repo_root
        from hellcat.operators.prompt_loader import build_variables_from_manifest, load_prompt
        from hellcat.operators.tools import ToolContext, get_tools_for_operator

        repo_root = find_repo_root()
        variables = build_variables_from_manifest(manifest)
        system_prompt = load_prompt("prompts/network-recon.txt", repo_root, variables)

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
            max_turns=manifest.toolchain_config.get("max_turns", 80)
            if manifest.toolchain_config
            else 80,
            timeout_seconds=manifest.timeout_seconds,
            system_prompt=system_prompt,
            tools=get_tools_for_operator("recon"),
        )

        initial_message = (
            f"Begin network reconnaissance of {manifest.target_url}. "
            "Perform host discovery, port scanning, service detection, "
            "and OS fingerprinting. Map all network-accessible services. "
            "Save your deliverable using the save_deliverable tool with "
            "type NETWORK_RECON."
        )

        logger.info("network_recon.starting", target=manifest.target_url)

        executor = AgentExecutor(ctx)
        try:
            result = executor.run(config, initial_message)
        finally:
            ctx.close()

        findings = _parse_network_findings(workspace_dir)

        logger.info(
            "network_recon.finished",
            turns=result.turns,
            cost=f"${result.cost_usd:.4f}",
            findings=len(findings),
            stop_reason=result.stop_reason,
        )

        return build_proof(
            operator_name=self.name,
            manifest=manifest,
            result=result,
            vulns=findings,
        )

    async def health_check(self) -> bool:
        """Check that nmap is available."""
        import shutil

        return shutil.which("nmap") is not None

    def estimate_cost(self, manifest: AttackManifest) -> CostEstimate:
        """Network recon is moderately token-intensive."""
        return CostEstimate(
            estimated_tokens=80_000,
            estimated_cost_usd=1.20,
            model=manifest.model,
        )
