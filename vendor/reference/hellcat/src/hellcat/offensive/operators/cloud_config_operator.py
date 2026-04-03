"""
Cloud Config Operator - Cloud misconfiguration analysis.

Reviews cloud configurations (AWS/GCP/Azure) for security misconfigurations
including public S3 buckets, overly permissive IAM policies, exposed
services, missing encryption, and insecure defaults. Supports white-box
analysis of Infrastructure-as-Code (Terraform, CloudFormation) when a
repository is provided.

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


def _parse_cloud_findings(workspace_dir: Path) -> list[VulnerabilityFinding]:
    """Parse cloud configuration analysis deliverable for findings."""
    findings: list[VulnerabilityFinding] = []

    queue_path = workspace_dir / "deliverables" / "cloud_config_findings.json"
    if not queue_path.exists():
        return findings

    try:
        data = json.loads(queue_path.read_text())
        for i, v in enumerate(data.get("misconfigurations", [])):
            findings.append(VulnerabilityFinding(
                vuln_id=v.get("id", f"CLOUD-{i+1:03d}"),
                vuln_type=v.get("type", "cloud-misconfiguration"),
                severity=v.get("severity", "medium"),
                title=v.get("title", "Cloud misconfiguration"),
                description=v.get("description", ""),
                endpoint=v.get("resource", v.get("endpoint", "")),
                parameter=v.get("setting"),
                evidence_summary=v.get("evidence", ""),
                cwe_id=v.get("cwe_id"),
            ))
    except Exception as exc:
        logger.warning("cloud_config.parse_findings_failed", error=str(exc))

    return findings


class CloudConfigOperator(SecurityOperator):
    """Cloud misconfiguration analysis operator.

    Performs systematic review of cloud infrastructure configurations
    across AWS, GCP, and Azure environments. Identifies security
    misconfigurations that could lead to data exposure, unauthorized
    access, or privilege escalation.

    Analysis categories:
    - Storage: Public buckets/blobs, permissive ACLs, missing encryption
    - IAM: Overly permissive policies, unused credentials, MFA gaps
    - Network: Security group misconfigs, exposed services, missing TLS
    - Compute: Instance metadata exposure, unpatched AMIs, weak configs
    - Secrets: Hardcoded credentials, unrotated keys, plaintext secrets
    - Logging: Missing audit trails, disabled CloudTrail/StackDriver
    - IaC: Terraform/CloudFormation misconfigurations (white-box)

    Methodology:
    1. Enumerate cloud resources from recon deliverable and target context.
    2. Analyze IaC files if repository is provided (Terraform, CloudFormation).
    3. Check each resource against security baselines (CIS benchmarks).
    4. Identify misconfigurations with severity and remediation guidance.
    5. Map attack paths from misconfiguration to potential impact.
    """

    name = "cloud-config"
    prompt_templates = [
        "cloud-config.txt",
    ]

    @property
    def operator_type(self) -> OperatorType:
        return "vuln_analysis"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "cloud"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        from hellcat.operators.executor import AgentExecutor, ExecutionConfig, resolve_model
        from hellcat.operators.helpers import build_proof, find_repo_root
        from hellcat.operators.prompt_loader import build_variables_from_manifest, load_prompt
        from hellcat.operators.tools import ToolContext, get_tools_for_operator

        repo_root = find_repo_root()
        variables = build_variables_from_manifest(manifest)

        # Inject IaC context if repository is available
        if manifest.target_repo:
            variables["IAC_CONTEXT"] = (
                f"Infrastructure-as-Code repository is available at: {manifest.target_repo}\n"
                "Perform white-box analysis of Terraform, CloudFormation, "
                "Pulumi, and other IaC files for misconfigurations."
            )
        else:
            variables["IAC_CONTEXT"] = (
                "No IaC repository provided. Perform black-box analysis "
                "of cloud configurations via external enumeration."
            )

        # Inject upstream recon context
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

        system_prompt = load_prompt("prompts/cloud-config.txt", repo_root, variables)

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
            f"Analyze cloud configurations for {manifest.target_url}. "
            "Check for storage misconfigurations, IAM policy issues, "
            "network exposure, missing encryption, and IaC vulnerabilities. "
            "Read any available recon deliverables first. "
            "Save your analysis with save_deliverable type CLOUD_CONFIG."
        )

        logger.info("cloud_config.starting", target=manifest.target_url)

        executor = AgentExecutor(ctx)
        try:
            result = executor.run(config, initial_message)
        finally:
            ctx.close()

        findings = _parse_cloud_findings(workspace_dir)

        logger.info(
            "cloud_config.finished",
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
        """Cloud config analysis is moderately token-intensive."""
        return CostEstimate(
            estimated_tokens=90_000,
            estimated_cost_usd=1.35,
            model=manifest.model,
        )
