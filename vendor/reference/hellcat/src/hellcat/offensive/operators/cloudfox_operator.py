"""CloudFox Operator - Cloud offensive security analysis."""
from __future__ import annotations

import shutil
from typing import Any

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
    VulnerabilityFinding,
)
from hellcat.offensive.tools.cloudfox.client import CloudFoxClient
from hellcat.offensive.tools.pmapper.client import PMapperClient

logger = structlog.get_logger()


class CloudFoxOperator(SecurityOperator):
    """Cloud offensive security operator.

    Runs CloudFox for AWS/GCP inventory and PMapper for IAM privilege
    escalation graph analysis. Identifies overprivileged roles, lateral
    movement paths, and cloud-specific attack vectors.
    """

    name = "cloud-offensive"
    prompt_templates = ["cloud-offensive.txt"]

    @property
    def operator_type(self) -> OperatorType:
        return "vuln_analysis"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "cloud"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        policy_gates: list[str] = []
        data_sources: list[str] = []

        # Extract AWS profile from toolchain config if provided
        profile = ""
        if manifest.toolchain_config:
            profile = manifest.toolchain_config.get("aws_profile", "")

        cf_client = CloudFoxClient()
        pm_client = PMapperClient()

        inventory: list[dict[str, Any]] = []
        permissions: list[dict[str, Any]] = []
        privesc_paths: list[dict[str, Any]] = []

        # Run CloudFox inventory
        try:
            inventory = cf_client.run_inventory(profile=profile)
            if inventory:
                data_sources.append("cloudfox-inventory")
        except Exception as exc:
            logger.warning("cloudfox.inventory_error", error=str(exc))

        # Run CloudFox permissions
        try:
            permissions = cf_client.run_permissions(profile=profile)
            if permissions:
                data_sources.append("cloudfox-permissions")
        except Exception as exc:
            logger.warning("cloudfox.permissions_error", error=str(exc))

        # Run PMapper privilege escalation analysis
        try:
            privesc_paths = pm_client.query_privesc()
            if privesc_paths:
                data_sources.append("pmapper-privesc")
        except Exception as exc:
            logger.warning("pmapper.privesc_error", error=str(exc))

        if not inventory and not permissions and not privesc_paths:
            logger.warning("cloudfox.no_results")
            return AttackProof(
                operator_name=self.name,
                target_id=manifest.target_id,
                status="failed",
                evidence={"error": "No results from CloudFox or PMapper"},
                metadata={
                    "data_sources": data_sources,
                    "item_count": 0,
                    "policy_gates": policy_gates,
                },
            )

        # Normalize findings
        vulns: list[VulnerabilityFinding] = []
        finding_idx = 0

        # Cloud inventory misconfigurations
        for item in inventory:
            finding_idx += 1
            resource = item.get("resource", item.get("Resource", "unknown"))
            resource_type = item.get("type", item.get("Type", "cloud-resource"))
            region = item.get("region", item.get("Region", ""))
            vulns.append(VulnerabilityFinding(
                vuln_id=f"CLOUD-{finding_idx:03d}",
                vuln_type="cloud-misconfiguration",
                severity="medium",
                title=f"Cloud resource: {resource}",
                description=(
                    f"Enumerated {resource_type} resource {resource} "
                    f"in region {region}"
                ),
                endpoint=resource,
                evidence_summary=f"Resource type: {resource_type}, Region: {region}",
            ))

        # Overprivileged roles from permissions analysis
        for item in permissions:
            finding_idx += 1
            principal = item.get("principal", item.get("Principal", "unknown"))
            action = item.get("action", item.get("Action", "*"))
            vulns.append(VulnerabilityFinding(
                vuln_id=f"CLOUD-{finding_idx:03d}",
                vuln_type="overprivileged-role",
                severity="high",
                title=f"Overprivileged: {principal}",
                description=(
                    f"Principal {principal} has action {action}"
                ),
                endpoint=principal,
                evidence_summary=f"Action: {action}",
                cwe_id="CWE-269",
            ))

        # Privilege escalation paths from PMapper
        for item in privesc_paths:
            finding_idx += 1
            source = item.get("source", item.get("from", "unknown"))
            target = item.get("target", item.get("to", "unknown"))
            method = item.get("method", item.get("path", "unknown"))
            vulns.append(VulnerabilityFinding(
                vuln_id=f"CLOUD-{finding_idx:03d}",
                vuln_type="iam-privesc-path",
                severity="critical",
                title=f"Privesc: {source} -> {target}",
                description=(
                    f"IAM privilege escalation from {source} to {target} "
                    f"via {method}"
                ),
                endpoint=source,
                evidence_summary=f"Method: {method}",
                cwe_id="CWE-269",
            ))

        total_findings = len(vulns)
        evidence = {
            "data_sources": data_sources,
            "inventory_count": len(inventory),
            "permissions_count": len(permissions),
            "privesc_count": len(privesc_paths),
            "total_findings": total_findings,
        }

        confidence = 0.8 if privesc_paths else (0.6 if permissions else 0.4)

        logger.info(
            "cloudfox.completed",
            inventory=len(inventory),
            permissions=len(permissions),
            privesc=len(privesc_paths),
            findings=total_findings,
        )

        return AttackProof(
            operator_name=self.name,
            target_id=manifest.target_id,
            status="success" if vulns else "partial",
            evidence=evidence,
            vulnerabilities_found=vulns,
            metadata={
                "data_sources": data_sources,
                "item_count": total_findings,
                "policy_gates": policy_gates,
            },
            confidence=confidence,
        )

    async def health_check(self) -> bool:
        return shutil.which("cloudfox") is not None

    def estimate_cost(self, manifest: AttackManifest) -> CostEstimate:
        return CostEstimate(
            estimated_tokens=90_000,
            estimated_cost_usd=1.35,
            model=manifest.model,
        )
