"""Identity Attack Path Operator - AD/Entra ID identity analysis."""
from __future__ import annotations

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
from hellcat.offensive.tools.bloodhound.client import BloodHoundClient

logger = structlog.get_logger()


class IdentityAttackPathOperator(SecurityOperator):
    """Identity attack path analysis operator.

    Ingests BloodHound CE data to map Active Directory and Entra ID
    identity relationships. Identifies shortest attack paths from
    initial access to high-value targets (Domain Admin, etc.).
    """

    name = "identity-attack-paths"
    prompt_templates = ["identity-attack-paths.txt"]

    @property
    def operator_type(self) -> OperatorType:
        return "recon"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "general"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        policy_gates: list[str] = []

        # Scope check: verify the target domain is in scope
        from urllib.parse import urlparse

        from hellcat.operators.tools import is_host_allowed

        parsed = urlparse(manifest.target_url)
        target_host = parsed.hostname or manifest.target_url
        target_port = parsed.port
        scope_includes = manifest.scope_includes or []

        if scope_includes:
            in_scope = is_host_allowed(target_host, target_port, scope_includes)
            if not in_scope:
                logger.warning(
                    "identity.target_not_in_scope",
                    target=target_host,
                    scope=scope_includes,
                )
                return AttackProof(
                    operator_name=self.name,
                    target_id=manifest.target_id,
                    status="blocked",
                    evidence={"error": f"Target {target_host} not in scope"},
                    metadata={"policy_gates": ["scope_check:denied"]},
                )
            policy_gates.append("scope_check:passed")

        client = BloodHoundClient()

        if not client.is_configured:
            logger.warning("identity.bloodhound_not_configured")
            return AttackProof(
                operator_name=self.name,
                target_id=manifest.target_id,
                status="failed",
                evidence={"error": "BloodHound CE not configured"},
                metadata={
                    "data_source": "bloodhound",
                    "policy_gates": policy_gates,
                },
            )

        try:
            attack_paths = client.get_attack_paths()
            domain_info = client.get_domain_info()
        except Exception as exc:
            logger.warning("identity.client_error", error=str(exc))
            return AttackProof(
                operator_name=self.name,
                target_id=manifest.target_id,
                status="failed",
                evidence={"error": f"BloodHound query failed: {exc}"},
                metadata={
                    "data_source": "bloodhound",
                    "policy_gates": policy_gates,
                },
            )

        # Build vulnerability findings from attack paths
        vulns: list[VulnerabilityFinding] = []
        path_descriptions: list[str] = []
        affected_principals: list[str] = []
        escalation_routes: list[str] = []

        for i, path in enumerate(attack_paths):
            source_name = path.source.name
            target_name = path.target.name
            hop_count = len(path.path_nodes)
            rels = " -> ".join(path.relationships) if path.relationships else "direct"

            desc = (
                f"Attack path from {source_name} to {target_name} "
                f"via {hop_count} hops ({rels})"
            )
            path_descriptions.append(desc)
            affected_principals.append(source_name)
            if target_name not in escalation_routes:
                escalation_routes.append(target_name)

            severity = "critical" if path.risk_score >= 8.0 else (
                "high" if path.risk_score >= 5.0 else "medium"
            )

            vulns.append(VulnerabilityFinding(
                vuln_id=f"IDENTITY-{i+1:03d}",
                vuln_type="identity-attack-path",
                severity=severity,
                title=f"Attack path: {source_name} -> {target_name}",
                description=desc,
                endpoint=target_host,
                evidence_summary=(
                    f"Risk score: {path.risk_score}, "
                    f"Relationships: {rels}"
                ),
                cwe_id="CWE-269",
                cvss_score=path.risk_score,
            ))

        # Build evidence
        evidence: dict = {
            "data_source": "bloodhound",
            "path_descriptions": path_descriptions,
            "affected_principals": affected_principals,
            "escalation_routes": escalation_routes,
            "domain_info": domain_info,
            "total_paths": len(attack_paths),
        }

        status = "success" if attack_paths else "partial"
        confidence = 0.85 if attack_paths else 0.3

        logger.info(
            "identity.completed",
            paths_found=len(attack_paths),
            vulns=len(vulns),
            domain=domain_info.get("name", "unknown"),
        )

        return AttackProof(
            operator_name=self.name,
            target_id=manifest.target_id,
            status=status,
            evidence=evidence,
            vulnerabilities_found=vulns,
            metadata={
                "data_source": "bloodhound",
                "item_count": len(attack_paths),
                "policy_gates": policy_gates,
                "domain_info": domain_info,
            },
            confidence=confidence,
        )

    async def health_check(self) -> bool:
        client = BloodHoundClient()
        return client.is_configured

    def estimate_cost(self, manifest: AttackManifest) -> CostEstimate:
        return CostEstimate(
            estimated_tokens=80_000,
            estimated_cost_usd=1.20,
            model=manifest.model,
        )
