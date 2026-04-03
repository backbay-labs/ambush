"""
Auth Operator - Authentication mechanism analysis and exploitation.

Audits the application's identity verification and session management
systems to find logical flaws: broken authentication, session fixation,
credential stuffing vectors, token manipulation, etc.
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


def _parse_auth_findings(workspace_dir: Path) -> list[VulnerabilityFinding]:
    """Try to parse the auth_exploitation_queue.json deliverable."""
    queue_path = workspace_dir / "deliverables" / "auth_exploitation_queue.json"
    if not queue_path.exists():
        return []
    try:
        data = json.loads(queue_path.read_text())
        vulns = data.get("vulnerabilities", [])
        findings: list[VulnerabilityFinding] = []
        for i, v in enumerate(vulns):
            findings.append(VulnerabilityFinding(
                vuln_id=v.get("id", f"AUTH-{i+1:03d}"),
                vuln_type=v.get("type", "auth"),
                severity=v.get("severity", "medium"),
                title=v.get("title", v.get("name", "Authentication vulnerability")),
                description=v.get("description", ""),
                endpoint=v.get("endpoint", v.get("url", "")),
                parameter=v.get("parameter"),
                evidence_summary=v.get("evidence", ""),
                cwe_id=v.get("cwe_id"),
            ))
        return findings
    except Exception as exc:
        logger.warning("auth.parse_queue_failed", error=str(exc))
        return []


class AuthVulnOperator(SecurityOperator):
    """Authentication vulnerability analysis operator.

    Dissects the application's authentication mechanisms to find
    logical flaws in identity verification and session management.

    Focus areas:
    - Login flow analysis (credential handling, error messages)
    - Session management (token generation, storage, validation)
    - Password reset flow (token entropy, expiration, reuse)
    - Multi-factor authentication bypass
    - JWT/token manipulation (algorithm confusion, claim tampering)
    - Session fixation and hijacking vectors
    - Account enumeration via timing or error differences
    """

    name = "auth-vuln"
    prompt_templates = [
        "vuln-auth.txt",
    ]

    @property
    def operator_type(self) -> OperatorType:
        return "vuln_analysis"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "auth"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        from hellcat.operators.executor import AgentExecutor, ExecutionConfig, resolve_model
        from hellcat.operators.helpers import build_proof, find_repo_root
        from hellcat.operators.prompt_loader import build_variables_from_manifest, load_prompt
        from hellcat.operators.tools import ToolContext, get_tools_for_operator

        repo_root = find_repo_root()
        variables = build_variables_from_manifest(manifest)
        system_prompt = load_prompt("prompts/vuln-auth.txt", repo_root, variables)

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
            f"Analyze {manifest.target_url} for authentication vulnerabilities "
            "(broken auth, session fixation, JWT manipulation, credential stuffing, MFA bypass). "
            "Read the recon deliverable at deliverables/recon_deliverable.md first. "
            "Save your analysis with save_deliverable type AUTH_ANALYSIS, "
            "and the exploitation queue with type AUTH_QUEUE."
        )

        logger.info("auth_vuln.starting", target=manifest.target_url)

        executor = AgentExecutor(ctx)
        try:
            result = executor.run(config, initial_message)
        finally:
            ctx.close()

        findings = _parse_auth_findings(workspace_dir)

        logger.info(
            "auth_vuln.finished",
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
            estimated_tokens=100_000,
            estimated_cost_usd=1.50,
            model=manifest.model,
        )


class AuthExploitOperator(SecurityOperator):
    """Authentication exploitation operator.

    Takes confirmed authentication vulnerabilities and demonstrates
    real impact: account takeover, session hijacking, privilege
    escalation via auth bypass.
    """

    name = "auth-exploit"
    prompt_templates = [
        "exploit-auth.txt",
    ]

    @property
    def operator_type(self) -> OperatorType:
        return "exploitation"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "auth"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        from hellcat.core.manifests.attack_proof import ExploitationResult
        from hellcat.operators.executor import AgentExecutor, ExecutionConfig, resolve_model
        from hellcat.operators.helpers import build_proof, find_repo_root
        from hellcat.operators.prompt_loader import build_variables_from_manifest, load_prompt
        from hellcat.operators.tools import ToolContext, get_tools_for_operator

        repo_root = find_repo_root()
        variables = build_variables_from_manifest(manifest)
        system_prompt = load_prompt("prompts/exploit-auth.txt", repo_root, variables)

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
            f"Exploit authentication vulnerabilities in {manifest.target_url}. "
            "Read the exploitation queue at deliverables/auth_exploitation_queue.json "
            "and the intelligence files in deliverables/. "
            "Pursue every vulnerability to a definitive conclusion. "
            "Save your evidence with save_deliverable type AUTH_EVIDENCE."
        )

        logger.info("auth_exploit.starting", target=manifest.target_url)

        executor = AgentExecutor(ctx)
        try:
            result = executor.run(config, initial_message)
        finally:
            ctx.close()

        exploits: list[ExploitationResult] = []
        evidence_path = workspace_dir / "deliverables" / "auth_exploitation_evidence.md"
        if evidence_path.exists():
            evidence_text = evidence_path.read_text()
            if "EXPLOITED" in evidence_text.upper():
                exploits.append(ExploitationResult(
                    vuln_id="AUTH-AUTO",
                    proof_level="L3",
                    reproducible=True,
                    response_summary=evidence_text[:2000],
                    impact_description="See full evidence report.",
                ))

        vulns = _parse_auth_findings(workspace_dir)

        logger.info(
            "auth_exploit.finished",
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
            estimated_tokens=80_000,
            estimated_cost_usd=1.20,
            model=manifest.model,
        )
