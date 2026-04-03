"""
XSS Operator - Cross-site scripting analysis and exploitation.

Uses a sink-to-source backward taint analysis methodology to find
context mismatches where untrusted data reaches DOM sinks without
appropriate encoding.
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


def _parse_xss_findings(workspace_dir: Path) -> list[VulnerabilityFinding]:
    """Try to parse the xss_exploitation_queue.json deliverable."""
    queue_path = workspace_dir / "deliverables" / "xss_exploitation_queue.json"
    if not queue_path.exists():
        return []
    try:
        data = json.loads(queue_path.read_text())
        vulns = data.get("vulnerabilities", [])
        findings: list[VulnerabilityFinding] = []
        for i, v in enumerate(vulns):
            findings.append(VulnerabilityFinding(
                vuln_id=v.get("id", f"XSS-{i+1:03d}"),
                vuln_type=v.get("type", "xss"),
                severity=v.get("severity", "medium"),
                title=v.get("title", v.get("name", "XSS vulnerability")),
                description=v.get("description", ""),
                endpoint=v.get("endpoint", v.get("url", "")),
                parameter=v.get("parameter"),
                evidence_summary=v.get("evidence", ""),
                cwe_id=v.get("cwe_id"),
            ))
        return findings
    except Exception as exc:
        logger.warning("xss.parse_queue_failed", error=str(exc))
        return []


class XSSVulnOperator(SecurityOperator):
    """XSS vulnerability analysis operator.

    Performs sink-to-source backward taint analysis:
    1. Enumerate XSS sinks from the recon deliverable.
    2. Trace each sink backward through the code to find sanitizers
       or untrusted sources.
    3. Check encoding-to-context match (HTML_BODY, HTML_ATTRIBUTE,
       JAVASCRIPT_STRING, URL_PARAM, CSS_VALUE).
    4. Classify as Reflected, Stored, or DOM-based XSS.
    5. Produce exploitation queue for the exploit phase.

    Covers: reflected XSS, stored XSS, DOM-based XSS, mutation XSS,
    DOM clobbering, template injection, CSP bypass analysis.
    """

    name = "xss-vuln"
    prompt_templates = [
        "vuln-xss.txt",
    ]

    @property
    def operator_type(self) -> OperatorType:
        return "vuln_analysis"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "xss"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        from hellcat.operators.executor import AgentExecutor, ExecutionConfig, resolve_model
        from hellcat.operators.helpers import build_proof, find_repo_root
        from hellcat.operators.prompt_loader import build_variables_from_manifest, load_prompt
        from hellcat.operators.tools import ToolContext, get_tools_for_operator

        repo_root = find_repo_root()
        variables = build_variables_from_manifest(manifest)
        system_prompt = load_prompt("prompts/vuln-xss.txt", repo_root, variables)

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
            f"Analyze {manifest.target_url} for XSS vulnerabilities "
            "(reflected, stored, DOM-based, mutation XSS, DOM clobbering). "
            "Read the recon deliverable at deliverables/recon_deliverable.md first. "
            "Save your analysis with save_deliverable type XSS_ANALYSIS, "
            "and the exploitation queue with type XSS_QUEUE."
        )

        logger.info("xss_vuln.starting", target=manifest.target_url)

        executor = AgentExecutor(ctx)
        try:
            result = executor.run(config, initial_message)
        finally:
            ctx.close()

        findings = _parse_xss_findings(workspace_dir)

        logger.info(
            "xss_vuln.finished",
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


class XSSExploitOperator(SecurityOperator):
    """XSS exploitation operator.

    Takes confirmed XSS vulnerabilities and demonstrates real impact:
    session token theft, credential capture, or unauthorized actions
    via crafted payloads executed in the target application's browser
    context.
    """

    name = "xss-exploit"
    prompt_templates = [
        "exploit-xss.txt",
    ]

    @property
    def operator_type(self) -> OperatorType:
        return "exploitation"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "xss"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        from hellcat.core.manifests.attack_proof import ExploitationResult
        from hellcat.operators.executor import AgentExecutor, ExecutionConfig, resolve_model
        from hellcat.operators.helpers import build_proof, find_repo_root
        from hellcat.operators.prompt_loader import build_variables_from_manifest, load_prompt
        from hellcat.operators.tools import ToolContext, get_tools_for_operator

        repo_root = find_repo_root()
        variables = build_variables_from_manifest(manifest)
        system_prompt = load_prompt("prompts/exploit-xss.txt", repo_root, variables)

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
            f"Exploit XSS vulnerabilities in {manifest.target_url}. "
            "Read the exploitation queue at deliverables/xss_exploitation_queue.json "
            "and the intelligence files in deliverables/. "
            "Pursue every vulnerability to a definitive conclusion. "
            "Save your evidence with save_deliverable type XSS_EVIDENCE."
        )

        logger.info("xss_exploit.starting", target=manifest.target_url)

        executor = AgentExecutor(ctx)
        try:
            result = executor.run(config, initial_message)
        finally:
            ctx.close()

        exploits: list[ExploitationResult] = []
        evidence_path = workspace_dir / "deliverables" / "xss_exploitation_evidence.md"
        if evidence_path.exists():
            evidence_text = evidence_path.read_text()
            if "EXPLOITED" in evidence_text.upper():
                exploits.append(ExploitationResult(
                    vuln_id="XSS-AUTO",
                    proof_level="L3",
                    reproducible=True,
                    response_summary=evidence_text[:2000],
                    impact_description="See full evidence report.",
                ))

        vulns = _parse_xss_findings(workspace_dir)

        logger.info(
            "xss_exploit.finished",
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
