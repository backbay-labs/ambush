"""
PromptEngine - Hellcat prompt template engine.

Provides rich context-aware prompt building:
  1. Loads prompt templates from a prompts directory
  2. Processes @include() directives for shared fragments
  3. Interpolates {{VARIABLE}} placeholders
  4. Injects dynamic TargetGraph context
  5. Injects prior findings as structured intelligence
  6. Injects evasion context when retrying after blocks
  7. Injects OPSEC constraints (noise, budget, circuit state)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# Regex for @include(path) directives
_INCLUDE_RE = re.compile(r"@include\(([^)]+)\)")

# Regex for {{VARIABLE}} placeholders
_VAR_RE = re.compile(r"\{\{([^}]+)\}\}")


@dataclass
class PromptVariables:
    """Static variables for prompt interpolation."""

    web_url: str = ""
    repo_path: str = ""
    mcp_server: str = "playwright-agent1"
    rules_avoid: str = "None"
    rules_focus: str = "None"
    login_instructions: str = ""

    # Hellcat-specific dynamic context (injected as blocks)
    graph_context: str = ""
    prior_findings: str = ""
    evasion_context: str = ""
    opsec_constraints: str = ""
    knowledge_context: str = ""


@dataclass
class LoginConfig:
    """Authentication configuration for login instruction building."""

    login_type: str = "form"  # "form" | "sso"
    login_flow: list[str] = field(default_factory=list)
    username: str = ""
    password: str = ""
    totp_secret: str = ""


class PromptEngine:
    """
    Loads, processes, and enriches prompt templates for Hellcat operators.

    Usage::

        engine = PromptEngine(prompts_dir=Path("prompts"))
        prompt = engine.build(
            operator_name="vuln-injection",
            variables=PromptVariables(web_url="http://target:3001"),
        )
    """

    def __init__(
        self,
        prompts_dir: Path | str,
        pipeline_testing: bool = False,
    ) -> None:
        self.prompts_dir = Path(prompts_dir)
        self.pipeline_testing = pipeline_testing

        # Use pipeline-testing subdirectory when enabled
        if pipeline_testing:
            testing_dir = self.prompts_dir / "pipeline-testing"
            if testing_dir.is_dir():
                self.prompts_dir = testing_dir
                logger.info("prompt_engine.pipeline_testing", prompts_dir=str(self.prompts_dir))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(
        self,
        operator_name: str,
        variables: PromptVariables | None = None,
        *,
        manifest: Any | None = None,
        graph: Any | None = None,
    ) -> str:
        """
        Build a complete prompt for the given operator.

        Args:
            operator_name: Name of the operator (maps to ``<name>.txt``).
            variables: Static variables for interpolation. If None, a
                default PromptVariables is used.
            manifest: Optional StrikeManifest to extract context from.
            graph: Optional TargetGraph for dynamic context injection.

        Returns:
            The fully-processed prompt string.
        """
        variables = variables or PromptVariables()

        # If a manifest is provided, populate variables from it
        if manifest is not None:
            variables = self._variables_from_manifest(variables, manifest)

        # 1. Load template
        template = self.load_template(operator_name)

        # 2. Process @include() directives
        template = self.process_includes(template)

        # 3. Inject dynamic context from graph if available
        if graph is not None and manifest is not None:
            variables.graph_context = self.build_graph_context(
                graph, getattr(manifest, "vuln_node_id", ""),
            )

        # 4. Build prior findings context
        if manifest is not None:
            prior = getattr(manifest, "prior_findings", None)
            if prior:
                variables.prior_findings = self.build_prior_findings_context(prior)

        # 5. Build evasion context
        if manifest is not None:
            evasion = getattr(manifest, "evasion_strategy", None)
            if evasion:
                variables.evasion_context = self.build_evasion_context(evasion)

        # 6. Interpolate all variables
        template = self.interpolate(template, variables)

        return template

    def load_template(self, operator_name: str) -> str:
        """Load a prompt template file by operator name."""
        prompt_path = self.prompts_dir / f"{operator_name}.txt"

        if not prompt_path.is_file():
            raise FileNotFoundError(
                f"Prompt template not found: {prompt_path}"
            )

        logger.debug("prompt_engine.load_template", path=str(prompt_path))
        return prompt_path.read_text(encoding="utf-8")

    def process_includes(self, content: str) -> str:
        """
        Process @include() directives in the template.

        Replaces each ``@include(relative/path.txt)`` with the contents
        of that file relative to the prompts directory.
        """
        def _replace_include(match: re.Match) -> str:
            include_path = self.prompts_dir / match.group(1).strip()
            if not include_path.is_file():
                logger.warning(
                    "prompt_engine.include_not_found",
                    path=str(include_path),
                )
                return match.group(0)  # Leave unresolved
            return include_path.read_text(encoding="utf-8")

        return _INCLUDE_RE.sub(_replace_include, content)

    def interpolate(self, template: str, variables: PromptVariables) -> str:
        """
        Replace ``{{VARIABLE}}`` placeholders with values from variables.
        """
        var_map = self._build_var_map(variables)
        result = template

        for key, value in var_map.items():
            placeholder = "{{" + key + "}}"
            result = result.replace(placeholder, value)

        # Warn about unresolved placeholders
        remaining = _VAR_RE.findall(result)
        if remaining:
            logger.warning(
                "prompt_engine.unresolved_placeholders",
                placeholders=remaining,
            )

        return result

    def list_templates(self) -> list[str]:
        """Return names of all available prompt templates."""
        templates = []
        for p in sorted(self.prompts_dir.glob("*.txt")):
            templates.append(p.stem)
        return templates

    # ------------------------------------------------------------------
    # Context builders
    # ------------------------------------------------------------------

    def build_graph_context(self, graph: Any, vuln_node_id: str) -> str:
        """
        Serialize relevant TargetGraph state as structured context.

        Includes the target node, related vulnerability details, connected
        edges, and defense information for the operator's prompt.
        """
        if not vuln_node_id:
            return ""

        sections: list[str] = []
        sections.append("<graph_context>")

        # Get the vulnerability node
        node = graph.get_node(vuln_node_id)
        if node:
            sections.append("## Current Target Node")
            sections.append(f"- ID: {node.get('id', 'unknown')}")
            sections.append(f"- Type: {node.get('node_type', 'unknown')}")
            sections.append(f"- Status: {node.get('status', 'unknown')}")

            # Add type-specific fields
            for key in ("vuln_type", "severity", "confidence", "description",
                        "source_location", "witness_payload", "url", "method",
                        "tech_stack"):
                val = node.get(key)
                if val:
                    sections.append(f"- {key}: {val}")

            # Parse and include metadata
            meta_json = node.get("metadata_json", "{}")
            if meta_json and meta_json != "{}":
                try:
                    meta = json.loads(meta_json)
                    if meta:
                        sections.append(f"- Metadata: {json.dumps(meta, indent=2)}")
                except json.JSONDecodeError:
                    pass

        # Get connected edges (incoming and outgoing)
        edges_from = graph.get_edges_from(vuln_node_id)
        edges_to = graph.get_edges_to(vuln_node_id)

        if edges_from or edges_to:
            sections.append("\n## Connected Nodes")
            for edge in edges_from:
                target_node = graph.get_node(edge["target_id"])
                if target_node:
                    sections.append(
                        f"- --[{edge['edge_type']}]--> "
                        f"{target_node.get('node_type', '?')}: "
                        f"{_node_summary(target_node)}"
                    )
            for edge in edges_to:
                source_node = graph.get_node(edge["source_id"])
                if source_node:
                    sections.append(
                        f"- <--[{edge['edge_type']}]-- "
                        f"{source_node.get('node_type', '?')}: "
                        f"{_node_summary(source_node)}"
                    )

        sections.append("</graph_context>")
        return "\n".join(sections)

    def build_prior_findings_context(
        self, prior_findings: list[dict[str, Any]],
    ) -> str:
        """
        Format prior findings from earlier engagement phases as structured
        intelligence for the operator prompt.
        """
        if not prior_findings:
            return ""

        sections: list[str] = []
        sections.append("<prior_findings>")
        sections.append(f"## Intelligence from Prior Phases ({len(prior_findings)} findings)")

        for i, finding in enumerate(prior_findings, 1):
            sections.append(f"\n### Finding {i}")
            for key in ("vuln_type", "severity", "confidence", "description",
                        "source_location", "witness_payload", "endpoint",
                        "attack_vector", "observed_behavior"):
                val = finding.get(key)
                if val:
                    sections.append(f"- {key}: {val}")

        sections.append("</prior_findings>")
        return "\n".join(sections)

    def build_evasion_context(self, evasion_strategy: dict[str, Any]) -> str:
        """
        Inject evasion context when retrying after a blocked exploit.

        Includes the block classification, bypass strategy, and techniques
        to try.
        """
        if not evasion_strategy:
            return ""

        sections: list[str] = []
        sections.append("<evasion_context>")
        sections.append("## Evasion Retry Context")
        sections.append(
            "This is a RETRY attempt after a previous exploit was blocked. "
            "You MUST use the bypass strategies below."
        )

        if "classification" in evasion_strategy:
            cls = evasion_strategy["classification"]
            sections.append("\n### Block Classification")
            sections.append(f"- Reason: {cls.get('reason', 'unknown')}")
            sections.append(f"- Confidence: {cls.get('confidence', 0):.0%}")
            if cls.get("details"):
                sections.append(f"- Details: {cls['details']}")

        if "description" in evasion_strategy:
            sections.append("\n### Bypass Strategy")
            sections.append(f"- Strategy: {evasion_strategy['description']}")

        if "techniques" in evasion_strategy:
            sections.append("\n### Techniques to Apply")
            for tech in evasion_strategy["techniques"]:
                sections.append(f"- {tech}")

        if "estimated_success_rate" in evasion_strategy:
            sections.append(
                f"\n- Estimated success rate: "
                f"{evasion_strategy['estimated_success_rate']:.0%}"
            )

        # Include defense intelligence if available
        if "defense_intelligence" in evasion_strategy:
            sections.append(f"\n{evasion_strategy['defense_intelligence']}")

        sections.append("</evasion_context>")
        return "\n".join(sections)

    def build_opsec_context(
        self,
        noise_score: float = 0.0,
        budget_remaining: float = 100.0,
        budget_total: float = 100.0,
        aggression: str = "normal",
        circuit_state: str = "covert",
    ) -> str:
        """
        Build OPSEC constraints block for the operator prompt.
        """
        sections: list[str] = []
        sections.append("<opsec_constraints>")
        sections.append("## Operational Security Constraints")
        sections.append(
            f"- Noise level: {noise_score:.0%} "
            f"({'LOW' if noise_score < 0.3 else 'MEDIUM' if noise_score < 0.6 else 'HIGH'})"
        )
        sections.append(
            f"- Stealth budget: {budget_remaining:.0f}/{budget_total:.0f} "
            f"({budget_remaining / budget_total * 100:.0f}% remaining)"
            if budget_total > 0 else
            "- Stealth budget: UNLIMITED (siege mode)"
        )
        sections.append(f"- Aggression: {aggression}")
        sections.append(f"- OPSEC state: {circuit_state}")

        # Add behavioral directives based on OPSEC state
        if circuit_state in ("detected", "dark"):
            sections.append(
                "\nWARNING: Detection signals received. MINIMIZE footprint. "
                "Avoid aggressive scanning or noisy payloads."
            )
        elif circuit_state == "compromised":
            sections.append(
                "\nCRITICAL: OPSEC compromised. Use only passive techniques. "
                "Do NOT send any active probes."
            )

        if noise_score >= 0.7:
            sections.append(
                "\nHIGH NOISE: Consider using encoding, obfuscation, or timing "
                "techniques to reduce detection probability."
            )

        sections.append("</opsec_constraints>")
        return "\n".join(sections)

    # ------------------------------------------------------------------
    # Login instruction builder
    # ------------------------------------------------------------------

    def build_login_instructions(self, config: LoginConfig) -> str:
        """
        Build login instructions from a LoginConfig, processing the
        shared/login-instructions.txt template with section extraction.
        """
        template_path = self.prompts_dir / "shared" / "login-instructions.txt"
        if not template_path.is_file():
            return ""

        full_template = template_path.read_text(encoding="utf-8")

        # Extract sections by markers
        def get_section(content: str, section_name: str) -> str:
            pattern = rf"<!-- BEGIN:{section_name} -->(.*?)<!-- END:{section_name} -->"
            match = re.search(pattern, content, re.DOTALL)
            return match.group(1).strip() if match else ""

        login_type = config.login_type.upper()
        common = get_section(full_template, "COMMON")
        auth_section = get_section(full_template, login_type)
        verification = get_section(full_template, "VERIFICATION")

        # Fallback to full template if markers missing
        if not common and not auth_section and not verification:
            login_instructions = full_template
        else:
            parts = [s for s in (common, auth_section, verification) if s]
            login_instructions = "\n\n".join(parts)

        # Replace user instructions
        user_instructions = "\n".join(config.login_flow)
        if config.username:
            user_instructions = user_instructions.replace("$username", config.username)
        if config.password:
            user_instructions = user_instructions.replace("$password", config.password)
        if config.totp_secret:
            user_instructions = user_instructions.replace(
                "$totp", f'generated TOTP code using secret "{config.totp_secret}"'
            )

        login_instructions = login_instructions.replace(
            "{{user_instructions}}", user_instructions,
        )
        if config.totp_secret:
            login_instructions = login_instructions.replace(
                "{{totp_secret}}", config.totp_secret,
            )

        return login_instructions

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_var_map(self, variables: PromptVariables) -> dict[str, str]:
        """Build the variable name -> value mapping for interpolation."""
        return {
            "WEB_URL": variables.web_url,
            "REPO_PATH": variables.repo_path,
            "MCP_SERVER": variables.mcp_server,
            "RULES_AVOID": variables.rules_avoid,
            "RULES_FOCUS": variables.rules_focus,
            "LOGIN_INSTRUCTIONS": variables.login_instructions,
            "GRAPH_CONTEXT": variables.graph_context,
            "PRIOR_FINDINGS": variables.prior_findings,
            "EVASION_CONTEXT": variables.evasion_context,
            "OPSEC_CONSTRAINTS": variables.opsec_constraints,
            "KNOWLEDGE_CONTEXT": variables.knowledge_context,
        }

    def _variables_from_manifest(
        self, variables: PromptVariables, manifest: Any,
    ) -> PromptVariables:
        """
        Populate PromptVariables from a StrikeManifest, filling in any
        fields not already set.
        """
        if not variables.web_url and hasattr(manifest, "target_url"):
            variables.web_url = manifest.target_url

        if hasattr(manifest, "prior_findings") and manifest.prior_findings:
            variables.prior_findings = self.build_prior_findings_context(
                manifest.prior_findings,
            )

        if hasattr(manifest, "evasion_strategy") and manifest.evasion_strategy:
            variables.evasion_context = self.build_evasion_context(
                manifest.evasion_strategy,
            )

        return variables


def _node_summary(node: dict[str, Any]) -> str:
    """One-line summary of a graph node for context injection."""
    parts: list[str] = []
    for key in ("url", "vuln_type", "description", "defense_type", "level"):
        val = node.get(key)
        if val:
            parts.append(str(val))
            break
    status = node.get("status", "")
    if status:
        parts.append(f"[{status}]")
    return " ".join(parts) if parts else node.get("id", "unknown")[:12]
