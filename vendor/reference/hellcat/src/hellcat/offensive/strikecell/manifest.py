"""
StrikeManifest - Configuration for what an operator receives inside a StrikeCell.

The manifest is serialised to ``workspace/manifest.json`` and read by the
container entrypoint to configure the operator run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StrikeManifest:
    """Describes a single operator execution inside a StrikeCell."""

    operator_name: str
    target_url: str
    vuln_node_id: str
    attack_type: str  # "vuln_analysis" | "exploitation" | "recon" | "reporting"

    # Operator config
    prompt_template: str = ""
    max_turns: int = 100
    timeout_seconds: int = 600

    # Evasion context (from EvasionLoop if this is a retry)
    evasion_strategy: dict[str, Any] | None = None

    # Resource limits
    cpu_limit: str = "2.0"
    memory_limit: str = "4g"

    # Network
    allowed_hosts: list[str] = field(default_factory=list)

    # Browser / Playwright MCP
    browser_enabled: bool = True
    browser_config: dict[str, Any] = field(default_factory=dict)
    mcp_server_name: str = ""

    # External security tools allowed in this cell
    allowed_tools: list[str] = field(default_factory=list)

    # Model routing (set by PlannerDispatcher via ModelRouter)
    model_config: dict[str, Any] | None = None

    # Prior context from other operators
    prior_findings: list[dict[str, Any]] = field(default_factory=list)

    # Safety / control-plane fields
    authorization_ref: str | None = None
    global_disable: bool = False
    disabled_tools: list[str] = field(default_factory=list)
    disabled_phases: list[str] = field(default_factory=list)
