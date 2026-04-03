"""
SecurityOperator - Base class for Hellcat pentesting operators.

Each operator wraps one or more prompt templates and exposes
them as a Hellcat toolchain adapter that the kernel can schedule
and dispatch against targets.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Literal

from hellcat.core.adapters.base import CostEstimate
from hellcat.core.manifests.attack_proof import AttackProof


@dataclass
class AttackManifest:
    """Input specification for a security operator execution.

    Analogous to the dict-based manifest used by ToolchainAdapter,
    but typed for the red-teaming workflow.
    """

    strike_cell_id: str
    target_id: str
    target_url: str
    target_repo: str | None = None

    # Scope constraints
    scope_includes: list[str] | None = None
    scope_excludes: list[str] | None = None

    # Auth context for the target
    login_instructions: str | None = None
    credentials: dict[str, str] | None = None

    # Custom rules
    rules_avoid: list[str] | None = None
    rules_focus: list[str] | None = None

    # Upstream intelligence (deliverables from prior phases)
    deliverables_dir: str | None = None
    upstream_findings: dict[str, Any] | None = None

    # Execution config
    model: str = "opus"
    provider: str = "anthropic"
    timeout_seconds: int = 1800
    toolchain_config: dict[str, Any] | None = None

    # Safety / control-plane fields
    authorization_ref: str | None = None
    global_disable: bool = False
    disabled_tools: list[str] | None = None
    disabled_phases: list[str] | None = None


OperatorType = Literal["recon", "vuln_analysis", "exploitation", "reporting"]
VulnerabilityCategory = Literal[
    "injection", "xss", "auth", "authz", "ssrf", "general",
    "network", "service", "cloud", "binary",
]


class SecurityOperator(ABC):
    """Base class for all security testing operators.

    Each operator corresponds to one or more operator roles
    (recon, vuln-analysis, exploitation, reporting) and wraps the
    associated prompt templates. The kernel dispatches AttackManifests
    to operators and collects AttackProofs.

    Subclasses must implement:
    - execute: Run the operator against a target and return an AttackProof.
    - health_check: Verify the operator is operational.
    - estimate_cost: Estimate tokens/cost for an execution.

    Subclasses must also set:
    - name: Unique operator identifier.
    - operator_type: One of recon, vuln_analysis, exploitation, reporting.
    - vulnerability_category: The vuln domain this operator covers.
    - prompt_templates: Paths to the prompt template files used.
    """

    name: str
    prompt_templates: list[str]

    @property
    @abstractmethod
    def operator_type(self) -> OperatorType:
        """The phase this operator belongs to."""
        ...

    @property
    @abstractmethod
    def vulnerability_category(self) -> VulnerabilityCategory:
        """The vulnerability domain this operator covers."""
        ...

    @abstractmethod
    async def execute(self, manifest: AttackManifest) -> AttackProof:
        """Execute the operator against a target.

        Args:
            manifest: Attack manifest with target details and scope.

        Returns:
            AttackProof with findings, evidence, and exploitation results.
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify the operator is operational.

        Returns:
            True if the operator's dependencies are available.
        """
        ...

    @abstractmethod
    def estimate_cost(self, manifest: AttackManifest) -> CostEstimate:
        """Estimate the cost of executing this operator.

        Args:
            manifest: Attack manifest.

        Returns:
            Cost estimate including tokens and USD.
        """
        ...
