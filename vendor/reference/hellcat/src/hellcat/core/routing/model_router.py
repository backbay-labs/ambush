"""
ModelRouter - Route security operators to optimal LLM models.

Different operators benefit from different models:
  - Pre-recon (tool coordination) -> fast, cheap models (Haiku/Flash)
  - Recon (surface mapping)       -> balanced models (Sonnet)
  - Vuln analysis (taint tracing) -> powerful models (Opus)
  - Exploitation (multi-step)     -> powerful models (Opus)
  - Evasion retry (novel bypass)  -> powerful models (Opus)
  - Reporting (structured write)  -> balanced models (Sonnet)

The router consults a default routing table (from architecture-next.md Section 4.4)
and supports per-engagement overrides via configuration.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

import structlog

logger = structlog.get_logger()


class ModelProvider(str, enum.Enum):
    """Supported LLM providers."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    LOCAL = "local"


@dataclass(frozen=True)
class ModelConfig:
    """Configuration for a specific LLM model."""

    model_id: str
    provider: ModelProvider = ModelProvider.ANTHROPIC
    max_tokens: int = 16384
    temperature: float = 0.0
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0

    def estimate_cost(self, input_tokens: int, output_tokens: int = 0) -> float:
        input_cost = (input_tokens / 1000) * self.cost_per_1k_input
        output_cost = (output_tokens / 1000) * self.cost_per_1k_output
        return input_cost + output_cost


# Pre-built model configs for common models
HAIKU = ModelConfig(
    model_id="claude-haiku-4-5-20251001",
    provider=ModelProvider.ANTHROPIC,
    max_tokens=8192,
    temperature=0.0,
    cost_per_1k_input=0.0008,
    cost_per_1k_output=0.004,
)

SONNET = ModelConfig(
    model_id="claude-sonnet-4-5-20250929",
    provider=ModelProvider.ANTHROPIC,
    max_tokens=16384,
    temperature=0.0,
    cost_per_1k_input=0.003,
    cost_per_1k_output=0.015,
)

OPUS = ModelConfig(
    model_id="claude-opus-4-6",
    provider=ModelProvider.ANTHROPIC,
    max_tokens=16384,
    temperature=0.0,
    cost_per_1k_input=0.015,
    cost_per_1k_output=0.075,
)


# Default routing table: (operator_name, phase) -> ModelConfig
# From architecture-next.md Section 4.4
_DEFAULT_PHASE_ROUTES: dict[str, ModelConfig] = {
    "pre-recon": HAIKU,
    "recon": SONNET,
    "vuln_analysis": OPUS,
    "exploitation": OPUS,
    "evasion_retry": OPUS,
    "reporting": SONNET,
}

# Operator-specific overrides (keyed by registry operator name)
_DEFAULT_OPERATOR_ROUTES: dict[str, ModelConfig] = {
    # Recon operators use Sonnet (balanced)
    "recon": SONNET,
    # Vuln analysis operators use Opus (deep reasoning)
    "injection-vuln": OPUS,
    "xss-vuln": OPUS,
    "auth-vuln": OPUS,
    "authz-vuln": OPUS,
    "ssrf-vuln": OPUS,
    # Exploitation operators use Opus (multi-step reasoning)
    "injection-exploit": OPUS,
    "auth-exploit": OPUS,
    # Report operator uses Sonnet (structured writing)
    "report": SONNET,
}


class ModelRouter:
    """
    Routes security operators to the optimal LLM model.

    Resolution order:
    1. Per-engagement overrides (from EngagementConfig)
    2. Operator-specific defaults (by operator name)
    3. Phase-based defaults (by execution phase)
    4. Fallback to SONNET
    """

    def __init__(
        self,
        phase_routes: dict[str, ModelConfig] | None = None,
        operator_routes: dict[str, ModelConfig] | None = None,
    ) -> None:
        self._phase_routes = dict(phase_routes or _DEFAULT_PHASE_ROUTES)
        self._operator_routes = dict(operator_routes or _DEFAULT_OPERATOR_ROUTES)
        self._overrides: dict[str, ModelConfig] = {}

    def get_model(
        self,
        operator_name: str,
        phase: str = "",
    ) -> ModelConfig:
        """
        Get the optimal model for an operator+phase combination.

        Args:
            operator_name: Registry name of the operator (e.g. "injection-vuln").
            phase: Execution phase (e.g. "vuln_analysis", "exploitation").

        Returns:
            ModelConfig for the selected model.
        """
        # 1. Check per-engagement overrides
        if operator_name in self._overrides:
            return self._overrides[operator_name]

        # 2. Check operator-specific defaults
        if operator_name in self._operator_routes:
            return self._operator_routes[operator_name]

        # 3. Check phase-based defaults
        if phase in self._phase_routes:
            return self._phase_routes[phase]

        # 4. Fallback
        return SONNET

    def override(self, operator_name: str, model_config: ModelConfig) -> None:
        self._overrides[operator_name] = model_config
        logger.info(
            "routing.model_override",
            operator=operator_name,
            model=model_config.model_id,
            provider=model_config.provider.value,
        )

    def clear_overrides(self) -> None:
        self._overrides.clear()

    def estimate_cost(
        self,
        operator_name: str,
        phase: str = "",
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> float:
        model = self.get_model(operator_name, phase)
        return model.estimate_cost(input_tokens, output_tokens)

    def get_routing_table(self) -> dict[str, dict[str, str]]:
        table: dict[str, dict[str, str]] = {}

        for name, config in self._operator_routes.items():
            table[name] = {
                "model_id": config.model_id,
                "provider": config.provider.value,
                "source": "operator_default",
            }

        for name, config in self._overrides.items():
            table[name] = {
                "model_id": config.model_id,
                "provider": config.provider.value,
                "source": "override",
            }

        return table
