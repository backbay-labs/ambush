"""Runtime gate enforcement for vendor integration adapters."""
from __future__ import annotations

from dataclasses import dataclass, field

import structlog

from hellcat.core.integrations.base import IntegrationAdapter
from hellcat.core.integrations.tenant_validation import TenantValidationRegistry

logger = structlog.get_logger()


@dataclass
class GateResult:
    """Outcome of an integration gate check."""

    allowed: bool
    missing_claims: list[str] = field(default_factory=list)
    expired_claims: list[str] = field(default_factory=list)
    message: str = ""


class IntegrationGate:
    """Check tenant-validation claims before adapter execution."""

    def __init__(self, registry: TenantValidationRegistry) -> None:
        self.registry = registry

    def check(self, adapter: IntegrationAdapter) -> GateResult:
        """Verify all required claims for *adapter* are validated."""
        if not adapter.required_claims:
            return GateResult(allowed=True, message="No claims required.")

        missing = self.registry.get_missing_claims(adapter.required_claims)
        expired = self.registry.get_expired_claims(adapter.required_claims)

        if missing or expired:
            parts: list[str] = []
            if missing:
                parts.append(f"missing/invalid claims: {missing}")
            if expired:
                parts.append(f"expired claims: {expired}")
            detail = "; ".join(parts)
            msg = (
                f"Blocked: {detail}. "
                f"See config/tenant_validation/{self.registry.tenant_id}.yaml "
                f"for the relevant checklist."
            )
            logger.warning(
                "integration_gate.denied",
                adapter=adapter.platform,
                missing=missing,
                expired=expired,
            )
            return GateResult(
                allowed=False,
                missing_claims=missing,
                expired_claims=expired,
                message=msg,
            )

        logger.info(
            "integration_gate.allowed",
            adapter=adapter.platform,
            claims=adapter.required_claims,
        )
        return GateResult(allowed=True, message="All claims validated.")
