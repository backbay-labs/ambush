"""Vendor integration adapters and tenant validation gates."""

from hellcat.core.integrations.base import (
    AdapterResult,
    IntegrationAdapter,
    IntegrationDirection,
)
from hellcat.core.integrations.gate import GateResult, IntegrationGate
from hellcat.core.integrations.tenant_validation import (
    ClaimStatus,
    TenantClaim,
    TenantValidationRegistry,
)

__all__ = [
    "AdapterResult",
    "ClaimStatus",
    "GateResult",
    "IntegrationAdapter",
    "IntegrationDirection",
    "IntegrationGate",
    "TenantClaim",
    "TenantValidationRegistry",
]
