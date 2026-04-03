"""Attestation registry interfaces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from cyntra.trust.membrane.receipt import RunReceipt


@dataclass
class AttestationRef:
    """Reference to a published attestation."""

    registry: str
    ref_id: str
    chain_id: int | None = None
    timestamp: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class VerificationResult:
    """Result of attestation verification."""

    valid: bool
    errors: list[str]
    inclusion_proof: str | None = None
    attestation_data: dict[str, Any] | None = None


class Signer(Protocol):
    """Signer interface for attestation publishing."""

    def sign(self, payload: bytes) -> bytes:
        ...


class AttestationRegistry(Protocol):
    """Abstract interface for attestation backends."""

    async def publish(self, receipt: RunReceipt, signer: Signer) -> AttestationRef:
        ...

    async def verify(self, ref: AttestationRef) -> VerificationResult:
        ...

    async def revoke(self, ref: AttestationRef, reason: str, signer: Signer) -> bool:
        ...

    async def batch_publish(
        self, receipts: list[RunReceipt], signer: Signer
    ) -> AttestationRef:
        ...
