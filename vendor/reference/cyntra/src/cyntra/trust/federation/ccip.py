"""CCIP federation client stubs."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from cyntra.trust.federation.anchors import AnchorBatch


class CCIPClientError(RuntimeError):
    """Raised when CCIP client is not configured."""


class CCIPMessageType(str, Enum):
    """Supported CCIP message types."""

    ATTESTATION_ANCHOR = "attestation_anchor"
    REVOCATION = "revocation"
    POLICY_UPDATE = "policy_update"


@dataclass
class CCIPMessage:
    """Canonical CCIP message payload."""

    message_type: CCIPMessageType
    payload: dict[str, Any]
    version: str = "1.0.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "message_type": self.message_type.value,
            "payload": self.payload,
        }


def build_anchor_message(anchor: AnchorBatch) -> CCIPMessage:
    payload = {
        "root": anchor.root,
        "count": anchor.count,
        "algorithm": anchor.algorithm,
        "leaf_hashes": anchor.leaf_hashes,
    }
    return CCIPMessage(message_type=CCIPMessageType.ATTESTATION_ANCHOR, payload=payload)


@dataclass
class CCIPClient:
    """Stub client for cross-chain attestation anchoring."""

    enabled: bool = False
    router_address: str | None = None

    def send_attestation_anchor(self, root: str, metadata: dict[str, Any]) -> str:
        if not self.enabled or not self.router_address:
            raise CCIPClientError("CCIP client not configured")
        raise NotImplementedError("CCIP send not implemented")
