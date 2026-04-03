"""
Spine plane gateways (scaffolding).

Gateways bridge Spine objects across transport planes without mutating signed
envelopes. This package provides:
- Plane B (NATS) pub/sub host
- Plane A-L (libp2p) pub/sub host
- A small bridge that verifies + forwards messages between hosts
"""

from cyntra.trust.spine.gateway.bridge import SpinePlaneBridge, SpinePlaneBridgeConfig
from cyntra.trust.spine.gateway.reticulum_plane import ReticulumPlaneConfig, ReticulumPlaneHost
from cyntra.trust.spine.gateway.transport import SpinePlaneHost, SpinePlaneHostConfig

__all__ = [
    "SpinePlaneBridge",
    "SpinePlaneBridgeConfig",
    "SpinePlaneHost",
    "SpinePlaneHostConfig",
    "ReticulumPlaneConfig",
    "ReticulumPlaneHost",
]
