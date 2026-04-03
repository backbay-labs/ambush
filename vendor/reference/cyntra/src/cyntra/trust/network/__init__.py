"""
CNP Network Layer - Gossip-based trail sharing and peer discovery.

This module implements Phase 1 of the Cyntra Network Protocol:
- libp2p-based peer discovery and gossip
- Stigmergic trail propagation
- Trail storage and querying
"""

# Lazy imports to avoid loading nacl/libp2p unless needed
def __getattr__(name: str):
    if name in ("ActionType", "StateFeatures", "Trail", "TrailContext", 
                "TrailOutcome", "TrailQuery", "TrailCitation"):
        from cyntra.trust.network import schemas
        return getattr(schemas, name)
    elif name in ("CNPNode", "NodeConfig"):
        from cyntra.trust.network import node
        return getattr(node, name)
    elif name == "TrailStore":
        from cyntra.trust.network.store.trails import TrailStore
        return TrailStore
    elif name in ("LibP2PHost", "LibP2PConfig", "create_host"):
        from cyntra.trust.network import libp2p_host
        return getattr(libp2p_host, name)
    elif name in ("GossipManager", "GossipConfig"):
        from cyntra.trust.network import gossip
        return getattr(gossip, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Schemas
    "ActionType",
    "StateFeatures",
    "Trail",
    "TrailContext",
    "TrailOutcome",
    "TrailQuery",
    "TrailCitation",
    # Node
    "CNPNode",
    "NodeConfig",
    # Storage
    "TrailStore",
    # libp2p
    "LibP2PHost",
    "LibP2PConfig",
    "create_host",
    # Gossip
    "GossipManager",
    "GossipConfig",
]
