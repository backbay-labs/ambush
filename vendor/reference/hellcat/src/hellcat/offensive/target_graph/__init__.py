"""
TargetGraph - Attack surface graph for Hellcat red teaming engagements.

Replaces the Beads work graph with a directed graph tracking targets,
vulnerabilities, credentials, access levels, and defenses discovered
during authorized penetration testing.

Modules:
    models  - Dataclass models for nodes, edges, and enums
    schema  - Raw SQLite schema (matches TransitionDB pattern)
    graph   - TargetGraph class with CRUD and traversal operations
"""

from hellcat.offensive.target_graph.graph import TargetGraph
from hellcat.offensive.target_graph.models import (
    AccessLevelNode,
    AttackStatus,
    CertificateNode,
    CredentialNode,
    CredentialType,
    DefenseNode,
    DefenseType,
    EdgeType,
    EndpointNode,
    GraphEdge,
    HostNode,
    NodeType,
    PortNode,
    ServiceNode,
    SessionNode,
    Severity,
    SubdomainNode,
    TargetNode,
    TechnologyNode,
    VulnerabilityNode,
)

__all__ = [
    "TargetGraph",
    "TargetNode",
    "VulnerabilityNode",
    "CredentialNode",
    "AccessLevelNode",
    "DefenseNode",
    "SubdomainNode",
    "HostNode",
    "PortNode",
    "ServiceNode",
    "EndpointNode",
    "TechnologyNode",
    "CertificateNode",
    "SessionNode",
    "GraphEdge",
    "AttackStatus",
    "EdgeType",
    "NodeType",
    "CredentialType",
    "DefenseType",
    "Severity",
]
