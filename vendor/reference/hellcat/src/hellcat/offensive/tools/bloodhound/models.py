"""Data models for BloodHound CE integration."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IdentityNode:
    """An identity principal (user, group, computer, OU)."""

    object_id: str
    name: str
    node_type: str  # "User", "Group", "Computer", "OU", "GPO", "Domain"
    domain: str = ""
    enabled: bool = True
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustRelationship:
    """A trust relationship between domains."""

    source_domain: str
    target_domain: str
    trust_type: str  # "ParentChild", "External", "Forest", "Shortcut"
    trust_direction: str  # "Inbound", "Outbound", "Bidirectional"
    is_transitive: bool = False


@dataclass
class AttackPath:
    """An attack path from source to target identity."""

    source: IdentityNode
    target: IdentityNode
    path_nodes: list[IdentityNode] = field(default_factory=list)
    relationships: list[str] = field(default_factory=list)
    risk_score: float = 0.0
