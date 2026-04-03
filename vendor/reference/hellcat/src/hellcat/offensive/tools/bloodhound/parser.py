"""Parser for BloodHound CE API responses."""
from __future__ import annotations

from typing import Any

from hellcat.offensive.tools.bloodhound.models import AttackPath, IdentityNode


class BloodHoundParser:
    """Parse BloodHound CE API responses into typed models."""

    @staticmethod
    def parse_attack_paths(data: list[dict[str, Any]]) -> list[AttackPath]:
        """Parse attack path API response."""
        paths: list[AttackPath] = []
        for item in data:
            nodes_data = item.get("nodes", [])
            nodes = [BloodHoundParser._parse_node(n) for n in nodes_data]
            source = nodes[0] if nodes else IdentityNode(
                object_id="", name="unknown", node_type="Unknown",
            )
            target = nodes[-1] if len(nodes) > 1 else source
            paths.append(AttackPath(
                source=source,
                target=target,
                path_nodes=nodes,
                relationships=item.get("relationships", []),
                risk_score=item.get("risk_score", 0.0),
            ))
        return paths

    @staticmethod
    def _parse_node(data: dict[str, Any]) -> IdentityNode:
        """Parse a single node from BloodHound response."""
        return IdentityNode(
            object_id=data.get("objectid", data.get("id", "")),
            name=data.get("name", data.get("label", "")),
            node_type=data.get("type", data.get("kind", "Unknown")),
            domain=data.get("domain", ""),
            enabled=data.get("enabled", True),
            properties=data.get("props", data.get("properties", {})),
        )

    @staticmethod
    def parse_domain_info(data: dict[str, Any]) -> dict[str, Any]:
        """Parse domain info response."""
        return {
            "name": data.get("name", ""),
            "domain_sid": data.get("domainsid", ""),
            "functional_level": data.get("functionallevel", ""),
            "users": data.get("users", 0),
            "groups": data.get("groups", 0),
            "computers": data.get("computers", 0),
            "ous": data.get("ous", 0),
        }
