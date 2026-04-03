"""
TargetGraph - SQLite-backed attack surface graph.

Follows the TransitionDB pattern: raw sqlite3, row_factory=sqlite3.Row,
idempotent schema init, json serialization for metadata.
"""

from __future__ import annotations

import json
import sqlite3
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hellcat.offensive.target_graph.models import (
    VALID_TRANSITIONS,
    AccessLevel,
    AccessLevelNode,
    AttackStatus,
    CertificateNode,
    CloudResourceNode,
    CredentialNode,
    CredentialType,
    DefenseNode,
    DefenseType,
    EdgeType,
    EndpointNode,
    GraphEdge,
    HostNode,
    IamPrincipalNode,
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
from hellcat.offensive.target_graph.schema import SCHEMA_SQL


class InvalidTransitionError(Exception):
    """Raised when a status transition violates the state machine."""

    def __init__(self, node_id: str, from_status: AttackStatus, to_status: AttackStatus) -> None:
        self.node_id = node_id
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(
            f"Invalid transition for {node_id}: {from_status.value} -> {to_status.value}"
        )


_NODE_TABLE: dict[NodeType, str] = {
    NodeType.TARGET: "targets",
    NodeType.VULNERABILITY: "vulnerabilities",
    NodeType.CREDENTIAL: "credentials",
    NodeType.ACCESS_LEVEL: "access_levels",
    NodeType.DEFENSE: "defenses",
    NodeType.SUBDOMAIN: "subdomains",
    NodeType.HOST: "hosts",
    NodeType.PORT: "ports",
    NodeType.SERVICE: "services",
    NodeType.ENDPOINT: "endpoints",
    NodeType.TECHNOLOGY: "technologies",
    NodeType.CERTIFICATE: "certificates",
    NodeType.SESSION: "sessions",
    NodeType.IAM_PRINCIPAL: "iam_principals",
    NodeType.CLOUD_RESOURCE: "cloud_resources",
}

# Columns per table (excluding id, status, discovered_at, metadata_json which are shared)
_NODE_COLUMNS: dict[NodeType, tuple[str, ...]] = {
    NodeType.TARGET: ("url", "method", "tech_stack", "description"),
    NodeType.VULNERABILITY: (
        "vuln_type", "severity", "confidence", "cvss",
        "description", "source_location", "witness_payload",
    ),
    NodeType.CREDENTIAL: ("username", "credential_type", "source", "access_level"),
    NodeType.ACCESS_LEVEL: ("level", "scope", "obtained_via"),
    NodeType.DEFENSE: ("defense_type", "strength", "observed_behavior"),
    NodeType.SUBDOMAIN: ("hostname", "resolved_ips", "source"),
    NodeType.HOST: ("ip", "hostname", "os_guess", "is_cdn"),
    NodeType.PORT: ("port_number", "protocol", "state", "service_name", "service_version"),
    NodeType.SERVICE: ("name", "version", "product", "banner", "cpe"),
    NodeType.ENDPOINT: ("url", "method", "auth_required", "parameters", "content_type"),
    NodeType.TECHNOLOGY: ("name", "version", "category"),
    NodeType.CERTIFICATE: ("subject", "issuer", "valid_from", "valid_to", "san_list"),
    NodeType.SESSION: ("session_type", "session_id", "target_host", "via_exploit"),
    NodeType.IAM_PRINCIPAL: ("name", "principal_type", "domain", "enabled"),
    NodeType.CLOUD_RESOURCE: ("resource_id", "resource_type", "provider", "region"),
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class TargetGraph:
    """
    SQLite-backed directed graph for tracking attack surfaces during
    authorized red teaming engagements.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        self.conn.close()

    def _init_schema(self) -> None:
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    # ==================================================================
    # Node insertion
    # ==================================================================

    def add_target(
        self,
        url: str,
        method: str = "GET",
        tech_stack: str = "",
        description: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TargetNode:
        node = TargetNode(
            url=url,
            method=method,
            tech_stack=tech_stack,
            description=description,
            status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO targets
                (id, url, method, tech_stack, description, status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.url, node.method, node.tech_stack,
             node.description, node.status.value, node.discovered_at, node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_vulnerability(
        self,
        vuln_type: str,
        severity: Severity = Severity.MEDIUM,
        confidence: float = 0.5,
        cvss: float | None = None,
        description: str = "",
        source_location: str = "",
        witness_payload: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> VulnerabilityNode:
        node = VulnerabilityNode(
            vuln_type=vuln_type,
            severity=severity,
            confidence=confidence,
            cvss=cvss,
            description=description,
            source_location=source_location,
            witness_payload=witness_payload,
            status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO vulnerabilities
                (id, vuln_type, severity, confidence, cvss, description,
                 source_location, witness_payload, status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.vuln_type, node.severity.value, node.confidence,
             node.cvss, node.description, node.source_location,
             node.witness_payload, node.status.value, node.discovered_at,
             node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_credential(
        self,
        username: str,
        credential_type: CredentialType,
        source: str = "",
        access_level: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CredentialNode:
        node = CredentialNode(
            username=username,
            credential_type=credential_type,
            source=source,
            access_level=access_level,
            status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO credentials
                (id, username, credential_type, source, access_level,
                 status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.username, node.credential_type.value, node.source,
             node.access_level, node.status.value, node.discovered_at,
             node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_access_level(
        self,
        level: AccessLevel,
        scope: str = "",
        obtained_via: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AccessLevelNode:
        node = AccessLevelNode(
            level=level,
            scope=scope,
            obtained_via=obtained_via,
            status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO access_levels
                (id, level, scope, obtained_via, status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.level.value, node.scope, node.obtained_via,
             node.status.value, node.discovered_at, node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_defense(
        self,
        defense_type: DefenseType,
        strength: str = "unknown",
        observed_behavior: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DefenseNode:
        node = DefenseNode(
            defense_type=defense_type,
            strength=strength,
            observed_behavior=observed_behavior,
            status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO defenses
                (id, defense_type, strength, observed_behavior,
                 status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.defense_type.value, node.strength,
             node.observed_behavior, node.status.value, node.discovered_at,
             node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_subdomain(
        self,
        hostname: str,
        resolved_ips: str = "",
        source: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SubdomainNode:
        node = SubdomainNode(
            hostname=hostname, resolved_ips=resolved_ips, source=source, status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO subdomains
                (id, hostname, resolved_ips, source, status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.hostname, node.resolved_ips, node.source,
             node.status.value, node.discovered_at, node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_host(
        self,
        ip: str,
        hostname: str = "",
        os_guess: str = "",
        is_cdn: bool = False,
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> HostNode:
        node = HostNode(
            ip=ip, hostname=hostname, os_guess=os_guess, is_cdn=is_cdn, status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO hosts
                (id, ip, hostname, os_guess, is_cdn, status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.ip, node.hostname, node.os_guess, int(node.is_cdn),
             node.status.value, node.discovered_at, node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_port(
        self,
        port_number: int,
        protocol: str = "tcp",
        state: str = "open",
        service_name: str = "",
        service_version: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> PortNode:
        node = PortNode(
            port_number=port_number, protocol=protocol, state=state,
            service_name=service_name, service_version=service_version, status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO ports
                (id, port_number, protocol, state, service_name, service_version,
                 status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.port_number, node.protocol, node.state,
             node.service_name, node.service_version,
             node.status.value, node.discovered_at, node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_service(
        self,
        name: str,
        version: str = "",
        product: str = "",
        banner: str = "",
        cpe: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ServiceNode:
        node = ServiceNode(
            name=name, version=version, product=product,
            banner=banner, cpe=cpe, status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO services
                (id, name, version, product, banner, cpe,
                 status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.name, node.version, node.product,
             node.banner, node.cpe,
             node.status.value, node.discovered_at, node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_endpoint(
        self,
        url: str,
        method: str = "GET",
        auth_required: bool = False,
        parameters: str = "",
        content_type: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EndpointNode:
        node = EndpointNode(
            url=url, method=method, auth_required=auth_required,
            parameters=parameters, content_type=content_type, status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO endpoints
                (id, url, method, auth_required, parameters, content_type,
                 status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.url, node.method, int(node.auth_required),
             node.parameters, node.content_type,
             node.status.value, node.discovered_at, node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_technology(
        self,
        name: str,
        version: str = "",
        category: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TechnologyNode:
        node = TechnologyNode(
            name=name, version=version, category=category, status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO technologies
                (id, name, version, category, status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.name, node.version, node.category,
             node.status.value, node.discovered_at, node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_certificate(
        self,
        subject: str,
        issuer: str = "",
        valid_from: str = "",
        valid_to: str = "",
        san_list: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CertificateNode:
        node = CertificateNode(
            subject=subject, issuer=issuer, valid_from=valid_from,
            valid_to=valid_to, san_list=san_list, status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO certificates
                (id, subject, issuer, valid_from, valid_to, san_list,
                 status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.subject, node.issuer, node.valid_from,
             node.valid_to, node.san_list,
             node.status.value, node.discovered_at, node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_session(
        self,
        session_type: str,
        session_id: str = "",
        target_host: str = "",
        via_exploit: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SessionNode:
        node = SessionNode(
            session_type=session_type, session_id=session_id,
            target_host=target_host, via_exploit=via_exploit, status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO sessions
                (id, session_type, session_id, target_host, via_exploit,
                 status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.session_type, node.session_id,
             node.target_host, node.via_exploit,
             node.status.value, node.discovered_at, node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_iam_principal(
        self,
        name: str,
        principal_type: str = "",
        domain: str = "",
        enabled: bool = True,
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IamPrincipalNode:
        node = IamPrincipalNode(
            name=name, principal_type=principal_type,
            domain=domain, enabled=enabled, status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO iam_principals
                (id, name, principal_type, domain, enabled,
                 status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.name, node.principal_type,
             node.domain, int(node.enabled),
             node.status.value, node.discovered_at, node.metadata_json),
        )
        self.conn.commit()
        return node

    def add_cloud_resource(
        self,
        resource_id: str,
        resource_type: str = "",
        provider: str = "",
        region: str = "",
        status: AttackStatus = AttackStatus.DISCOVERED,
        node_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CloudResourceNode:
        node = CloudResourceNode(
            resource_id=resource_id, resource_type=resource_type,
            provider=provider, region=region, status=status,
        )
        if node_id:
            node.id = node_id
        if metadata:
            node.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO cloud_resources
                (id, resource_id, resource_type, provider, region,
                 status, discovered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node.id, node.resource_id, node.resource_type,
             node.provider, node.region,
             node.status.value, node.discovered_at, node.metadata_json),
        )
        self.conn.commit()
        return node

    # ==================================================================
    # Edges
    # ==================================================================

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        metadata: dict[str, Any] | None = None,
    ) -> GraphEdge:
        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
        )
        if metadata:
            edge.metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO edges
                (id, source_id, target_id, edge_type, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (edge.id, edge.source_id, edge.target_id,
             edge.edge_type.value, edge.metadata_json, edge.created_at),
        )
        self.conn.commit()
        return edge

    def get_edges_from(self, node_id: str, edge_type: EdgeType | None = None) -> list[dict[str, Any]]:
        if edge_type:
            rows = self.conn.execute(
                "SELECT * FROM edges WHERE source_id = ? AND edge_type = ?",
                (node_id, edge_type.value),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM edges WHERE source_id = ?", (node_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_edges_to(self, node_id: str, edge_type: EdgeType | None = None) -> list[dict[str, Any]]:
        if edge_type:
            rows = self.conn.execute(
                "SELECT * FROM edges WHERE target_id = ? AND edge_type = ?",
                (node_id, edge_type.value),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM edges WHERE target_id = ?", (node_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ==================================================================
    # Status state machine
    # ==================================================================

    def update_status(self, node_id: str, new_status: AttackStatus) -> bool:
        """
        Update a node's status with state machine validation.

        Searches all node tables for the given ID, validates the transition
        against VALID_TRANSITIONS, writes the change, and logs to status_history.

        Returns True if the update was applied.

        Raises:
            InvalidTransitionError: If the transition is not allowed.
            KeyError: If the node_id is not found in any table.
        """
        for node_type, table in _NODE_TABLE.items():
            row = self.conn.execute(
                f"SELECT status FROM {table} WHERE id = ?", (node_id,),  # noqa: S608
            ).fetchone()
            if row is None:
                continue

            current = AttackStatus(row["status"])
            allowed = VALID_TRANSITIONS.get(current, set())
            if new_status not in allowed:
                raise InvalidTransitionError(node_id, current, new_status)

            now = _utc_now()
            self.conn.execute(
                f"UPDATE {table} SET status = ? WHERE id = ?",  # noqa: S608
                (new_status.value, node_id),
            )
            self.conn.execute(
                """
                INSERT INTO status_history
                    (node_id, node_type, from_status, to_status, changed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (node_id, node_type.value, current.value, new_status.value, now),
            )
            self.conn.commit()
            return True

        raise KeyError(f"Node {node_id} not found in any table")

    # ==================================================================
    # Query helpers
    # ==================================================================

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        """Look up a node by ID across all tables. Returns dict or None."""
        for node_type, table in _NODE_TABLE.items():
            row = self.conn.execute(
                f"SELECT * FROM {table} WHERE id = ?", (node_id,),  # noqa: S608
            ).fetchone()
            if row is not None:
                result = dict(row)
                result["node_type"] = node_type.value
                return result
        return None

    def get_ready_attacks(self) -> list[dict[str, Any]]:
        """
        Return nodes in 'analyzed' status that have no incoming 'blocks' edges
        from defenses that are not yet bypassed (i.e., no active blockers).

        These represent attack paths that are ready to attempt.
        """
        results: list[dict[str, Any]] = []

        for node_type, table in _NODE_TABLE.items():
            rows = self.conn.execute(
                f"SELECT * FROM {table} WHERE status = ?",  # noqa: S608
                (AttackStatus.ANALYZED.value,),
            ).fetchall()

            for row in rows:
                node = dict(row)
                node["node_type"] = node_type.value
                node_id = node["id"]

                # Check for active blocking edges
                blockers = self.conn.execute(
                    """
                    SELECT e.source_id FROM edges e
                    WHERE e.target_id = ? AND e.edge_type = ?
                    """,
                    (node_id, EdgeType.BLOCKS.value),
                ).fetchall()

                is_blocked = False
                for blocker in blockers:
                    # Check if this blocker has been bypassed
                    bypass = self.conn.execute(
                        """
                        SELECT 1 FROM edges
                        WHERE target_id = ? AND edge_type = ?
                        LIMIT 1
                        """,
                        (blocker["source_id"], EdgeType.BYPASSED_BY.value),
                    ).fetchone()
                    if bypass is None:
                        is_blocked = True
                        break

                if not is_blocked:
                    results.append(node)

        return results

    def get_exploit_chains(self, from_node: str) -> list[list[str]]:
        """
        Traverse 'chains_to' edges from the given node using BFS.

        Returns all paths (as lists of node IDs) reachable via chains_to.
        """
        chains: list[list[str]] = []
        queue: deque[list[str]] = deque([[from_node]])
        visited: set[str] = {from_node}

        while queue:
            path = queue.popleft()
            current = path[-1]

            next_edges = self.conn.execute(
                "SELECT target_id FROM edges WHERE source_id = ? AND edge_type = ?",
                (current, EdgeType.CHAINS_TO.value),
            ).fetchall()

            if not next_edges:
                # Only record paths longer than the starting node
                if len(path) > 1:
                    chains.append(path)
                continue

            for edge in next_edges:
                next_id = edge["target_id"]
                if next_id not in visited:
                    visited.add(next_id)
                    new_path = path + [next_id]
                    queue.append(new_path)

        return chains

    def get_critical_path(self, objective: str) -> list[str] | None:
        """
        Find the shortest path from any node with 'exploited' status to the
        objective node, traversing 'chains_to', 'enables', and 'requires' edges.

        Returns the path as a list of node IDs, or None if no path exists.
        """
        # Collect all exploited nodes as potential starting points
        start_nodes: list[str] = []
        for table in _NODE_TABLE.values():
            rows = self.conn.execute(
                f"SELECT id FROM {table} WHERE status = ?",  # noqa: S608
                (AttackStatus.EXPLOITED.value,),
            ).fetchall()
            start_nodes.extend(r["id"] for r in rows)

        if not start_nodes:
            return None

        # BFS from all start nodes simultaneously
        traversal_types = (EdgeType.CHAINS_TO.value, EdgeType.ENABLES.value, EdgeType.REQUIRES.value)
        placeholders = ",".join("?" for _ in traversal_types)

        visited: dict[str, str | None] = dict.fromkeys(start_nodes)
        queue: deque[str] = deque(start_nodes)

        while queue:
            current = queue.popleft()
            if current == objective:
                # Reconstruct path
                path = [current]
                while visited[path[-1]] is not None:
                    path.append(visited[path[-1]])  # type: ignore[arg-type]
                path.reverse()
                return path

            rows = self.conn.execute(
                f"SELECT target_id FROM edges WHERE source_id = ? AND edge_type IN ({placeholders})",
                (current, *traversal_types),
            ).fetchall()

            for row in rows:
                nid = row["target_id"]
                if nid not in visited:
                    visited[nid] = current
                    queue.append(nid)

        return None

    # ==================================================================
    # Credential-aware queries
    # ==================================================================

    def get_unlocked_targets(self, credential_id: str) -> list[dict[str, Any]]:
        """
        Find targets accessible with a given credential by following
        ENABLES edges from the credential node.

        Returns target/vulnerability nodes that are reachable via the
        credential's ENABLES edges.
        """
        results: list[dict[str, Any]] = []
        # Follow ENABLES edges from this credential
        edges = self.conn.execute(
            "SELECT target_id FROM edges WHERE source_id = ? AND edge_type = ?",
            (credential_id, EdgeType.ENABLES.value),
        ).fetchall()

        for edge in edges:
            node = self.get_node(edge["target_id"])
            if node is not None:
                results.append(node)

        # Also follow indirect paths: credential -> ENABLES -> target -> EXPOSES -> vuln
        for edge in edges:
            target_id = edge["target_id"]
            indirect = self.conn.execute(
                "SELECT target_id FROM edges WHERE source_id = ? AND edge_type = ?",
                (target_id, EdgeType.EXPOSES.value),
            ).fetchall()
            for ind_edge in indirect:
                node = self.get_node(ind_edge["target_id"])
                if node is not None and node["id"] not in {r["id"] for r in results}:
                    results.append(node)

        return results

    def get_unattacked_paths(self) -> list[dict[str, Any]]:
        """
        Find nodes in DISCOVERED or ANALYZED status that have not yet
        been attempted. These represent potential attack paths that
        could be enabled by newly discovered credentials.
        """
        results: list[dict[str, Any]] = []
        target_statuses = (
            AttackStatus.DISCOVERED.value,
            AttackStatus.ANALYZED.value,
        )

        for node_type, table in _NODE_TABLE.items():
            rows = self.conn.execute(
                f"SELECT * FROM {table} WHERE status IN (?, ?)",  # noqa: S608
                target_statuses,
            ).fetchall()
            for row in rows:
                node = dict(row)
                node["node_type"] = node_type.value
                results.append(node)

        return results

    def get_subdomains(self) -> list[dict[str, Any]]:
        """Return all subdomain nodes."""
        rows = self.conn.execute("SELECT * FROM subdomains").fetchall()
        results = []
        for row in rows:
            node = dict(row)
            node["node_type"] = NodeType.SUBDOMAIN.value
            results.append(node)
        return results

    def get_hosts(self) -> list[dict[str, Any]]:
        """Return all host nodes."""
        rows = self.conn.execute("SELECT * FROM hosts").fetchall()
        results = []
        for row in rows:
            node = dict(row)
            node["node_type"] = NodeType.HOST.value
            results.append(node)
        return results

    def get_ports_for_host(self, host_id: str) -> list[dict[str, Any]]:
        """Return port nodes linked to a host via HAS_PORT edges."""
        rows = self.conn.execute(
            """
            SELECT p.* FROM ports p
            JOIN edges e ON e.target_id = p.id
            WHERE e.source_id = ? AND e.edge_type = ?
            """,
            (host_id, EdgeType.HAS_PORT.value),
        ).fetchall()
        results = []
        for row in rows:
            node = dict(row)
            node["node_type"] = NodeType.PORT.value
            results.append(node)
        return results

    def get_services_for_host(self, host_id: str) -> list[dict[str, Any]]:
        """Return service nodes reachable from a host via HAS_PORT -> RUNS_SERVICE."""
        rows = self.conn.execute(
            """
            SELECT s.* FROM services s
            JOIN edges e2 ON e2.target_id = s.id AND e2.edge_type = ?
            JOIN edges e1 ON e1.target_id = e2.source_id AND e1.edge_type = ?
            WHERE e1.source_id = ?
            """,
            (EdgeType.RUNS_SERVICE.value, EdgeType.HAS_PORT.value, host_id),
        ).fetchall()
        results = []
        for row in rows:
            node = dict(row)
            node["node_type"] = NodeType.SERVICE.value
            results.append(node)
        return results

    def get_endpoints_for_service(self, service_id: str) -> list[dict[str, Any]]:
        """Return endpoint nodes linked to a service via HAS_ENDPOINT edges."""
        rows = self.conn.execute(
            """
            SELECT ep.* FROM endpoints ep
            JOIN edges e ON e.target_id = ep.id
            WHERE e.source_id = ? AND e.edge_type = ?
            """,
            (service_id, EdgeType.HAS_ENDPOINT.value),
        ).fetchall()
        results = []
        for row in rows:
            node = dict(row)
            node["node_type"] = NodeType.ENDPOINT.value
            results.append(node)
        return results

    def get_credentials_since(self, since_iso: str) -> list[dict[str, Any]]:
        """
        Return credential nodes discovered after the given ISO timestamp.
        """
        rows = self.conn.execute(
            "SELECT * FROM credentials WHERE discovered_at > ?",
            (since_iso,),
        ).fetchall()
        results = []
        for row in rows:
            node = dict(row)
            node["node_type"] = NodeType.CREDENTIAL.value
            results.append(node)
        return results

    # ==================================================================
    # Node promotion
    # ==================================================================

    def promote_discovered_nodes(self) -> int:
        """Promote DISCOVERED vulnerability nodes with metadata to ANALYZED.

        Performs DISCOVERED -> RECOND -> ANALYZED transitions respecting
        the VALID_TRANSITIONS state machine. Only promotes nodes whose
        metadata_json is non-empty (i.e. not '{}'), indicating recon
        data has been attached.

        Returns:
            Count of nodes promoted to ANALYZED.
        """
        rows = self.conn.execute(
            "SELECT id FROM vulnerabilities WHERE status = ? AND metadata_json != '{}'",
            (AttackStatus.DISCOVERED.value,),
        ).fetchall()

        promoted = 0
        for row in rows:
            node_id = row["id"]
            try:
                self.update_status(node_id, AttackStatus.RECOND)
                self.update_status(node_id, AttackStatus.ANALYZED)
                promoted += 1
            except (InvalidTransitionError, KeyError):
                continue
        return promoted

    # ==================================================================
    # Vulnerability enrichment helpers
    # ==================================================================

    def get_vuln_scoring_metadata(self, node_id: str) -> dict[str, Any]:
        """Get typed scoring fields for a vulnerability node.

        Returns dict with canonical enrichment keys:
        epss_score, epss_percentile, cvss_v4_score, cvss_v4_vector,
        data_freshness, cve_id.  Missing keys are omitted.
        """
        row = self.conn.execute(
            "SELECT metadata_json FROM vulnerabilities WHERE id = ?", (node_id,),
        ).fetchone()
        if row is None:
            return {}
        raw = row["metadata_json"]
        try:
            meta = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}
        if not isinstance(meta, dict):
            return {}
        scoring_keys = {
            "epss_score", "epss_percentile", "cvss_v4_score",
            "cvss_v4_vector", "data_freshness", "cve_id",
        }
        return {k: v for k, v in meta.items() if k in scoring_keys}

    def update_vuln_enrichment(self, node_id: str, enrichment: dict[str, Any]) -> None:
        """Update vulnerability node with enrichment data (EPSS, CVSSv4, etc.).

        Merges enrichment keys into existing metadata_json.
        """
        row = self.conn.execute(
            "SELECT metadata_json FROM vulnerabilities WHERE id = ?", (node_id,),
        ).fetchone()
        if row is None:
            return
        raw = row["metadata_json"]
        try:
            meta = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError, ValueError):
            meta = {}
        if not isinstance(meta, dict):
            meta = {}
        meta.update(enrichment)
        new_json = json.dumps(meta, sort_keys=True, separators=(",", ":"))
        self.conn.execute(
            "UPDATE vulnerabilities SET metadata_json = ? WHERE id = ?",
            (new_json, node_id),
        )
        self.conn.commit()

    # ==================================================================
    # Stats
    # ==================================================================

    def get_stats(self) -> dict[str, Any]:
        """Return a summary of the graph state."""
        stats: dict[str, Any] = {}

        for node_type, table in _NODE_TABLE.items():
            # Total count
            total = self.conn.execute(f"SELECT COUNT(*) as c FROM {table}").fetchone()["c"]  # noqa: S608

            # Status breakdown
            rows = self.conn.execute(
                f"SELECT status, COUNT(*) as c FROM {table} GROUP BY status",  # noqa: S608
            ).fetchall()
            by_status = {r["status"]: r["c"] for r in rows}

            stats[node_type.value] = {"total": total, "by_status": by_status}

        # Edge counts
        edge_total = self.conn.execute("SELECT COUNT(*) as c FROM edges").fetchone()["c"]
        edge_rows = self.conn.execute(
            "SELECT edge_type, COUNT(*) as c FROM edges GROUP BY edge_type"
        ).fetchall()
        edges_by_type = {r["edge_type"]: r["c"] for r in edge_rows}
        stats["edges"] = {"total": edge_total, "by_type": edges_by_type}

        return stats
