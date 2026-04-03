"""
Service Fingerprinting - Identify services and technologies.

Runs httpx for HTTP probing and technology detection, populating SERVICE
and TECHNOLOGY nodes with RUNS_SERVICE and USES_TECH edges.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from hellcat.offensive.target_graph.models import EdgeType
from hellcat.offensive.tools.parsers import HttpxParser

if TYPE_CHECKING:
    from hellcat.offensive.target_graph.graph import TargetGraph
    from hellcat.offensive.tools.registry import ToolRegistry

logger = structlog.get_logger()


def run_service_fingerprint(
    target_domain: str,
    graph: TargetGraph,
    registry: ToolRegistry,
    timeout: int = 120,
) -> int:
    """Fingerprint services on discovered ports.

    Runs httpx to detect web services and technologies, then populates
    SERVICE and TECHNOLOGY nodes.

    Args:
        target_domain: Base domain for context.
        graph: TargetGraph to populate.
        registry: ToolRegistry with available tools.
        timeout: Tool execution timeout in seconds.

    Returns:
        Number of nodes added to the graph.
    """
    nodes_added = 0

    httpx = registry.get_tool("httpx")
    if not httpx or not httpx.available:
        logger.info("recon.service_fp.httpx_unavailable")
        return 0

    # Build probe targets: ip:port for each host's open ports
    hosts = graph.get_hosts()
    targets: list[tuple[str, str, int]] = []  # (host_id, ip, port)

    for host in hosts:
        host_id = host["id"]
        ip = host["ip"]
        ports = graph.get_ports_for_host(host_id)
        for port in ports:
            targets.append((host_id, ip, port["port_number"]))

    if not targets:
        logger.info("recon.service_fp.no_targets", domain=target_domain)
        return 0

    # Probe each target with httpx
    for host_id, ip, port_number in targets:
        url = f"http://{ip}:{port_number}"
        try:
            exit_code, stdout, stderr = registry.run_tool(
                "httpx",
                {"-j": "", "-silent": "", "-td": ""},
                target=url,
                timeout=timeout,
            )
            if exit_code == 0 and stdout.strip():
                parsed = HttpxParser.parse(stdout)
                for entry in parsed:
                    nodes_added += _ingest_httpx_entry(
                        entry, host_id, graph,
                    )
        except Exception as exc:
            logger.warning(
                "recon.service_fp.httpx_error",
                ip=ip, port=port_number, error=str(exc),
            )

    logger.info(
        "recon.service_fp.complete",
        domain=target_domain,
        targets_probed=len(targets),
        nodes_added=nodes_added,
    )
    return nodes_added


def _ingest_httpx_entry(
    entry: dict[str, Any],
    host_id: str,
    graph: TargetGraph,
) -> int:
    """Ingest a single httpx result into the graph. Returns count of nodes added."""
    nodes_added = 0

    # Look up the port node for this host
    port_number = entry.get("port", 0)
    port_id = None
    if port_number:
        ports = graph.get_ports_for_host(host_id)
        for p in ports:
            if p["port_number"] == port_number:
                port_id = p["id"]
                break

    server = entry.get("server", "")
    if server or entry.get("status_code"):
        svc_node = graph.add_service(
            name=server or "http",
            version=entry.get("content_type", ""),
            product=server,
        )
        nodes_added += 1

        if port_id:
            graph.add_edge(
                source_id=port_id,
                target_id=svc_node.id,
                edge_type=EdgeType.RUNS_SERVICE,
            )

    for tech in entry.get("technologies", []):
        tech_name = tech if isinstance(tech, str) else tech.get("name", "")
        tech_version = "" if isinstance(tech, str) else tech.get("version", "")
        if tech_name:
            tech_node = graph.add_technology(
                name=tech_name,
                version=tech_version,
                category="web",
            )
            nodes_added += 1
            graph.add_edge(
                source_id=host_id,
                target_id=tech_node.id,
                edge_type=EdgeType.USES_TECH,
            )

    return nodes_added
