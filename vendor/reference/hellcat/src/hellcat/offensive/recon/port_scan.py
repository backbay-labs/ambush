"""
Port Scanning - Discover open ports on hosts.

Runs nmap or masscan against discovered hosts and populates the TargetGraph
with PORT nodes and HAS_PORT edges.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from hellcat.offensive.target_graph.models import EdgeType
from hellcat.offensive.tools.parsers import MasscanParser, NmapParser

if TYPE_CHECKING:
    from hellcat.offensive.target_graph.graph import TargetGraph
    from hellcat.offensive.tools.registry import ToolRegistry

logger = structlog.get_logger()


def run_port_scan(
    target_domain: str,
    graph: TargetGraph,
    registry: ToolRegistry,
    timeout: int = 300,
) -> int:
    """Run port scanning against all discovered hosts.

    Uses nmap (preferred) or masscan (fallback) to discover open ports.

    Args:
        target_domain: The base domain (used for logging context).
        graph: TargetGraph to populate with PORT nodes.
        registry: ToolRegistry with available tools.
        timeout: Tool execution timeout in seconds.

    Returns:
        Number of port nodes added to the graph.
    """
    hosts = graph.get_hosts()
    if not hosts:
        logger.info("recon.port_scan.no_hosts", domain=target_domain)
        return 0

    nodes_added = 0

    nmap = registry.get_tool("nmap")
    masscan = registry.get_tool("masscan")

    for host in hosts:
        ip = host["ip"]
        host_id = host["id"]

        if nmap and nmap.available:
            nodes_added += _scan_with_nmap(ip, host_id, graph, registry, timeout)
        elif masscan and masscan.available:
            nodes_added += _scan_with_masscan(ip, host_id, graph, registry, timeout)
        else:
            logger.info("recon.port_scan.no_scanner", ip=ip)

    logger.info(
        "recon.port_scan.complete",
        domain=target_domain,
        hosts_scanned=len(hosts),
        ports_added=nodes_added,
    )
    return nodes_added


def _scan_with_nmap(
    ip: str,
    host_id: str,
    graph: TargetGraph,
    registry: ToolRegistry,
    timeout: int,
) -> int:
    """Run nmap scan and ingest results."""
    nodes_added = 0
    try:
        exit_code, stdout, stderr = registry.run_tool(
            "nmap",
            {"-sV": "", "-oX": "-", "--top-ports": "1000"},
            target=ip,
            timeout=timeout,
        )
        if exit_code == 0 and stdout.strip():
            parsed = NmapParser.parse(stdout)
            for entry in parsed:
                if entry.get("type") == "port" and entry.get("state") == "open":
                    port_node = graph.add_port(
                        port_number=entry["port"],
                        protocol=entry.get("protocol", "tcp"),
                        state="open",
                        service_name=entry.get("service_name", ""),
                        service_version=entry.get("service_version", ""),
                    )
                    graph.add_edge(
                        source_id=host_id,
                        target_id=port_node.id,
                        edge_type=EdgeType.HAS_PORT,
                    )
                    nodes_added += 1
    except Exception as exc:
        logger.warning("recon.port_scan.nmap_error", ip=ip, error=str(exc))
    return nodes_added


def _scan_with_masscan(
    ip: str,
    host_id: str,
    graph: TargetGraph,
    registry: ToolRegistry,
    timeout: int,
) -> int:
    """Run masscan scan and ingest results."""
    nodes_added = 0
    try:
        exit_code, stdout, stderr = registry.run_tool(
            "masscan",
            {"-p": "1-65535", "--rate": "1000", "-oJ": "-"},
            target=ip,
            timeout=timeout,
        )
        if exit_code == 0 and stdout.strip():
            parsed = MasscanParser.parse(stdout)
            for entry in parsed:
                if entry.get("type") == "port":
                    port_node = graph.add_port(
                        port_number=entry["port"],
                        protocol=entry.get("protocol", "tcp"),
                        state=entry.get("state", "open"),
                    )
                    graph.add_edge(
                        source_id=host_id,
                        target_id=port_node.id,
                        edge_type=EdgeType.HAS_PORT,
                    )
                    nodes_added += 1
    except Exception as exc:
        logger.warning("recon.port_scan.masscan_error", ip=ip, error=str(exc))
    return nodes_added
