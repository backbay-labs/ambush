"""
Domain Recon - Subdomain enumeration and DNS resolution.

Runs subfinder for subdomain discovery, then resolves discovered subdomains
to IP addresses and populates TargetGraph with SUBDOMAIN, HOST nodes and
HAS_SUBDOMAIN, RESOLVES_TO edges.
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

import structlog

from hellcat.offensive.target_graph.models import EdgeType
from hellcat.offensive.tools.parsers import SubfinderParser

if TYPE_CHECKING:
    from hellcat.offensive.target_graph.graph import TargetGraph
    from hellcat.offensive.tools.registry import ToolRegistry

logger = structlog.get_logger()


def run_domain_recon(
    target_domain: str,
    graph: TargetGraph,
    registry: ToolRegistry,
    root_target_id: str | None = None,
    timeout: int = 120,
) -> int:
    """Run subdomain enumeration and DNS resolution.

    Args:
        target_domain: The base domain to enumerate (e.g. "example.com").
        graph: TargetGraph to populate.
        registry: ToolRegistry with available tools.
        root_target_id: Optional ID of the root target node to link subdomains to.
        timeout: Tool execution timeout in seconds.

    Returns:
        Number of nodes added to the graph.
    """
    nodes_added = 0

    subfinder = registry.get_tool("subfinder")
    subdomains: list[str] = []

    if subfinder and subfinder.available:
        try:
            exit_code, stdout, stderr = registry.run_tool(
                "subfinder",
                {"-d": target_domain, "-silent": ""},
                timeout=timeout,
            )
            if exit_code == 0 and stdout.strip():
                parsed = SubfinderParser.parse(stdout)
                subdomains = [entry["host"] for entry in parsed if entry.get("host")]
                logger.info(
                    "recon.domain.subfinder_complete",
                    domain=target_domain,
                    subdomains_found=len(subdomains),
                )
        except Exception as exc:
            logger.warning("recon.domain.subfinder_error", error=str(exc))
    else:
        logger.info("recon.domain.subfinder_unavailable", domain=target_domain)

    # Always include the base domain itself
    if target_domain not in subdomains:
        subdomains.insert(0, target_domain)

    seen_ips: dict[str, str] = {}  # ip -> host_node_id

    for hostname in subdomains:
        resolved_ips = _resolve_hostname(hostname)
        ip_str = ",".join(resolved_ips)

        sub_node = graph.add_subdomain(
            hostname=hostname,
            resolved_ips=ip_str,
            source="subfinder" if hostname != target_domain else "seed",
        )
        nodes_added += 1

        if root_target_id:
            graph.add_edge(
                source_id=root_target_id,
                target_id=sub_node.id,
                edge_type=EdgeType.HAS_SUBDOMAIN,
            )

        # Add host nodes for resolved IPs
        for ip in resolved_ips:
            if ip not in seen_ips:
                host_node = graph.add_host(ip=ip, hostname=hostname)
                seen_ips[ip] = host_node.id
                nodes_added += 1

            graph.add_edge(
                source_id=sub_node.id,
                target_id=seen_ips[ip],
                edge_type=EdgeType.RESOLVES_TO,
            )

    logger.info(
        "recon.domain.complete",
        domain=target_domain,
        subdomains=len(subdomains),
        hosts=len(seen_ips),
        nodes_added=nodes_added,
    )
    return nodes_added


def _resolve_hostname(hostname: str) -> list[str]:
    """Resolve a hostname to IP addresses. Returns empty list on failure."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips = list({r[4][0] for r in results})
        return sorted(ips)
    except (socket.gaierror, OSError):
        return []
