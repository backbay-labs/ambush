"""Phase: Asset Discovery - Broad asset enumeration via Amass."""
from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from hellcat.offensive.tools.parsers import AmassParser

if TYPE_CHECKING:
    from hellcat.offensive.target_graph.graph import TargetGraph
    from hellcat.offensive.tools.registry import ToolRegistry

logger = structlog.get_logger()


def run_asset_discovery(
    target_domain: str,
    graph: TargetGraph,
    registry: ToolRegistry,
    root_target_id: str | None = None,
    timeout: int = 300,
) -> int:
    """Run Amass passive asset discovery for the target domain.

    Discovers subdomains and hosts via passive DNS, certificate transparency,
    and other OSINT sources. Creates SUBDOMAIN and HOST nodes.

    Returns:
        Number of nodes added.
    """
    tool = registry.get_tool("amass")
    if tool is None or not tool.available:
        logger.warning("recon.asset_discovery.amass_unavailable")
        return 0

    nodes_added = 0

    try:
        exit_code, stdout, stderr = registry.run_tool(
            "amass",
            {"-d": target_domain, "-passive": "", "-json": ""},
            timeout=timeout,
        )
    except Exception as exc:
        logger.warning("recon.asset_discovery.tool_error", error=str(exc))
        return 0

    if exit_code != 0:
        logger.warning("recon.asset_discovery.nonzero_exit", code=exit_code)

    results = AmassParser.parse(stdout)
    for result in results:
        hostname = result.get("hostname", "")
        if not hostname:
            continue

        sub_node = graph.add_subdomain(
            hostname=hostname,
            resolved_ips=",".join(result.get("addresses", [])),
            source=result.get("source", "amass"),
            metadata={"tag": result.get("tag", ""), "source": "amass"},
        )
        nodes_added += 1

        if root_target_id:
            from hellcat.offensive.target_graph.models import EdgeType
            graph.add_edge(
                source_id=root_target_id,
                target_id=sub_node.id,
                edge_type=EdgeType.HAS_SUBDOMAIN,
            )

        for addr in result.get("addresses", []):
            graph.add_host(
                ip=addr,
                hostname=hostname,
                metadata={"source": "amass"},
            )
            nodes_added += 1

    logger.info(
        "recon.asset_discovery.complete",
        domain=target_domain,
        nodes_added=nodes_added,
    )
    return nodes_added
