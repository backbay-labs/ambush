"""
Vulnerability Scanning - Template-based vuln detection.

Runs nuclei against discovered endpoints and services, then populates
VULNERABILITY nodes linked to their targets.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from hellcat.offensive.target_graph.models import EdgeType, Severity
from hellcat.offensive.tools.parsers import NucleiParser

if TYPE_CHECKING:
    from hellcat.offensive.target_graph.graph import TargetGraph
    from hellcat.offensive.tools.registry import ToolRegistry

logger = structlog.get_logger()

_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def run_vuln_scan(
    target_domain: str,
    graph: TargetGraph,
    registry: ToolRegistry,
    timeout: int = 600,
) -> int:
    """Run nuclei vulnerability scanning against discovered targets.

    Args:
        target_domain: Base domain for context.
        graph: TargetGraph to populate with VULNERABILITY nodes.
        registry: ToolRegistry with available tools.
        timeout: Tool execution timeout in seconds.

    Returns:
        Number of vulnerability nodes added to the graph.
    """
    nuclei = registry.get_tool("nuclei")
    if not nuclei or not nuclei.available:
        logger.info("recon.vuln_scan.nuclei_unavailable")
        return 0

    # Build list of URLs to scan from subdomains and hosts
    scan_urls: list[str] = []
    for sub in graph.get_subdomains():
        hostname = sub.get("hostname", "")
        if hostname:
            scan_urls.append(f"https://{hostname}")

    if not scan_urls:
        # Fall back to host IPs
        for host in graph.get_hosts():
            ip = host.get("ip", "")
            if ip:
                scan_urls.append(f"http://{ip}")

    if not scan_urls:
        logger.info("recon.vuln_scan.no_targets", domain=target_domain)
        return 0

    nodes_added = 0
    for url in scan_urls:
        try:
            exit_code, stdout, stderr = registry.run_tool(
                "nuclei",
                {"-u": url, "-j": "", "-silent": ""},
                timeout=timeout,
            )
            if exit_code == 0 and stdout.strip():
                parsed = NucleiParser.parse(stdout)
                for entry in parsed:
                    nodes_added += _ingest_nuclei_finding(entry, graph)
        except Exception as exc:
            logger.warning(
                "recon.vuln_scan.nuclei_error", url=url, error=str(exc),
            )

    logger.info(
        "recon.vuln_scan.complete",
        domain=target_domain,
        urls_scanned=len(scan_urls),
        vulns_added=nodes_added,
    )
    return nodes_added


def _ingest_nuclei_finding(entry: dict, graph: TargetGraph) -> int:
    """Ingest a single nuclei finding into the graph. Returns 1 if added, 0 otherwise."""
    if entry.get("type") != "vulnerability":
        return 0

    severity_str = entry.get("severity", "info").lower()
    severity = _SEVERITY_MAP.get(severity_str, Severity.INFO)

    vuln_node = graph.add_vulnerability(
        vuln_type=entry.get("vuln_type", "unknown"),
        severity=severity,
        description=entry.get("description", ""),
        source_location=entry.get("matched_at", entry.get("endpoint", "")),
        metadata={
            "template_id": entry.get("template_id", ""),
            "tags": entry.get("metadata", {}).get("tags", []),
        },
    )

    # Try to link to the target subdomain node via EXPOSES
    endpoint = entry.get("endpoint", "")
    if endpoint:
        # Find matching subdomain
        for sub in graph.get_subdomains():
            if sub["hostname"] in endpoint:
                graph.add_edge(
                    source_id=sub["id"],
                    target_id=vuln_node.id,
                    edge_type=EdgeType.EXPOSES,
                )
                break

    return 1
