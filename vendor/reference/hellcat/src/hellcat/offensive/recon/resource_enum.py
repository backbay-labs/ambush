"""
Resource Enumeration - Directory and endpoint fuzzing.

Runs ffuf against discovered web services to find hidden endpoints,
directories, and resources. Populates ENDPOINT nodes with HAS_ENDPOINT edges.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import structlog

from hellcat.offensive.target_graph.models import EdgeType

if TYPE_CHECKING:
    from hellcat.offensive.target_graph.graph import TargetGraph
    from hellcat.offensive.tools.registry import ToolRegistry

logger = structlog.get_logger()

# Default wordlist path (common in Kali/security distros)
_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


def run_resource_enum(
    target_domain: str,
    graph: TargetGraph,
    registry: ToolRegistry,
    wordlist: str = _DEFAULT_WORDLIST,
    timeout: int = 300,
) -> int:
    """Enumerate directories and endpoints on web services.

    Runs ffuf directory fuzzing against each discovered service.

    Args:
        target_domain: Base domain for context.
        graph: TargetGraph to populate with ENDPOINT nodes.
        registry: ToolRegistry with available tools.
        wordlist: Path to directory wordlist for ffuf.
        timeout: Tool execution timeout in seconds.

    Returns:
        Number of endpoint nodes added to the graph.
    """
    ffuf = registry.get_tool("ffuf")
    if not ffuf or not ffuf.available:
        logger.info("recon.resource_enum.ffuf_unavailable")
        return 0

    nodes_added = 0

    # Get all hosts and their services
    hosts = graph.get_hosts()
    for host in hosts:
        host_id = host["id"]
        ip = host["ip"]
        services = graph.get_services_for_host(host_id)

        # If no services, try ports directly
        ports = graph.get_ports_for_host(host_id)
        if not services and not ports:
            continue

        # Build URLs to fuzz: use services if available, fall back to ports
        fuzz_targets: list[tuple[str, str]] = []  # (url, parent_id)
        for svc in services:
            port_edges = graph.get_edges_to(svc["id"], EdgeType.RUNS_SERVICE)
            for edge in port_edges:
                port_node = graph.get_node(edge["source_id"])
                if port_node:
                    port_num = port_node.get("port_number", 80)
                    scheme = "https" if port_num == 443 else "http"
                    url = f"{scheme}://{ip}:{port_num}/FUZZ"
                    fuzz_targets.append((url, svc["id"]))

        if not fuzz_targets:
            for port in ports:
                port_num = port["port_number"]
                scheme = "https" if port_num == 443 else "http"
                url = f"{scheme}://{ip}:{port_num}/FUZZ"
                fuzz_targets.append((url, port["id"]))

        for fuzz_url, parent_id in fuzz_targets:
            nodes_added += _fuzz_endpoint(
                fuzz_url, parent_id, graph, registry, wordlist, timeout,
            )

    logger.info(
        "recon.resource_enum.complete",
        domain=target_domain,
        endpoints_added=nodes_added,
    )
    return nodes_added


def _fuzz_endpoint(
    fuzz_url: str,
    parent_id: str,
    graph: TargetGraph,
    registry: ToolRegistry,
    wordlist: str,
    timeout: int,
) -> int:
    """Run ffuf against a single URL with FUZZ marker."""
    nodes_added = 0
    try:
        exit_code, stdout, stderr = registry.run_tool(
            "ffuf",
            {
                "-u": fuzz_url,
                "-w": wordlist,
                "-mc": "200,201,301,302,403",
                "-of": "json",
                "-o": "-",
            },
            timeout=timeout,
        )
        if exit_code == 0 and stdout.strip():
            nodes_added += _parse_ffuf_output(stdout, fuzz_url, parent_id, graph)
    except Exception as exc:
        logger.warning("recon.resource_enum.ffuf_error", url=fuzz_url, error=str(exc))
    return nodes_added


def _parse_ffuf_output(
    output: str,
    fuzz_url: str,
    parent_id: str,
    graph: TargetGraph,
) -> int:
    """Parse ffuf JSON output and add endpoint nodes."""
    nodes_added = 0
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return 0

    results = data.get("results", [])
    base_url = fuzz_url.replace("/FUZZ", "")

    for result in results:
        input_word = result.get("input", {}).get("FUZZ", "")
        status = result.get("status", 0)
        length = result.get("length", 0)
        content_type = result.get("content-type", "")

        if input_word:
            endpoint_url = f"{base_url}/{input_word}"
            ep_node = graph.add_endpoint(
                url=endpoint_url,
                method="GET",
                content_type=content_type,
                metadata={"status_code": status, "content_length": length},
            )
            graph.add_edge(
                source_id=parent_id,
                target_id=ep_node.id,
                edge_type=EdgeType.HAS_ENDPOINT,
            )
            nodes_added += 1

    return nodes_added
