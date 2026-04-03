"""Phase: Web Crawl - Headless JS crawling via katana."""
from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from hellcat.offensive.tools.parsers import KatanaParser

if TYPE_CHECKING:
    from hellcat.offensive.target_graph.graph import TargetGraph
    from hellcat.offensive.tools.registry import ToolRegistry

logger = structlog.get_logger()


def run_web_crawl(
    target_domain: str,
    graph: TargetGraph,
    registry: ToolRegistry,
    timeout: int = 300,
) -> int:
    """Run katana headless crawler against discovered endpoints.

    Discovers JavaScript-rendered endpoints, form actions, and API calls
    that static crawlers miss. Creates ENDPOINT nodes in the TargetGraph.

    Returns:
        Number of nodes added.
    """
    tool = registry.get_tool("katana")
    if tool is None or not tool.available:
        logger.warning("recon.web_crawl.katana_unavailable")
        return 0

    nodes_added = 0

    # Collect existing endpoint URLs to crawl
    endpoint_rows = graph.conn.execute(
        "SELECT url FROM endpoints UNION SELECT url FROM targets"
    ).fetchall()
    urls = [row["url"] for row in endpoint_rows if row["url"]]

    if not urls:
        urls = [f"https://{target_domain}"]

    for url in urls[:10]:  # Limit to first 10 URLs to avoid excessive crawling
        try:
            exit_code, stdout, stderr = registry.run_tool(
                "katana",
                {"-u": url, "-j": "", "-headless": "", "-depth": "3", "-silent": ""},
                timeout=timeout,
            )
        except (ValueError, Exception) as exc:
            logger.warning("recon.web_crawl.tool_error", url=url, error=str(exc))
            continue

        if exit_code != 0:
            logger.warning("recon.web_crawl.nonzero_exit", url=url, code=exit_code)
            continue

        results = KatanaParser.parse(stdout)
        for result in results:
            endpoint_url = result.get("url", "")
            if not endpoint_url:
                continue

            graph.add_endpoint(
                url=endpoint_url,
                method=result.get("method", "GET"),
                parameters=result.get("parameters", ""),
                content_type=result.get("content_type", ""),
                metadata={
                    "source": "katana",
                    "tag": result.get("tag", ""),
                },
            )
            nodes_added += 1

    logger.info("recon.web_crawl.complete", domain=target_domain, nodes_added=nodes_added)
    return nodes_added
