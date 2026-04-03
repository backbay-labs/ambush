"""
Intel Enrichment - NVD/CVE correlation for discovered services.

Queries the NVD for known CVEs affecting discovered technologies and
services, then adds VULNERABILITY nodes linked via EXPOSES edges.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import structlog

from hellcat.offensive.target_graph.models import EdgeType, Severity

if TYPE_CHECKING:
    from hellcat.offensive.knowledge.vuln_db import VulnKnowledgeBase
    from hellcat.offensive.target_graph.graph import TargetGraph

logger = structlog.get_logger()


def run_intel_enrichment(
    target_domain: str,
    graph: TargetGraph,
    vuln_kb: VulnKnowledgeBase | None = None,
) -> int:
    """Enrich discovered services/technologies with CVE intelligence.

    Searches the VulnKnowledgeBase for CVEs matching discovered
    technology names and versions, then links them to the graph.

    Args:
        target_domain: Base domain for context.
        graph: TargetGraph to enrich with VULNERABILITY nodes.
        vuln_kb: Optional VulnKnowledgeBase to search for CVEs.

    Returns:
        Number of vulnerability nodes added.
    """
    if vuln_kb is None:
        logger.info("recon.intel_enrichment.no_kb", domain=target_domain)
        return 0

    nodes_added = 0

    # Collect technology names to search
    tech_rows = graph.conn.execute("SELECT * FROM technologies").fetchall()
    for row in tech_rows:
        tech = dict(row)
        search_term = tech["name"]
        if tech.get("version"):
            search_term = f"{tech['name']} {tech['version']}"

        cves = vuln_kb.search(search_term)
        for cve in cves:
            severity = _cvss_to_severity(cve.get("cvss", 0.0))
            vuln_node = graph.add_vulnerability(
                vuln_type=cve.get("vuln_type", "cve"),
                severity=severity,
                description=cve.get("description", ""),
                cvss=cve.get("cvss"),
                metadata={
                    "cve_id": cve.get("cve_id", ""),
                    "source": "intel_enrichment",
                    "matched_tech": tech["name"],
                },
            )
            graph.add_edge(
                source_id=tech["id"],
                target_id=vuln_node.id,
                edge_type=EdgeType.EXPOSES,
            )
            nodes_added += 1

    # Also search for service names
    svc_rows = graph.conn.execute("SELECT * FROM services").fetchall()
    for row in svc_rows:
        svc = dict(row)
        if not svc["name"]:
            continue
        search_term = svc["name"]
        if svc.get("version"):
            search_term = f"{svc['name']} {svc['version']}"

        cves = vuln_kb.search(search_term)
        for cve in cves:
            severity = _cvss_to_severity(cve.get("cvss", 0.0))
            vuln_node = graph.add_vulnerability(
                vuln_type=cve.get("vuln_type", "cve"),
                severity=severity,
                description=cve.get("description", ""),
                cvss=cve.get("cvss"),
                metadata={
                    "cve_id": cve.get("cve_id", ""),
                    "source": "intel_enrichment",
                    "matched_service": svc["name"],
                },
            )
            graph.add_edge(
                source_id=svc["id"],
                target_id=vuln_node.id,
                edge_type=EdgeType.EXPOSES,
            )
            nodes_added += 1

    # KEV prioritization pass — tag existing vulns, no new nodes
    vuln_rows = graph.conn.execute("SELECT * FROM vulnerabilities").fetchall()
    for row in vuln_rows:
        vuln = dict(row)
        meta = json.loads(vuln.get("metadata_json", "{}"))
        cve_id = meta.get("cve_id", "")
        if cve_id and vuln_kb and vuln_kb.is_kev(cve_id):
            meta["kev_exploited"] = True
            graph.conn.execute(
                "UPDATE vulnerabilities SET metadata_json = ? WHERE id = ?",
                (json.dumps(meta), vuln["id"]),
            )
    graph.conn.commit()

    logger.info(
        "recon.intel_enrichment.complete",
        domain=target_domain,
        vulns_added=nodes_added,
    )
    return nodes_added


def _cvss_to_severity(cvss: float) -> Severity:
    """Map CVSS score to Severity enum."""
    if cvss >= 9.0:
        return Severity.CRITICAL
    elif cvss >= 7.0:
        return Severity.HIGH
    elif cvss >= 4.0:
        return Severity.MEDIUM
    elif cvss > 0:
        return Severity.LOW
    return Severity.INFO
