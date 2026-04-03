"""Phase: Exposure Intelligence - Passive reconnaissance via Shodan/Censys APIs."""
from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from hellcat.offensive.tools.osint.censys import CensysClient
from hellcat.offensive.tools.osint.shodan import ShodanClient

if TYPE_CHECKING:
    from hellcat.offensive.target_graph.graph import TargetGraph

logger = structlog.get_logger()


def run_exposure_intel(
    target_domain: str,
    graph: TargetGraph,
) -> int:
    """Query Shodan and Censys APIs for passive exposure intelligence.

    Creates HOST, PORT, SERVICE, and CERTIFICATE nodes from API data
    without sending any packets to the target.

    Returns:
        Number of nodes added.
    """
    nodes_added = 0

    shodan = ShodanClient()
    censys = CensysClient()

    if not shodan.is_configured and not censys.is_configured:
        logger.info("recon.exposure_intel.no_api_keys_configured")
        return 0

    # Collect IPs from existing hosts
    host_rows = graph.conn.execute("SELECT ip FROM hosts").fetchall()
    ips = [row["ip"] for row in host_rows if row["ip"]]

    # Shodan domain search
    if shodan.is_configured:
        try:
            domain_results = shodan.search_domain(target_domain)
            for record in domain_results:
                subdomain = record.get("subdomain", "")
                value = record.get("value", "")
                if subdomain and value:
                    full_hostname = (
                        f"{subdomain}.{target_domain}" if subdomain else target_domain
                    )
                    graph.add_subdomain(
                        hostname=full_hostname,
                        resolved_ips=value,
                        source="shodan",
                        metadata={
                            "source": "shodan",
                            "record_type": record.get("type", ""),
                        },
                    )
                    nodes_added += 1
        except Exception as exc:
            logger.warning(
                "recon.exposure_intel.shodan_domain_error", error=str(exc),
            )

    # Shodan host lookups
    if shodan.is_configured:
        for ip in ips[:20]:  # Limit API calls
            try:
                host_result = shodan.search_host(ip)
                if host_result is None:
                    continue

                # Update host with OS info
                if host_result.os_guess:
                    graph.conn.execute(
                        "UPDATE hosts SET os_guess = ? WHERE ip = ?",
                        (host_result.os_guess, ip),
                    )

                for svc in host_result.services:
                    port_num = svc.get("port", 0)
                    if not port_num:
                        continue
                    graph.add_port(
                        port_number=port_num,
                        protocol=svc.get("transport", "tcp"),
                        service_name=svc.get("product", ""),
                        service_version=svc.get("version", ""),
                        metadata={
                            "source": "shodan",
                            "banner": svc.get("banner", "")[:200],
                        },
                    )
                    nodes_added += 1

                    if svc.get("product"):
                        graph.add_service(
                            name=svc["product"],
                            version=svc.get("version", ""),
                            banner=svc.get("banner", "")[:200],
                            cpe=",".join(svc.get("cpe", [])),
                            metadata={"source": "shodan"},
                        )
                        nodes_added += 1

                # Record Shodan vulns
                for vuln_id in host_result.vulns:
                    graph.add_vulnerability(
                        vuln_type="cve",
                        description=f"Shodan reported vulnerability: {vuln_id}",
                        metadata={
                            "cve_id": vuln_id,
                            "source": "shodan",
                            "host_ip": ip,
                        },
                    )
                    nodes_added += 1

            except Exception as exc:
                logger.warning(
                    "recon.exposure_intel.shodan_host_error",
                    ip=ip,
                    error=str(exc),
                )

    # Censys host search
    if censys.is_configured:
        try:
            censys_results = censys.search_hosts(target_domain)
            for host_result in censys_results:
                if not host_result.ip:
                    continue
                graph.add_host(
                    ip=host_result.ip,
                    os_guess=host_result.operating_system,
                    metadata={"source": "censys"},
                )
                nodes_added += 1

                for svc in host_result.services:
                    port_num = svc.get("port", 0)
                    if not port_num:
                        continue
                    graph.add_port(
                        port_number=port_num,
                        protocol=svc.get(
                            "transport_protocol", "TCP",
                        ).lower(),
                        service_name=svc.get("service_name", ""),
                        metadata={"source": "censys"},
                    )
                    nodes_added += 1

        except Exception as exc:
            logger.warning(
                "recon.exposure_intel.censys_error", error=str(exc),
            )

    # Censys certificate search
    if censys.is_configured:
        try:
            certs = censys.search_certs(target_domain)
            for cert in certs:
                graph.add_certificate(
                    subject=cert.get("subject", ""),
                    issuer=cert.get("issuer", ""),
                    valid_from=cert.get("validity_start", ""),
                    valid_to=cert.get("validity_end", ""),
                    san_list=",".join(cert.get("names", [])),
                    metadata={
                        "source": "censys",
                        "fingerprint": cert.get("fingerprint", ""),
                    },
                )
                nodes_added += 1
        except Exception as exc:
            logger.warning(
                "recon.exposure_intel.censys_certs_error", error=str(exc),
            )

    graph.conn.commit()

    logger.info(
        "recon.exposure_intel.complete",
        domain=target_domain,
        nodes_added=nodes_added,
    )
    return nodes_added
