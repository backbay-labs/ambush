"""
ReconPipeline - Orchestrates the 9-phase deterministic recon pipeline.

Phases:
  1. Asset Discovery    - Amass broad asset enumeration
  2. Exposure Intel     - Shodan/Censys passive exposure intelligence
  3. Domain Recon       - Subdomain enumeration + DNS resolution
  4. Port Scan          - nmap/masscan port discovery
  5. Service FP         - httpx service & technology fingerprinting
  6. Web Crawl          - katana headless JS crawling
  7. Resource Enum      - ffuf directory/endpoint fuzzing
  8. Vuln Scan          - nuclei template scanning
  9. Intel Enrichment   - NVD/CVE correlation

Each phase runs tools directly (no LLM) and populates the TargetGraph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

from hellcat.offensive.recon.asset_discovery import run_asset_discovery
from hellcat.offensive.recon.domain_recon import run_domain_recon
from hellcat.offensive.recon.exposure_intel import run_exposure_intel
from hellcat.offensive.recon.intel_enrichment import run_intel_enrichment
from hellcat.offensive.recon.port_scan import run_port_scan
from hellcat.offensive.recon.resource_enum import run_resource_enum
from hellcat.offensive.recon.service_fingerprint import run_service_fingerprint
from hellcat.offensive.recon.vuln_scan import run_vuln_scan
from hellcat.offensive.recon.web_crawl import run_web_crawl

if TYPE_CHECKING:
    from hellcat.offensive.knowledge.vuln_db import VulnKnowledgeBase
    from hellcat.offensive.target_graph.graph import TargetGraph
    from hellcat.offensive.tools.registry import ToolRegistry

logger = structlog.get_logger()

# All pipeline phases in order
ALL_RECON_PHASES: list[str] = [
    "asset_discovery",
    "exposure_intel",
    "domain_recon",
    "port_scan",
    "service_fingerprint",
    "web_crawl",
    "resource_enum",
    "vuln_scan",
    "intel_enrichment",
]


@dataclass
class ReconPipelineConfig:
    """Configuration for the recon pipeline."""

    enabled: bool = True
    phases: list[str] = field(default_factory=lambda: list(ALL_RECON_PHASES))
    timeout: int = 300


@dataclass
class PhaseResult:
    """Result from a single pipeline phase."""

    phase: str
    nodes_added: int = 0
    error: str | None = None
    skipped: bool = False


@dataclass
class ReconPipelineResult:
    """Aggregate result from running the full pipeline."""

    phases: list[PhaseResult] = field(default_factory=list)
    total_nodes_added: int = 0
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return len(self.errors) == 0


class ReconPipeline:
    """Orchestrates the 9-phase recon pipeline.

    Usage::

        pipeline = ReconPipeline(graph, registry, config=ReconPipelineConfig())
        result = pipeline.run("example.com")
    """

    def __init__(
        self,
        graph: TargetGraph,
        registry: ToolRegistry,
        config: ReconPipelineConfig | None = None,
        vuln_kb: VulnKnowledgeBase | None = None,
        root_target_id: str | None = None,
    ) -> None:
        self.graph = graph
        self.registry = registry
        self.config = config or ReconPipelineConfig()
        self.vuln_kb = vuln_kb
        self.root_target_id = root_target_id

    def run(self, target_domain: str) -> ReconPipelineResult:
        """Execute the configured pipeline phases in order.

        Args:
            target_domain: The base domain to recon (e.g. "example.com").

        Returns:
            ReconPipelineResult with per-phase counts and errors.
        """
        if not self.config.enabled:
            logger.info("recon.pipeline.disabled")
            return ReconPipelineResult()

        result = ReconPipelineResult()
        timeout = self.config.timeout

        logger.info(
            "recon.pipeline.starting",
            domain=target_domain,
            phases=self.config.phases,
        )

        phase_runners = {
            "asset_discovery": lambda: run_asset_discovery(
                target_domain, self.graph, self.registry,
                root_target_id=self.root_target_id,
                timeout=timeout,
            ),
            "exposure_intel": lambda: run_exposure_intel(
                target_domain, self.graph,
            ),
            "domain_recon": lambda: run_domain_recon(
                target_domain, self.graph, self.registry,
                root_target_id=self.root_target_id,
                timeout=timeout,
            ),
            "port_scan": lambda: run_port_scan(
                target_domain, self.graph, self.registry, timeout=timeout,
            ),
            "service_fingerprint": lambda: run_service_fingerprint(
                target_domain, self.graph, self.registry, timeout=timeout,
            ),
            "web_crawl": lambda: run_web_crawl(
                target_domain, self.graph, self.registry, timeout=timeout,
            ),
            "resource_enum": lambda: run_resource_enum(
                target_domain, self.graph, self.registry, timeout=timeout,
            ),
            "vuln_scan": lambda: run_vuln_scan(
                target_domain, self.graph, self.registry, timeout=timeout,
            ),
            "intel_enrichment": lambda: run_intel_enrichment(
                target_domain, self.graph, vuln_kb=self.vuln_kb,
            ),
        }

        for phase_name in self.config.phases:
            if phase_name not in phase_runners:
                logger.warning("recon.pipeline.unknown_phase", phase=phase_name)
                result.phases.append(PhaseResult(
                    phase=phase_name, skipped=True,
                    error=f"Unknown phase: {phase_name}",
                ))
                continue

            logger.info("recon.pipeline.phase_start", phase=phase_name)
            try:
                nodes_added = phase_runners[phase_name]()
                result.phases.append(PhaseResult(
                    phase=phase_name, nodes_added=nodes_added,
                ))
                result.total_nodes_added += nodes_added
                logger.info(
                    "recon.pipeline.phase_complete",
                    phase=phase_name,
                    nodes_added=nodes_added,
                )
            except Exception as exc:
                error_msg = str(exc)
                result.phases.append(PhaseResult(
                    phase=phase_name, error=error_msg,
                ))
                result.errors[phase_name] = error_msg
                logger.error(
                    "recon.pipeline.phase_error",
                    phase=phase_name,
                    error=error_msg,
                )

        logger.info(
            "recon.pipeline.complete",
            domain=target_domain,
            total_nodes=result.total_nodes_added,
            errors=list(result.errors.keys()),
        )
        return result
