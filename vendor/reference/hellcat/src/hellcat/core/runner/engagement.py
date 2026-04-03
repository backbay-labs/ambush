"""
EngagementRunner - Orchestrates a full pentest engagement.

Wires together: EngagementConfig -> TargetGraph -> AttackPlanner ->
PlannerDispatcher -> ReportGenerator.

Supports:
- Full run: execute all phases and generate reports
- Dry run: plan preview without execution
- Signal handling: SIGTERM/SIGINT -> graceful shutdown
- CI exit codes: 0=clean, 1=error, 2=vulns found
"""

from __future__ import annotations

import contextlib
import json
import signal
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from hellcat.core.audit.session import AuditSession, EngagementSummary
from hellcat.core.config.engagement import EngagementConfig
from hellcat.offensive.knowledge.vuln_db import VulnKnowledgeBase
from hellcat.offensive.opsec.circuit_breaker import OpsecCircuitBreaker
from hellcat.offensive.opsec.noise_monitor import NoiseMonitor
from hellcat.offensive.opsec.stealth_budget import BudgetConfig, StealthBudget
from hellcat.core.planner.dispatch import DispatchResult, PlannerDispatcher
from hellcat.core.planner.planner import AttackPlan, AttackPlanner
from hellcat.offensive.proof.validator import ProofValidator
from hellcat.offensive.recon.pipeline import ReconPipeline, ReconPipelineConfig, ReconPipelineResult
from hellcat.core.reporting.generator import ReportBundle, ReportGenerator
from hellcat.core.store.engagement_store import EngagementStore
from hellcat.offensive.strikecell.manager import StrikeCellManager
from hellcat.offensive.target_graph.graph import TargetGraph
from hellcat.offensive.tools.osint.base import OsintResult
from hellcat.offensive.tools.osint.collector import OsintCollector
from hellcat.offensive.tools.registry import ToolRegistry

logger = structlog.get_logger()

# Exit codes for CI gate integration
EXIT_CLEAN = 0
EXIT_ERROR = 1
EXIT_VULNS_FOUND = 2


@dataclass
class EngagementResult:
    """Outcome of a full engagement run."""

    engagement_id: str = ""
    target_url: str = ""
    success: bool = False
    exit_code: int = EXIT_ERROR
    summary: EngagementSummary | None = None
    dispatch_result: DispatchResult | None = None
    report: ReportBundle | None = None
    plan: AttackPlan | None = None
    error: str | None = None
    vulns_found: int = 0
    osint_result: OsintResult | None = None
    output_dir: str = ""


def _promote_recon_nodes(graph: TargetGraph) -> int:
    """Promote DISCOVERED nodes with recon data to ANALYZED.

    Called after recon completes but before the planner runs so that
    recon findings become schedulable attack targets. Idempotent:
    already-promoted nodes are skipped.

    Returns:
        Number of nodes promoted.
    """
    promoted = graph.promote_discovered_nodes()
    if promoted > 0:
        logger.info(
            "engagement.recon_promotion",
            promoted_node_count=promoted,
        )
    return promoted


def _enrich_vuln_scoring(graph: TargetGraph, output_dir: Path) -> int:
    """Enrich vulnerability nodes with EPSS and CVSSv4 data.

    Scans ANALYZED nodes for CVE IDs, fetches EPSS scores in bulk,
    queries NVD for CVSSv4 metrics, and writes enrichment to the graph
    so the AttackScorer can use real EPSS/CVSSv4 signals.

    Returns:
        Number of nodes enriched.
    """
    from hellcat.offensive.tools.osint.epss import EPSSClient
    from hellcat.offensive.tools.osint.nvd import NvdClient

    rows = graph.conn.execute(
        "SELECT id, metadata_json FROM vulnerabilities WHERE metadata_json != '{}'"
    ).fetchall()
    if not rows:
        return 0

    # Collect CVE IDs from vulnerability metadata (multiple nodes may share a CVE)
    cve_map: dict[str, list[str]] = {}  # cve_id -> [node_id, ...]
    for row in rows:
        raw = row["metadata_json"]
        try:
            meta = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        cve_id = meta.get("cve_id", "")
        if cve_id and cve_id.startswith("CVE-"):
            cve_map.setdefault(cve_id, []).append(row["id"])

    if not cve_map:
        return 0

    enriched = 0

    # Bulk EPSS lookup
    try:
        epss_client = EPSSClient(timeout=15)
        epss_records = epss_client.bulk_lookup(list(cve_map.keys()))
        epss_by_cve = {r.cve_id: r for r in epss_records}
    except Exception as exc:
        logger.debug("engagement.epss_enrichment_error", error=str(exc))
        epss_by_cve = {}

    # CVSSv4 extraction via NVD point queries
    nvd_client = NvdClient(timeout=15)
    now_iso = datetime.now(UTC).isoformat()

    for cve_id, node_ids in cve_map.items():
        update: dict[str, Any] = {"data_freshness": now_iso}

        # EPSS
        epss_rec = epss_by_cve.get(cve_id)
        if epss_rec:
            update["epss_score"] = epss_rec.epss_score
            update["epss_percentile"] = epss_rec.percentile

        # CVSSv4 — query NVD for this specific CVE by exact ID
        try:
            vuln = nvd_client.fetch_cve_by_id(cve_id)
            if vuln:
                cve_data = vuln.get("cve", {})
                v4 = NvdClient.extract_cvss_v4(cve_data)
                if v4:
                    update.update(v4)
        except Exception as exc:
            logger.debug("engagement.nvd_v4_error", cve_id=cve_id, error=str(exc))

        if len(update) > 1:  # more than just data_freshness
            for node_id in node_ids:
                graph.update_vuln_enrichment(node_id, update)
                enriched += 1

    return enriched


class EngagementRunner:
    """
    Orchestrates a full Hellcat pentest engagement.

    Usage::

        config = EngagementConfig.from_yaml("engagement.yaml")
        runner = EngagementRunner(config)
        result = runner.run()
        sys.exit(result.exit_code)
    """

    def __init__(self, config: EngagementConfig) -> None:
        self.config = config
        self._shutdown_event = threading.Event()
        self._original_sigint = None
        self._original_sigterm = None

    def run(self) -> EngagementResult:
        """Execute the full engagement pipeline.

        Returns:
            EngagementResult with exit_code:
                0 = clean (no vulns)
                1 = error
                2 = vulns found (useful for CI gates)
        """
        self._install_signal_handlers()
        try:
            return self._run_engagement()
        except Exception as exc:
            logger.error("engagement.fatal_error", error=str(exc))
            return EngagementResult(
                target_url=self.config.target_url,
                success=False,
                exit_code=EXIT_ERROR,
                error=str(exc),
            )
        finally:
            self._restore_signal_handlers()

    def run_dry(self) -> EngagementResult:
        """Plan preview without execution.

        Creates the TargetGraph and AttackPlan but does not dispatch
        any StrikeCells. Useful for reviewing what would happen.

        Returns:
            EngagementResult with the plan but no dispatch results.
        """
        try:
            output_dir = Path(self.config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            db_path = output_dir / "target_graph.db"
            graph = TargetGraph(db_path)

            try:
                # Seed the root target
                graph.add_target(
                    url=self.config.target_url,
                    description="engagement root target",
                )

                # Build planner components
                noise_monitor = NoiseMonitor()
                stealth_budget = StealthBudget(BudgetConfig(total_budget=self.config.stealth_budget))
                circuit_breaker = OpsecCircuitBreaker()

                planner = AttackPlanner(
                    graph=graph,
                    noise_monitor=noise_monitor,
                    stealth_budget=stealth_budget,
                    circuit_breaker=circuit_breaker,
                    epss_staleness_hours=self.config.epss_max_age_hours,
                    nvd_staleness_hours=self.config.nvd_max_age_hours,
                )

                plan = planner.plan()

                logger.info(
                    "engagement.dry_run",
                    target=self.config.target_url,
                    scheduled=len(plan.scheduled),
                    skipped=len(plan.skipped),
                    phases=self.config.phases,
                )

                return EngagementResult(
                    target_url=self.config.target_url,
                    success=True,
                    exit_code=EXIT_CLEAN,
                    plan=plan,
                    output_dir=str(output_dir),
                )
            finally:
                graph.close()

        except Exception as exc:
            logger.error("engagement.dry_run_error", error=str(exc))
            return EngagementResult(
                target_url=self.config.target_url,
                success=False,
                exit_code=EXIT_ERROR,
                error=str(exc),
            )

    def _run_engagement(self) -> EngagementResult:
        """Internal engagement execution."""
        config = self.config
        output_dir = Path(config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        db_path = output_dir / "target_graph.db"
        graph = TargetGraph(db_path)

        audit_dir = output_dir / "audit"
        audit_session = AuditSession(audit_dir=audit_dir)
        engagement_id = audit_session.start_engagement(
            target_url=config.target_url,
            config=config.to_dict(),
        )

        # Register in central engagement store
        try:
            store = EngagementStore()
            store.create_engagement(
                target_url=config.target_url,
                config=config.to_dict(),
                engagement_id=engagement_id,
                project_id=config.project_id,
                output_dir=str(output_dir),
            )
        except Exception:
            logger.debug("store.registration_failed", engagement_id=engagement_id)
            store = None

        logger.info(
            "engagement.starting",
            engagement_id=engagement_id,
            target=config.target_url,
            phases=config.phases,
            aggression=config.aggression,
            max_concurrency=config.max_concurrency,
            timeout=config.timeout_seconds,
        )

        try:
            # Seed the root target
            graph.add_target(
                url=config.target_url,
                description="engagement root target",
            )

            # Passive OSINT collection
            osint_result = self._collect_osint(config, graph, output_dir)

            if self._shutdown_event.is_set():
                return self._make_shutdown_result(
                    engagement_id, config.target_url, output_dir,
                )

            # Structured recon pipeline (tool-based, no LLM)
            if "structured_recon" in config.phases:
                self._run_recon_pipeline(config, graph, output_dir)

            if self._shutdown_event.is_set():
                return self._make_shutdown_result(
                    engagement_id, config.target_url, output_dir,
                )

            # Promote recon outputs so planner can schedule attacks
            promoted = _promote_recon_nodes(graph)
            if promoted > 0:
                audit_session._write_record(
                    "recon_promotion",
                    {"promoted_node_count": promoted},
                )

            # Enrich vulnerability nodes with EPSS/CVSSv4 scoring data
            enriched = _enrich_vuln_scoring(graph, output_dir)
            if enriched > 0:
                logger.info("engagement.vuln_enrichment", enriched_count=enriched)

            # Build OPSEC components
            noise_monitor = NoiseMonitor()
            stealth_budget = StealthBudget(BudgetConfig(total_budget=config.stealth_budget))
            circuit_breaker = OpsecCircuitBreaker()

            # Build planner
            planner = AttackPlanner(
                graph=graph,
                noise_monitor=noise_monitor,
                stealth_budget=stealth_budget,
                circuit_breaker=circuit_breaker,
                epss_staleness_hours=config.epss_max_age_hours,
                nvd_staleness_hours=config.nvd_max_age_hours,
            )

            # Build StrikeCellManager
            cells_dir = output_dir / "cells"
            cell_manager = StrikeCellManager(
                base_dir=cells_dir,
                use_docker=False,
            )

            # Build ProofValidator
            proof_validator = ProofValidator(target_graph=graph)

            # Build Dispatcher
            dispatcher = PlannerDispatcher(
                graph=graph,
                cell_manager=cell_manager,
                target_url=config.target_url,
                proof_validator=proof_validator,
                max_concurrency=config.max_concurrency,
                attack_planner=planner,
                authorization_ref=config.authorization_ref,
                global_disable=config.global_disable,
                disabled_tools=config.disabled_tools,
                disabled_phases=config.disabled_phases,
                allowed_hosts=config.scope_includes,
            )

            # Check for shutdown before planning
            if self._shutdown_event.is_set():
                return self._make_shutdown_result(
                    engagement_id, config.target_url, output_dir,
                )

            # Plan
            plan = planner.plan()

            logger.info(
                "engagement.planned",
                scheduled=len(plan.scheduled),
                skipped=len(plan.skipped),
            )

            # Check for shutdown before dispatch
            if self._shutdown_event.is_set():
                return self._make_shutdown_result(
                    engagement_id, config.target_url, output_dir,
                )

            # Kill-switch: global_disable skips dispatch entirely
            if config.global_disable:
                logger.warning(
                    "engagement.global_disable",
                    msg="global_disable is set — skipping dispatch",
                    engagement_id=engagement_id,
                )
                audit_session.end_engagement()
                try:
                    if store is not None:
                        store.update_status(
                            engagement_id=engagement_id,
                            status="failed",
                            exit_code=EXIT_ERROR,
                            error="Engagement disabled via global_disable",
                        )
                except Exception:
                    logger.debug(
                        "store.update_failed", engagement_id=engagement_id,
                    )
                return EngagementResult(
                    engagement_id=engagement_id,
                    target_url=config.target_url,
                    success=False,
                    exit_code=EXIT_ERROR,
                    plan=plan,
                    error="Engagement disabled via global_disable",
                    output_dir=str(output_dir),
                )

            # Dispatch
            dispatch_result = dispatcher.dispatch_plan(plan)

            # Determine vuln count
            vulns_found = len(dispatch_result.collected_findings)

            # End audit
            summary = audit_session.end_engagement(
                vulns_found=vulns_found,
                vulns_exploited=dispatch_result.total_succeeded,
            )

            # Generate reports
            report_generator = ReportGenerator()
            reports_dir = output_dir / "reports"
            report = report_generator.generate(
                graph=graph,
                audit_session=audit_session,
                output_dir=reports_dir,
            )

            # Run format-specific formatters based on config
            from hellcat.core.reporting.formatter import get_formatter
            for fmt in config.report_formats:
                try:
                    formatter = get_formatter(fmt)
                    formatter.format(report, reports_dir)
                except Exception as fmt_exc:
                    logger.warning(
                        "engagement.formatter_error",
                        format=fmt,
                        error=str(fmt_exc),
                    )

            # Determine exit code
            exit_code = EXIT_VULNS_FOUND if vulns_found > 0 else EXIT_CLEAN

            # Update central store
            try:
                if store is not None:
                    store.update_status(
                        engagement_id=engagement_id,
                        status="completed",
                        vulns_found=vulns_found,
                        exit_code=exit_code,
                    )
            except Exception:
                logger.debug("store.update_failed", engagement_id=engagement_id)

            logger.info(
                "engagement.complete",
                engagement_id=engagement_id,
                vulns_found=vulns_found,
                exit_code=exit_code,
                dispatched=dispatch_result.total_dispatched,
                succeeded=dispatch_result.total_succeeded,
                failed=dispatch_result.total_failed,
            )

            return EngagementResult(
                engagement_id=engagement_id,
                target_url=config.target_url,
                success=True,
                exit_code=exit_code,
                summary=summary,
                dispatch_result=dispatch_result,
                report=report,
                plan=plan,
                vulns_found=vulns_found,
                osint_result=osint_result,
                output_dir=str(output_dir),
            )

        except Exception as exc:
            logger.error("engagement.error", error=str(exc))
            with contextlib.suppress(Exception):
                audit_session.end_engagement()
            try:
                if store is not None:
                    store.update_status(
                        engagement_id=engagement_id,
                        status="failed",
                        exit_code=EXIT_ERROR,
                        error=str(exc),
                    )
            except Exception:
                logger.debug("store.update_failed", engagement_id=engagement_id)
            return EngagementResult(
                engagement_id=engagement_id,
                target_url=config.target_url,
                success=False,
                exit_code=EXIT_ERROR,
                error=str(exc),
            )
        finally:
            graph.close()
            try:
                if store is not None:
                    store.close()
            except Exception:
                pass

    def _run_recon_pipeline(
        self,
        config: EngagementConfig,
        graph: TargetGraph,
        output_dir: Path,
    ) -> ReconPipelineResult | None:
        """Run the structured recon pipeline (tool-based, no LLM)."""
        if not config.recon_pipeline_enabled:
            logger.info("engagement.recon_pipeline.disabled")
            return None

        # Extract domain from target URL
        import urllib.parse
        parsed = urllib.parse.urlparse(config.target_url)
        domain = parsed.hostname or parsed.path.split("/")[0]

        # Set up ToolRegistry and check availability
        tool_registry = ToolRegistry()
        tool_registry.check_availability()

        # Set up VulnKnowledgeBase for intel enrichment
        kb_path = output_dir / "vuln_kb.db"
        kb = VulnKnowledgeBase(kb_path)

        # Find root target node ID
        targets = graph.conn.execute(
            "SELECT id FROM targets LIMIT 1"
        ).fetchone()
        root_id = targets["id"] if targets else None

        pipeline_config = ReconPipelineConfig(
            enabled=config.recon_pipeline_enabled,
            phases=config.recon_pipeline_phases,
            timeout=config.recon_pipeline_timeout,
        )

        pipeline = ReconPipeline(
            graph=graph,
            registry=tool_registry,
            config=pipeline_config,
            vuln_kb=kb,
            root_target_id=root_id,
        )

        try:
            result = pipeline.run(domain)
            logger.info(
                "engagement.recon_pipeline.complete",
                total_nodes=result.total_nodes_added,
                errors=list(result.errors.keys()),
            )
            return result
        except Exception as exc:
            logger.warning(
                "engagement.recon_pipeline.error", error=str(exc),
            )
            return None
        finally:
            kb.close()

    def _collect_osint(
        self,
        config: EngagementConfig,
        graph: TargetGraph,
        output_dir: Path,
    ) -> OsintResult | None:
        """Run passive OSINT collection before active recon."""
        if not config.osint_sources:
            return None

        collector = OsintCollector(
            sources=config.osint_sources,
            api_keys=config.osint_api_keys,
        )
        result = collector.collect(config.target_url)

        # Ingest subdomains into TargetGraph
        subs_added = collector.ingest_into_graph(result, graph)

        # Ingest CVEs into VulnKnowledgeBase
        kb_path = output_dir / "vuln_kb.db"
        kb = VulnKnowledgeBase(kb_path)
        try:
            cves_added = collector.ingest_into_knowledge_base(result, kb)
        finally:
            kb.close()

        logger.info(
            "engagement.osint_complete",
            subdomains_added=subs_added,
            cves_added=cves_added,
            total_findings=len(result.findings),
        )
        return result

    def _make_shutdown_result(
        self,
        engagement_id: str,
        target_url: str,
        output_dir: Path,
    ) -> EngagementResult:
        """Create a result for a graceful shutdown."""
        logger.info("engagement.shutdown", engagement_id=engagement_id)
        return EngagementResult(
            engagement_id=engagement_id,
            target_url=target_url,
            success=False,
            exit_code=EXIT_ERROR,
            error="Engagement interrupted by signal",
            output_dir=str(output_dir),
        )

    def _install_signal_handlers(self) -> None:
        """Install SIGINT/SIGTERM handlers for graceful shutdown."""
        if threading.current_thread() is not threading.main_thread():
            return
        try:
            self._original_sigint = signal.getsignal(signal.SIGINT)
            self._original_sigterm = signal.getsignal(signal.SIGTERM)
            signal.signal(signal.SIGINT, self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)
        except (OSError, ValueError):
            pass

    def _restore_signal_handlers(self) -> None:
        """Restore original signal handlers."""
        if threading.current_thread() is not threading.main_thread():
            return
        try:
            if self._original_sigint is not None:
                signal.signal(signal.SIGINT, self._original_sigint)
            if self._original_sigterm is not None:
                signal.signal(signal.SIGTERM, self._original_sigterm)
        except (OSError, ValueError):
            pass

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Handle SIGINT/SIGTERM by setting the shutdown event."""
        sig_name = signal.Signals(signum).name
        logger.warning("engagement.signal_received", signal=sig_name)
        self._shutdown_event.set()
