"""
Kernel Runner - Main orchestration loop.

Coordinates the full cycle:
1. Load Beads state
2. Schedule ready tasks
3. Dispatch to workcells (parallel)
4. Verify results
5. Write back to Beads
6. Handle failures → create issues
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cyntra.cognition.dynamics.state_t1 import build_state_t1
from cyntra.cognition.dynamics.transition_db import TransitionDB
from cyntra.cognition.sleeptime import SleeptimeConfig, SleeptimeOrchestrator
from cyntra.cognition.strategy.profiles import DomainProfileStore
from cyntra.core.control.exploration_controller import ExplorationController
from cyntra.core.dispatcher import Dispatcher, DispatchResult
from cyntra.core.memory_integration import KernelMemoryBridge
from cyntra.core.planner_integration import KernelPlannerIntegration, PlannerSelection
from cyntra.core.ralph import RalphConfig, RalphIntegration
from cyntra.core.scheduler import (
    SchedulePlan,
    Scheduler,
    SchedulingSignals,
    SchedulingSignalsBuilder,
)
from cyntra.core.scheduler.routing import KernelConfig
from cyntra.core.sentinel import create_sentinel_scheduler_from_config
from cyntra.core.state.manager import StateManager
from cyntra.core.strategy_integration import StrategyIntegration
from cyntra.core.topology import create_topology_integration
from cyntra.core.verifier import Verifier
from cyntra.core.workcell.manager import WorkcellManager

try:
    from cyntra.core.providers.e2b.provider import E2B_AVAILABLE, E2BProvider
except ImportError:
    E2B_AVAILABLE = False
    E2BProvider = None  # type: ignore[assignment,misc]
from cyntra.infra.observability.events import EventEmitter
from cyntra.infra.observability.swarm_summary import (
    LatencyEnvelope,
    SwarmEpisode,
    WorkCategories,
)

if TYPE_CHECKING:
    from cyntra.cognition.planner.action_space import ActionSpace
    from cyntra.core.state.models import BeadsGraph, Issue

logger = structlog.get_logger()
console = Console()

ESCALATION_TAGS = {"escalation", "needs-human", "@human-escalated", "human-escalated"}


def _utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(UTC)


@dataclass(frozen=True)
class SpeculateDispatchPlan:
    candidates: list[str]
    selection: PlannerSelection
    parallelism: int


class KernelRunner:
    """
    Main kernel orchestration loop.

    Coordinates scheduling, dispatch, verification, and state updates.
    Supports both synchronous (single-threaded) and asynchronous (parallel)
    execution modes.
    """

    def __init__(
        self,
        config_path: Path | None = None,
        config: KernelConfig | None = None,
        single_cycle: bool = False,
        target_issue: str | None = None,
        universe_id: str | None = None,
        max_concurrent: int | None = None,
        force_speculate: bool = False,
        dry_run: bool = False,
        watch_mode: bool = False,
    ) -> None:
        # Load or use provided config
        if config:
            self.config = config
        elif config_path:
            self.config = KernelConfig.load(config_path)
        else:
            self.config = KernelConfig()

        self.universe_id = universe_id
        self.universe_config = None

        if universe_id:
            from cyntra.eval.universe import UniverseLoadError, load_universe

            try:
                self.universe_config = load_universe(
                    universe_id,
                    repo_root=self.config.repo_root,
                    validate_worlds=False,
                )
            except UniverseLoadError as exc:
                raise RuntimeError(str(exc)) from exc

            from cyntra.eval.universe.policy import apply_universe_policies

            apply_universe_policies(self.config, self.universe_config)

        # Apply runtime overrides
        self.config.force_speculate = force_speculate
        self.config.dry_run = dry_run
        self.config.watch_mode = watch_mode

        if max_concurrent:
            self.config.max_concurrent_workcells = max_concurrent

        self.single_cycle = single_cycle
        self.target_issue = target_issue

        # Track running tasks
        self._running_tasks: set[str] = set()

        # Initialize components
        self.state_manager = StateManager(self.config)
        self.controller = ExplorationController(self.config)

        # Memory integration (claude-mem pattern) - created early for scheduler
        self.memory_bridge = KernelMemoryBridge(
            db_path=self.config.repo_root / ".cyntra" / "memory" / "cyntra-mem.db"
        )

        # Dynamics transition DB for routing improvement - created early for scheduler
        dynamics_db_path = self.config.repo_root / ".cyntra" / "dynamics" / "cyntra.db"
        self.transition_db = TransitionDB(dynamics_db_path)
        self.strategy_integration = StrategyIntegration(self.transition_db)

        # Domain profiles for token estimation and toolchain preferences
        profiles_cache_dir = self.config.repo_root / ".cyntra" / "strategy"
        self.domain_profile_store = DomainProfileStore(
            transition_db=self.transition_db,
            cache_dir=profiles_cache_dir,
        )
        self.domain_profile_store.rebuild()

        # Scheduler (pure core) and signals builder
        learned_context_dir = self.config.repo_root / ".cyntra" / "learned_context"
        self.scheduler = Scheduler(
            self.config,
            transition_db=self.transition_db,
            domain_profiles=self.domain_profile_store,
        )
        self.scheduling_signals_builder = SchedulingSignalsBuilder(
            config=self.config,
            controller=self.controller,
            transition_db=self.transition_db,
            learned_context_dir=learned_context_dir,
        )

        self.dispatcher = Dispatcher(self.config, controller=self.controller)
        self.topology_integration = create_topology_integration(
            self.config,
            dispatcher=self.dispatcher,
            transition_db=self.transition_db,
        )
        self.verifier = Verifier(self.config)
        self.planner_integration = KernelPlannerIntegration(self.config)
        self.workcell_manager = WorkcellManager(self.config, self.config.repo_root)

        # E2B cloud sandbox provider (optional)
        self.e2b_provider: E2BProvider | None = None
        if E2B_AVAILABLE:
            e2b_config = getattr(self.config, "e2b", None)
            if e2b_config is not None:
                # Convert E2BConfig dataclass to dict for provider
                if hasattr(e2b_config, "template"):
                    e2b_dict = {
                        "template": e2b_config.template,
                        "timeout": e2b_config.timeout,
                    }
                else:
                    e2b_dict = dict(e2b_config) if isinstance(e2b_config, dict) else {}
                try:
                    self.e2b_provider = E2BProvider(e2b_dict)
                    logger.info("E2B provider initialized", available=True)
                except Exception as e:
                    logger.warning("E2B provider initialization failed", error=str(e))

        # Sleeptime orchestrator for background consolidation
        sleeptime_config = SleeptimeConfig()
        if hasattr(self.config, "sleeptime") and self.config.sleeptime:
            sleeptime_config = SleeptimeConfig.from_dict(self.config.sleeptime)
        self.sleeptime = SleeptimeOrchestrator(
            config=sleeptime_config,
            repo_root=self.config.repo_root,
        )

        # Ralph integration for autonomous loop features (Full-Scale Ralph)
        ralph_config = RalphConfig()
        if hasattr(self.config, "ralph") and self.config.ralph:
            ralph_config = RalphConfig.from_dict(self.config.ralph)
        self.ralph = RalphIntegration(
            config=ralph_config,
            repo_root=self.config.repo_root,
            memory_bridge=self.memory_bridge,
            transition_db=self.transition_db,
        )

        # Sentinel scheduler for periodic background agents
        self.sentinel_scheduler = create_sentinel_scheduler_from_config(
            sentinels_config=self.config.sentinels,
            repo_root=self.config.repo_root,
        )

        # Track from_state for each workcell
        self._workcell_from_states: dict[str, dict] = {}

        # Track dispatch start times for swarm episode emission
        self._dispatch_start_times: dict[str, float] = {}

        # Event emitter for swarm episodes
        self._event_emitter = EventEmitter(self.config.logs_dir)

        self._running = False
        self._cycle_count = 0
        self._cycle_start_time: float | None = None
        self._stats = {
            "issues_completed": 0,
            "issues_failed": 0,
            "total_duration_ms": 0,
        }

    def _should_use_e2b(self, issue: Issue) -> bool:
        """
        Determine if an issue should be executed in an E2B cloud sandbox.

        Checks (in order):
        1. E2B provider must be available
        2. Issue has 'e2b' or 'cloud' tag
        3. Config has workcell_provider='e2b'
        """
        if not self.e2b_provider:
            return False

        # Check issue tags for e2b hint
        tags = issue.tags or []
        if "e2b" in tags or "cloud" in tags or "dk_provider:e2b" in tags:
            return True

        # Check config for default provider
        workcell_provider = getattr(self.config, "workcell_provider", "local")
        if workcell_provider == "e2b":
            return True

        return False

    def run(self) -> None:
        """Run the kernel loop (synchronous entry point)."""
        asyncio.run(self.run_async())

    async def run_async(self) -> None:
        """Run the kernel loop asynchronously."""
        self._running = True

        console.print("\n[bold blue]Cyntra[/bold blue] starting...")
        console.print(f"[dim]Config:[/dim] {self.config.config_path}")
        console.print(f"[dim]Mode:[/dim] {'dry-run' if self.config.dry_run else 'live'}")
        console.print(f"[dim]Max Concurrent:[/dim] {self.config.max_concurrent_workcells}")

        available = self.dispatcher.get_available_toolchains()
        console.print(f"[dim]Toolchains:[/dim] {', '.join(available) if available else 'none'}")

        if self.target_issue:
            console.print(f"[dim]Target:[/dim] Issue #{self.target_issue}")

        console.print()

        try:
            while self._running:
                self._cycle_count += 1
                self._cycle_start_time = time.time()
                logger.info("Starting kernel cycle", cycle=self._cycle_count)

                # Wrap cycle execution to prevent kernel crash on unexpected errors
                try:
                    had_work = await self._run_cycle()
                except Exception:
                    logger.exception(
                        "Kernel cycle failed unexpectedly",
                        cycle=self._cycle_count,
                    )
                    console.print(
                        f"[red]✗[/red] Cycle {self._cycle_count} failed - see logs"
                    )
                    # Continue to next cycle (or exit if single_cycle)
                    had_work = False

                if self.single_cycle:
                    console.print("\n[green]✓[/green] Single cycle complete")
                    break

                if not had_work and not self.config.watch_mode:
                    console.print("\n[green]✓[/green] No more ready work")
                    break

                if self.config.watch_mode:
                    console.print("[dim]Waiting for Beads changes...[/dim]")

                    # Notify sentinel scheduler that kernel is idle
                    self.sentinel_scheduler.set_kernel_idle(True)

                    # Sleeptime idle consolidation: in watch mode the kernel can sit
                    # idle indefinitely, so we proactively check triggers here to
                    # keep PSN canary/backlog generation running on schedule.
                    try:
                        if self.sleeptime.should_trigger():
                            consolidation_result = self.sleeptime.consolidate()
                            if consolidation_result and consolidation_result.success:
                                # Reload controller's dynamics report after consolidation
                                self.controller._report = self.controller._load_report()
                    except Exception:
                        logger.exception("Sleeptime idle consolidation failed")

                    # Run due sentinels during idle time
                    try:
                        if self.sentinel_scheduler.should_run_any():
                            sentinel_results = await self.sentinel_scheduler.run_due_sentinels()
                            for result in sentinel_results:
                                if result.success:
                                    logger.info(
                                        "sentinel_completed",
                                        name=result.sentinel_name,
                                        changes=result.change_count,
                                        dry_run=result.dry_run,
                                    )
                                else:
                                    logger.warning(
                                        "sentinel_failed",
                                        name=result.sentinel_name,
                                        error=result.error,
                                    )
                    except Exception:
                        logger.exception("Sentinel execution failed")

                    await asyncio.sleep(5)

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted[/yellow]")
            self._running = False
            self.ralph.on_interrupt()

        self._display_summary()

    async def _run_cycle(self) -> bool:
        """
        Execute one scheduling cycle.

        Returns True if work was dispatched.
        """
        # Load current state
        graph = self.state_manager.load_beads_graph()
        if self._reconcile_running_issues(graph):
            graph = self.state_manager.load_beads_graph()

        if not graph.issues:
            console.print("[yellow]No issues found in Beads[/yellow]")
            return False

        # Filter to target issue if specified
        if self.target_issue:
            graph = graph.filter_to_issue(self.target_issue)
            if not graph.issues:
                console.print(f"[yellow]Issue #{self.target_issue} not found[/yellow]")
                return False

        # Build scheduling signals and plan
        cycle_started_at = _utc_now()
        signals = self.scheduling_signals_builder.build(
            graph=graph,
            running_task_ids=self._running_tasks,
            cycle_started_at=cycle_started_at,
        )

        ready_set = self.scheduler.compute_ready_set(graph, signals.running_task_ids)
        critical_path = self.scheduler.compute_critical_path(graph)

        history_candidates: list[dict[str, Any]] = []
        speculate_plans: dict[str, SpeculateDispatchPlan] = {}

        if self.config.speculation.enabled and ready_set:
            should_speculate = any(
                self.scheduler.should_speculate(issue, critical_path) for issue in ready_set
            )
            if should_speculate:
                from cyntra.cognition.planner.artifacts import collect_history_candidates

                history_candidates = collect_history_candidates(
                    repo_root=self.config.repo_root,
                    include_world=False,
                )
                signals, speculate_plans = self._cap_speculate_parallelism(
                    ready_set=ready_set,
                    critical_path=critical_path,
                    signals=signals,
                    history_candidates=history_candidates,
                )

        plan = self.scheduler.schedule(graph, signals)

        if not plan.scheduled:
            if self.target_issue and self.single_cycle:
                issue = next(
                    (i for i in graph.issues if i.id == self.target_issue),
                    None,
                )
                if issue:
                    reason = self._explain_not_ready(issue, graph)
                    console.print(
                        f"[yellow]Target issue not ready ({reason}); forcing one-shot run[/yellow]"
                    )
                    if not history_candidates:
                        from cyntra.cognition.planner.artifacts import collect_history_candidates

                        history_candidates = collect_history_candidates(
                            repo_root=self.config.repo_root,
                            include_world=False,
                        )
                    await self._dispatch_single_async(
                        issue,
                        history_candidates=history_candidates,
                        signals=signals,
                    )
                    return True
            console.print("[dim]Nothing ready to schedule[/dim]")
            return False

        if not history_candidates:
            from cyntra.cognition.planner.artifacts import collect_history_candidates

            history_candidates = collect_history_candidates(
                repo_root=self.config.repo_root,
                include_world=False,
            )

        # Display schedule
        self._display_schedule(plan, graph)

        if self.config.dry_run:
            console.print("\n[yellow]Dry run - no changes made[/yellow]")
            return True

        # Kernel is now busy - reset idle state for sentinels
        self.sentinel_scheduler.set_kernel_idle(False)

        # Track stats before dispatch to compute cycle-level delta
        pre_completed = self._stats["issues_completed"]
        pre_failed = self._stats["issues_failed"]
        scheduled_count = len(plan.scheduled)

        # Dispatch work in parallel
        await self._dispatch_parallel(
            plan,
            graph,
            history_candidates=history_candidates,
            speculate_plans=speculate_plans,
            signals=signals,
        )

        # Emit swarm cycle episode
        cycle_completed = self._stats["issues_completed"] - pre_completed
        cycle_failed = self._stats["issues_failed"] - pre_failed
        self._emit_swarm_cycle_episode(
            cycle_number=self._cycle_count,
            scheduled=scheduled_count,
            completed=cycle_completed,
            failed=cycle_failed,
        )

        return True

    def _cap_speculate_parallelism(
        self,
        *,
        ready_set: list[Issue],
        critical_path: list[Issue],
        signals: SchedulingSignals,
        history_candidates: list[dict[str, Any]],
    ) -> tuple[SchedulingSignals, dict[str, SpeculateDispatchPlan]]:
        if not ready_set:
            return signals, {}

        from cyntra.core.routing import speculate_parallelism as routing_parallelism

        capped_parallelism = dict(signals.speculate_parallelism)
        speculate_plans: dict[str, SpeculateDispatchPlan] = {}

        for issue in ready_set:
            if not self.scheduler.should_speculate(issue, critical_path):
                continue
            requested = capped_parallelism.get(issue.id)
            if requested is None:
                requested = routing_parallelism(self.config, issue)
            dispatch_plan = self._build_speculate_dispatch_plan(
                issue,
                requested_parallelism=requested,
                history_candidates=history_candidates,
            )
            if not dispatch_plan:
                continue
            speculate_plans[issue.id] = dispatch_plan
            if dispatch_plan.parallelism < requested:
                capped_parallelism[issue.id] = dispatch_plan.parallelism

        if capped_parallelism == signals.speculate_parallelism:
            return signals, speculate_plans

        return replace(signals, speculate_parallelism=capped_parallelism), speculate_plans

    def _explain_not_ready(self, issue: Issue, graph: BeadsGraph) -> str:
        reasons: list[str] = []
        if issue.status not in ("open", "ready"):
            reasons.append(f"status={issue.status}")
        if issue.dk_attempts >= issue.dk_max_attempts:
            reasons.append(f"attempts={issue.dk_attempts}/{issue.dk_max_attempts}")
        if any(tag in ESCALATION_TAGS for tag in (issue.tags or [])):
            reasons.append("escalated")
        blockers = [b.id for b in graph.get_blocking_deps(issue.id) if b.status != "done"]
        if blockers:
            reasons.append(f"blocked_by={','.join(blockers[:3])}")
        return "; ".join(reasons) if reasons else "unspecified"

    async def _dispatch_parallel(
        self,
        plan: SchedulePlan,
        graph: BeadsGraph,
        *,
        history_candidates: list[dict[str, Any]],
        speculate_plans: dict[str, SpeculateDispatchPlan] | None = None,
        signals: SchedulingSignals | None = None,
    ) -> None:
        """Dispatch all scheduled work in parallel."""
        issue_by_id = {issue.id: issue for issue in graph.issues}
        speculate_plans = speculate_plans or {}

        # Create tasks for all dispatches
        tasks = []

        for issue_plan in plan.scheduled:
            issue = issue_by_id.get(issue_plan.issue_id)
            if not issue:
                logger.warning(
                    "Scheduled issue missing from graph",
                    issue_id=issue_plan.issue_id,
                )
                continue
            if self.topology_integration and self.topology_integration.should_use_topology(issue):
                tasks.append(
                    self._dispatch_topology_async(
                        issue,
                        history_candidates=history_candidates,
                        signals=signals,
                    )
                )
                continue
            if issue_plan.run_mode == "speculate":
                dispatch_plan = speculate_plans.get(issue_plan.issue_id)
                tasks.append(
                    self._dispatch_speculate_async(
                        issue,
                        parallelism=issue_plan.parallelism,
                        history_candidates=history_candidates,
                        dispatch_plan=dispatch_plan,
                    )
                )
            else:
                tasks.append(
                    self._dispatch_single_async(
                        issue,
                        history_candidates=history_candidates,
                        signals=signals,
                    )
                )

        # Run all in parallel
        if tasks:
            console.print(f"\n[cyan]Dispatching {len(tasks)} task(s) in parallel...[/cyan]")
            await asyncio.gather(*tasks)

    async def _dispatch_e2b_async(
        self,
        issue: Issue,
        history_candidates: list[dict[str, Any]],
        signals: SchedulingSignals | None = None,
    ) -> None:
        """Dispatch an issue to E2B cloud sandbox."""
        if not self.e2b_provider:
            logger.error("E2B provider not available", issue_id=issue.id)
            return

        e2b_workcell_id = f"e2b-{issue.id}-{int(time.time() * 1000)}"
        toolchain = self.dispatcher._route_toolchain(issue)

        self._dispatch_start_times[e2b_workcell_id] = time.time()
        self._running_tasks.add(issue.id)

        try:
            self.state_manager.update_issue_status(
                issue.id, "running", workcell_id=e2b_workcell_id, toolchain=f"e2b:{toolchain}"
            )
            self.state_manager.add_event(
                issue.id,
                "issue.started",
                {"provider": "e2b", "toolchain": toolchain},
            )

            # Build manifest for E2B execution
            from datetime import timedelta

            from cyntra.core.manifests.schema import RuntimeConfig, TaskSpec, ToolchainManifest
            from cyntra.core.providers.base import ExecutionContext

            task_spec = TaskSpec(
                issue_id=issue.id,
                title=issue.title,
                description=issue.description or "",
                repo_url=None,  # E2B will clone from current repo
                branch=None,
            )

            runtime_config = RuntimeConfig(
                timeout=timedelta(seconds=1800),
                max_retries=1,
            )

            manifest = ToolchainManifest(
                manifest_id=e2b_workcell_id,
                task=task_spec,
                runtime=runtime_config,
                toolchain=toolchain,
                provider_hint="e2b",
            )

            # Create execution context
            context = ExecutionContext(
                run_id=e2b_workcell_id,
                step_id="main",
                artifact_store=None,
            )

            # Execute in E2B sandbox
            logger.info(
                "Executing in E2B sandbox",
                issue_id=issue.id,
                workcell_id=e2b_workcell_id,
            )

            result = await self.e2b_provider.execute(manifest, context)

            # Handle result
            if result.status == "completed":
                # E2B sandbox completed - run kernel-level verification
                # before marking as done. The E2B provider runs gates in-sandbox,
                # but we still need the Verifier to enforce kernel-level policies
                # (forbidden paths, gate normalization, proof persistence).
                verified = await self._verify_e2b_result(
                    issue, result, e2b_workcell_id, toolchain
                )
                if verified:
                    console.print(f"  [green]✓[/green] #{issue.id} completed in E2B (verified)")
                    self.state_manager.update_issue_status(issue.id, "done")
                    self.state_manager.add_event(
                        issue.id,
                        "issue.completed",
                        {"provider": "e2b", "exit_code": result.exit_code, "verified": True},
                    )
                    self._stats["issues_completed"] += 1

                    # Record success in Ralph with concrete file-change evidence.
                    files_changed_for_ralph: list[str] = []
                    if isinstance(result.proof, dict):
                        patch = result.proof.get("patch")
                        if isinstance(patch, dict):
                            raw_files = patch.get("files_modified")
                            if isinstance(raw_files, list):
                                files_changed_for_ralph = [str(path) for path in raw_files if path]
                    self.ralph.after_dispatch(
                        issue=issue,
                        toolchain=f"e2b:{toolchain}",
                        success=True,
                        files_changed=files_changed_for_ralph,
                    )
                    self.ralph.on_success(issue)
                else:
                    # Verification failed - treat like a gate failure
                    console.print(
                        f"  [red]✗[/red] #{issue.id} E2B execution succeeded "
                        f"but verification failed"
                    )
                    self._handle_e2b_failure(
                        issue,
                        e2b_workcell_id,
                        error_summary="Kernel verification failed after E2B execution",
                        result=result,
                    )
            elif result.status == "gate_failed":
                # E2B provider detected gate failure in-sandbox
                console.print(
                    f"  [red]✗[/red] #{issue.id} failed quality gates in E2B"
                )
                gate_summary = ""
                if result.proof and isinstance(result.proof, dict):
                    verification = result.proof.get("verification", {})
                    blocking = verification.get("blocking_failures", [])
                    if blocking:
                        gate_summary = f"Gate failures: {', '.join(str(b) for b in blocking)}"
                self._handle_e2b_failure(
                    issue,
                    e2b_workcell_id,
                    error_summary=gate_summary or f"E2B gate_failed",
                    result=result,
                )
            else:
                console.print(f"  [red]✗[/red] #{issue.id} failed in E2B: {result.status}")
                self._handle_e2b_failure(
                    issue,
                    e2b_workcell_id,
                    error_summary=f"E2B:{result.status}",
                    result=result,
                )

        except Exception as e:
            logger.exception("E2B dispatch failed", issue_id=issue.id, error=str(e))
            console.print(f"  [red]✗[/red] #{issue.id} E2B error: {e}")
            self.state_manager.update_issue_status(issue.id, "ready")
            self.state_manager.add_event(
                issue.id,
                "issue.failed",
                {"provider": "e2b", "error": str(e)},
            )
            self._stats["issues_failed"] += 1

        finally:
            self._running_tasks.discard(issue.id)
            self._dispatch_start_times.pop(e2b_workcell_id, None)

    async def _verify_e2b_result(
        self,
        issue: Issue,
        result: Any,
        e2b_workcell_id: str,
        toolchain: str,
    ) -> bool:
        """Run kernel-level verification on an E2B execution result.

        Constructs a PatchProof from the E2B provider's proof dict and
        runs it through the Verifier. Uses a temporary directory as the
        workcell path since E2B has no local worktree.

        Returns True if verification passes.
        """
        import tempfile

        from cyntra.core.adapters.base import PatchProof

        e2b_proof = result.proof if isinstance(result.proof, dict) else {}
        verification = e2b_proof.get("verification", {})

        proof = PatchProof(
            schema_version="1.0",
            workcell_id=e2b_workcell_id,
            issue_id=issue.id,
            status="success",
            patch=e2b_proof.get("patch", {}),
            verification=verification,
            metadata={
                "provider": "e2b",
                "toolchain": toolchain,
                "exit_code": e2b_proof.get("exit_code", 0),
                "sandbox_id": e2b_proof.get("sandbox_id"),
            },
        )

        # The Verifier requires a workcell_path (used for proof persistence
        # and as working directory for gates). Create a temp directory since
        # E2B runs remotely and has no local worktree.
        tmp_dir = None
        try:
            tmp_dir = Path(tempfile.mkdtemp(prefix=f"e2b-verify-{issue.id}-"))
            verified = await self.verifier.verify_async(proof, tmp_dir)
            return verified
        except Exception:
            logger.exception(
                "E2B verification raised an exception",
                issue_id=issue.id,
                workcell_id=e2b_workcell_id,
            )
            return False
        finally:
            # Clean up temp directory
            if tmp_dir and tmp_dir.exists():
                import shutil

                shutil.rmtree(tmp_dir, ignore_errors=True)

    def _handle_e2b_failure(
        self,
        issue: Issue,
        e2b_workcell_id: str,
        error_summary: str,
        result: Any = None,
    ) -> None:
        """Handle an E2B dispatch or verification failure.

        Mirrors the failure handling in _handle_failure but without
        requiring a local workcell path. Increments attempts, logs
        events, and either re-queues or escalates the issue.
        """
        self._stats["issues_failed"] += 1

        # Increment attempt counter
        current_attempts = self.state_manager.increment_attempts(issue.id)

        # Log failure events
        self.state_manager.add_event(
            issue.id,
            "workcell.failed",
            {
                "provider": "e2b",
                "toolchain": f"e2b",
                "error": error_summary or "Unknown error",
                "attempt": current_attempts,
            },
            workcell_id=e2b_workcell_id,
        )
        self.state_manager.add_event(
            issue.id,
            "issue.failed",
            {
                "provider": "e2b",
                "error": error_summary or "Unknown error",
                "attempt": current_attempts,
            },
        )

        # Record failure in Ralph
        self.ralph.after_dispatch(
            issue=issue,
            toolchain="e2b",
            success=False,
            error=error_summary,
        )
        self.ralph.on_failure(issue, error_summary)

        # Escalate or re-queue
        if current_attempts >= issue.dk_max_attempts:
            self.state_manager.update_issue_status(issue.id, "escalated")
            console.print(
                f"  [yellow]⚠[/yellow] #{issue.id} escalated "
                f"(max attempts reached after E2B failure)"
            )
        else:
            self.state_manager.update_issue_status(issue.id, "ready")
            console.print(
                f"  [dim]Attempt {current_attempts}/{issue.dk_max_attempts}[/dim]"
            )

    async def _dispatch_topology_async(
        self,
        issue: Issue,
        *,
        history_candidates: list[dict[str, Any]],
        signals: SchedulingSignals | None = None,
    ) -> None:
        """Dispatch a topology execution for an issue (HSM path)."""
        if not self.topology_integration:
            await self._dispatch_single_async(
                issue,
                history_candidates=history_candidates,
                signals=signals,
                allow_topology=False,
            )
            return

        topology = self.topology_integration.plan_topology(issue, signals)
        if not topology:
            logger.info(
                "Topology template not found; falling back to standard dispatch",
                issue_id=issue.id,
            )
            self.state_manager.add_event(
                issue.id,
                "topology.skipped",
                {"reason": "no_template"},
            )
            await self._dispatch_single_async(
                issue,
                history_candidates=history_candidates,
                signals=signals,
                allow_topology=False,
            )
            return

        toolchain_hint = "topology"
        ralph_decision = self.ralph.before_dispatch(issue, toolchain_hint)
        if not ralph_decision.allow:
            if ralph_decision.should_exit:
                console.print(f"[yellow]Ralph exit:[/yellow] {ralph_decision.exit_reason}")
                self._running = False
                return
            if ralph_decision.wait_seconds > 0:
                from cyntra.core.rate_limiter import format_wait_time

                console.print(
                    f"[yellow]Rate limited:[/yellow] {ralph_decision.reason} "
                    f"(wait {format_wait_time(ralph_decision.wait_seconds)})"
                )
                await asyncio.sleep(min(ralph_decision.wait_seconds, 60))
                return

        console.print(
            f"\n[cyan]Dispatching topology[/cyan] #{issue.id}: {issue.title} "
            f"(topology={topology.name})"
        )

        topology_workcell_id = f"topology-{issue.id}-{int(time.time() * 1000)}"
        from_state = self._build_from_state(issue, topology_workcell_id, toolchain_hint)
        self._workcell_from_states[topology_workcell_id] = from_state

        # Track dispatch start time for swarm episode emission
        self._dispatch_start_times[topology_workcell_id] = time.time()

        self._running_tasks.add(issue.id)
        try:
            self.state_manager.update_issue_status(
                issue.id, "running", workcell_id=topology_workcell_id
            )
            self.state_manager.add_event(
                issue.id,
                "issue.started",
                {"topology": topology.name, "mode": "hsm"},
            )
            self.state_manager.add_event(
                issue.id,
                "topology.started",
                {
                    "topology": topology.name,
                    "phase_count": len(topology.phases),
                    "mode": "hsm",
                },
            )

            initial_context = {
                "issue_id": issue.id,
                "issue_title": issue.title,
                "issue_description": issue.description or "",
                "issue_tags": issue.tags or [],
            }

            try:
                topology_result = await self.topology_integration.execute_topology(
                    topology,
                    issue,
                    initial_context=initial_context,
                )
            except Exception:
                logger.exception(
                    "Topology execution failed unexpectedly",
                    issue_id=issue.id,
                    topology=topology.name,
                    workcell_id=topology_workcell_id,
                )
                # Create a failure result so normal failure handling runs
                from types import SimpleNamespace

                topology_result = SimpleNamespace(
                    success=False,
                    error=f"Unexpected exception in topology execution",
                    total_duration_ms=0,
                    total_tokens=0,
                    final_output=None,
                    all_files_written=[],
                )

            duration_ms = int(getattr(topology_result, "total_duration_ms", 0) or 0)
            tokens_used = int(getattr(topology_result, "total_tokens", 0) or 0)
            dispatch_result = DispatchResult(
                success=topology_result.success,
                proof=None,
                workcell_id=topology_workcell_id,
                issue_id=issue.id,
                toolchain=toolchain_hint,
                duration_ms=duration_ms,
                error=topology_result.error,
            )

            if topology_result.success:
                self._stats["issues_completed"] += 1
                self._stats["total_duration_ms"] += duration_ms

                self._record_transition(
                    topology_workcell_id,
                    issue,
                    dispatch_result,
                    verified=True,
                )

                self.state_manager.update_issue_status(issue.id, "done")
                self.state_manager.add_event(
                    issue.id,
                    "topology.completed",
                    {
                        "topology": topology.name,
                        "duration_ms": duration_ms,
                        "total_tokens": tokens_used,
                        "phase_count": len(topology.phases),
                        "files_written": topology_result.all_files_written,
                    },
                )
                self.state_manager.add_event(
                    issue.id,
                    "issue.completed",
                    {
                        "toolchain": toolchain_hint,
                        "duration_ms": duration_ms,
                    },
                )

                files_changed_for_ralph: list[str] = []
                raw_files = getattr(topology_result, "all_files_written", None)
                if isinstance(raw_files, list):
                    files_changed_for_ralph = [str(path) for path in raw_files if path]

                self.ralph.after_dispatch(
                    issue=issue,
                    toolchain=toolchain_hint,
                    success=True,
                    response_text=str(topology_result.final_output or ""),
                    files_changed=files_changed_for_ralph,
                    tokens_used=tokens_used,
                )
                self.ralph.on_success(issue)

                consolidation_result = self.sleeptime.on_workcell_complete(success=True)
                if consolidation_result and consolidation_result.success:
                    self.controller._report = self.controller._load_report()
                    self.sleeptime.notify_ralph(self.ralph, consolidation_result)

                # Emit swarm episode for successful topology dispatch
                self._emit_swarm_episode(
                    workcell_id=topology_workcell_id,
                    issue_id=issue.id,
                    success=True,
                    duration_ms=duration_ms,
                    toolchain=toolchain_hint,
                )
            else:
                await self._handle_topology_failure(
                    issue=issue,
                    dispatch_result=dispatch_result,
                    topology_result=topology_result,
                    workcell_id=topology_workcell_id,
                )
        finally:
            self._running_tasks.discard(issue.id)
            self._workcell_from_states.pop(topology_workcell_id, None)

    async def _dispatch_single_async(
        self,
        issue: Issue,
        *,
        history_candidates: list[dict[str, Any]],
        signals: SchedulingSignals | None = None,
        allow_topology: bool = True,
    ) -> None:
        """Dispatch a single workcell for an issue asynchronously."""
        if (
            allow_topology
            and self.topology_integration
            and self.topology_integration.should_use_topology(issue)
        ):
            await self._dispatch_topology_async(
                issue,
                history_candidates=history_candidates,
                signals=signals,
            )
            return
        # Ralph: check circuit breaker and rate limits before dispatch
        toolchain_hint = self.dispatcher._route_toolchain(issue)
        ralph_decision = self.ralph.before_dispatch(issue, toolchain_hint)
        if not ralph_decision.allow:
            if ralph_decision.should_exit:
                console.print(f"[yellow]Ralph exit:[/yellow] {ralph_decision.exit_reason}")
                self._running = False
                return
            if ralph_decision.wait_seconds > 0:
                from cyntra.core.rate_limiter import format_wait_time

                console.print(
                    f"[yellow]Rate limited:[/yellow] {ralph_decision.reason} "
                    f"(wait {format_wait_time(ralph_decision.wait_seconds)})"
                )
                await asyncio.sleep(min(ralph_decision.wait_seconds, 60))
                return

        console.print(f"\n[cyan]Dispatching[/cyan] #{issue.id}: {issue.title}")

        # Check if this issue should use E2B cloud sandbox
        if self._should_use_e2b(issue):
            console.print(f"  [dim]Provider:[/dim] E2B cloud sandbox")
            await self._dispatch_e2b_async(issue, history_candidates, signals)
            return

        workcell_path = None
        workcell_id = None

        # Create workcell BEFORE marking as running to prevent race condition
        # If creation fails, issue won't be in _running_tasks and can be rescheduled
        try:
            suggested_template = self.workcell_manager.suggest_template(
                domain=self._infer_domain(issue),
                tags=issue.tags,
            )
            workcell_path = self.workcell_manager.create(issue.id, template=suggested_template)
        except Exception as exc:
            self._handle_workcell_create_failure(issue, exc)
            return
        workcell_id = workcell_path.name

        # Track dispatch start time for swarm episode emission
        self._dispatch_start_times[workcell_id] = time.time()

        # Only mark as running AFTER workcell creation succeeds
        self._running_tasks.add(issue.id)

        # Determine toolchain for this dispatch
        toolchain = self.dispatcher._route_toolchain(issue)

        try:

            # Update issue status (uses ephemeral state to avoid dirtying repo)
            self.state_manager.update_issue_status(
                issue.id, "running", workcell_id=workcell_id, toolchain=toolchain
            )

            self.state_manager.add_event(
                issue.id,
                "issue.started",
                {"speculate": False},
            )

            planner_universe_id, planner_universe_defaults, planner_action_space = (
                self._planner_universe_context()
            )
            from cyntra.cognition.planner.artifacts import system_state_snapshot

            now_ms = int(time.time() * 1000)
            system_state = system_state_snapshot(
                active_workcells=len(self._running_tasks),
                queue_depth=None,
                available_toolchains=self.dispatcher.get_available_toolchains(),
                now_ms=now_ms,
            )
            toolchain_cfg = self.config.toolchains.get(toolchain)
            timeout_seconds = (
                int(getattr(toolchain_cfg, "timeout_seconds", 1800))
                if toolchain_cfg is not None
                else 1800
            )
            job_type = "fab-world" if "asset:world" in (issue.tags or []) else "code"

            selection = self.planner_integration.decide(
                issue=issue,
                job_type=job_type,
                universe_id=planner_universe_id,
                universe_defaults=planner_universe_defaults,
                action_space=planner_action_space,
                history_candidates=history_candidates,
                system_state=system_state,
                now_ms=now_ms,
                baseline_swarm_id="serial_handoff",
                baseline_max_candidates=1,
                baseline_timeout_cap_seconds=int(timeout_seconds),
                max_iterations=None,
            )
            planner_bundle = self.planner_integration.build_manifest_planner_bundle(
                selection=selection,
                swarm_id_executed="serial_handoff",
                timeout_seconds_default=int(timeout_seconds),
                max_iterations_executed=None,
            )

            # Dynamics: capture from_state before execution
            from_state = self._build_from_state(issue, workcell_id, toolchain)
            self._workcell_from_states[workcell_id] = from_state

            self.state_manager.add_event(
                issue.id,
                "workcell.created",
                {
                    "toolchain": toolchain,
                    "speculate_tag": None,
                },
                workcell_id=workcell_id,
            )
            self.state_manager.add_event(
                issue.id,
                "workcell.started",
                {"toolchain": toolchain},
                workcell_id=workcell_id,
            )

            # Memory: start session and get context for injection
            manifest_base = self.dispatcher._build_manifest(issue, workcell_id, toolchain, None)
            strategy_event: dict[str, Any] = {}
            strategy_cfg = manifest_base.get("strategy")
            if isinstance(strategy_cfg, dict) and strategy_cfg.get("enabled") is True:
                strategy_event["strategy_enabled"] = True
                routing_cfg = strategy_cfg.get("routing")
                if isinstance(routing_cfg, dict):
                    strategy_event["strategy_bucket"] = routing_cfg.get("ab_bucket")
                    strategy_event["strategy_bucket_value"] = routing_cfg.get("ab_bucket_value")
                directive_cfg = strategy_cfg.get("directive")
                if isinstance(directive_cfg, dict):
                    strategy_event["strategy_directive_id"] = directive_cfg.get("directive_hash")
                    strategy_event["strategy_directive_source"] = directive_cfg.get("source")

                # Re-log key lifecycle markers with strategy metadata for dashboards.
                self.state_manager.add_event(
                    issue.id,
                    "strategy.routing",
                    strategy_event,
                    workcell_id=workcell_id,
                )
            # Memory integration is optional - continue dispatch if memory fails
            try:
                memory_context = self.memory_bridge.on_workcell_start(
                    workcell_id=workcell_id,
                    issue=issue,
                    manifest=manifest_base,
                )
            except Exception:
                logger.warning(
                    "Memory bridge on_workcell_start failed, continuing without memory context",
                    workcell_id=workcell_id,
                    issue_id=issue.id,
                )
                memory_context = None

            # Fetch learned context from sleeptime consolidation
            learned_context = None
            try:
                learned_context = self.sleeptime.get_learned_context()
            except Exception:
                logger.warning(
                    "Failed to fetch learned context",
                    issue_id=issue.id,
                )

            if learned_context:
                if memory_context is None:
                    memory_context = {}
                # Cap each block to avoid oversized manifests
                memory_context["learned_patterns"] = {
                    k: v[:2000] for k, v in learned_context.items()
                }

            # Knowledge graph context injection (best-effort).
            try:
                job_type = manifest_base.get("job_type") if isinstance(manifest_base, dict) else None
                if not isinstance(job_type, str) or not job_type.strip():
                    job_type = "code"
                kg_context = self._render_knowledge_graph_context(
                    issue=issue,
                    toolchain=toolchain,
                    job_type=job_type,
                )
            except Exception:
                kg_context = None

            if kg_context:
                if memory_context is None:
                    memory_context = {}
                # Cap to avoid oversized manifests.
                memory_context["knowledge_graph_context"] = kg_context[:4000]

            # Run toolchain via async dispatch (pass memory context for injection)
            result = await self.dispatcher.dispatch_async(
                issue,
                workcell_path,
                memory_context=memory_context,
                manifest_overrides={"planner": planner_bundle},
            )

            # Memory: parse telemetry for tool observations
            if workcell_path:
                try:
                    self.memory_bridge.on_dispatch_complete(
                        workcell_id=workcell_id,
                        workcell_path=workcell_path,
                        proof=result.proof,
                    )
                except Exception:
                    logger.warning(
                        "Memory bridge on_dispatch_complete failed",
                        workcell_id=workcell_id,
                    )

            if result.success and result.proof:
                # Verify
                verified = await self.verifier.verify_async(result.proof, workcell_path)

                # Strategy telemetry: extract + store profile after verification.
                self._maybe_store_strategy_profile(
                    workcell_id=workcell_id,
                    workcell_path=workcell_path,
                    issue=issue,
                    proof=result.proof,
                    toolchain=result.toolchain,
                    verified=verified,
                )

                # Memory: record gate results
                if result.proof and isinstance(result.proof.verification, dict):
                    gates = result.proof.verification.get("gates", {})
                    for gate_name, gate_result in gates.items():
                        if isinstance(gate_result, dict):
                            self.memory_bridge.on_gate_result(
                                gate_name=gate_name,
                                passed=gate_result.get("passed", False),
                                score=gate_result.get("score"),
                                fail_codes=gate_result.get("fail_codes", []),
                            )

                if verified:
                    outcome = await self._handle_success(issue, result, workcell_path)
                    merge_error = None
                    if outcome == "merge_failed" and result.proof and isinstance(
                        result.proof.patch, dict
                    ):
                        merge_error = result.proof.patch.get("merge_error")

                    memory_status = (
                        "success"
                        if outcome == "completed"
                        else "review_required"
                        if outcome == "review_required"
                        else "merge_failed"
                    )
                    success_for_ralph = outcome in {"completed", "review_required"}

                    # Memory: end session
                    self.memory_bridge.on_workcell_end(workcell_id, memory_status)
                    # Ralph: record outcome (Full-Scale Ralph)
                    tokens_used = 0
                    if result.proof and result.proof.metadata:
                        tokens_used = int(result.proof.metadata.get("tokens_used") or 0)
                    # Get state_id and session_id for dynamics/memory integration
                    from_state = self._workcell_from_states.get(workcell_id, {})
                    state_id = from_state.get("state_id")
                    session_id = self.memory_bridge.get_session_id(workcell_id)
                    files_changed_for_ralph: list[str] = []
                    if result.proof and isinstance(result.proof.patch, dict):
                        raw_files = result.proof.patch.get("files_modified")
                        if isinstance(raw_files, list):
                            files_changed_for_ralph = [str(path) for path in raw_files if path]

                    self.ralph.after_dispatch(
                        issue=issue,
                        toolchain=result.toolchain,
                        success=success_for_ralph,
                        files_changed=files_changed_for_ralph,
                        error=merge_error,
                        tokens_used=tokens_used,
                        state_id=state_id,
                        session_id=session_id,
                    )
                    if outcome == "completed":
                        self.ralph.on_success(issue)
                    elif outcome == "merge_failed":
                        self.ralph.on_failure(issue, merge_error or "merge_failed")
                    # Sleeptime: notify completion and possibly consolidate
                    consolidation_result = self.sleeptime.on_workcell_complete(
                        success=success_for_ralph
                    )
                    if consolidation_result and consolidation_result.success:
                        # Reload controller's dynamics report after consolidation
                        self.controller._report = self.controller._load_report()
                        # Full-Scale Ralph: notify of consolidation for pattern/trap refresh
                        self.sleeptime.notify_ralph(self.ralph, consolidation_result)
                else:
                    await self._handle_failure(issue, result, workcell_path)
                    # Memory: end session as failed
                    self.memory_bridge.on_workcell_end(workcell_id, "failed")
                    # Ralph: record failure (Full-Scale Ralph)
                    error_msg = None
                    tokens_used = 0
                    if result.proof:
                        error_msg = (
                            result.proof.metadata.get("error") if result.proof.metadata else None
                        )
                        tokens_used = (
                            int(result.proof.metadata.get("tokens_used") or 0)
                            if result.proof.metadata
                            else 0
                        )
                    # Get state_id and session_id for dynamics/memory integration
                    from_state = self._workcell_from_states.get(workcell_id, {})
                    state_id = from_state.get("state_id")
                    session_id = self.memory_bridge.get_session_id(workcell_id)
                    self.ralph.after_dispatch(
                        issue=issue,
                        toolchain=result.toolchain,
                        success=False,
                        error=error_msg,
                        tokens_used=tokens_used,
                        state_id=state_id,
                        session_id=session_id,
                    )
                    self.ralph.on_failure(issue, error_msg)
                    # Sleeptime: notify failure and possibly consolidate
                    consolidation_result = self.sleeptime.on_workcell_complete(success=False)
                    if consolidation_result and consolidation_result.success:
                        self.controller._report = self.controller._load_report()
                        # Full-Scale Ralph: notify of consolidation for pattern/trap refresh
                        self.sleeptime.notify_ralph(self.ralph, consolidation_result)
            else:
                # Strategy telemetry: if we have a proof (even failed/timeout), store as failed.
                if result.proof is not None:
                    self._maybe_store_strategy_profile(
                        workcell_id=workcell_id,
                        workcell_path=workcell_path,
                        issue=issue,
                        proof=result.proof,
                        toolchain=result.toolchain,
                        verified=False,
                    )
                await self._handle_failure(issue, result, workcell_path)
                # Memory: end session as failed
                if workcell_id:
                    self.memory_bridge.on_workcell_end(workcell_id, "failed")
                # Ralph: record failure (dispatch did not succeed) - Full-Scale Ralph
                error_msg = result.error
                if not error_msg and result.proof and result.proof.metadata:
                    error_msg = result.proof.metadata.get("error")
                # Get state_id and session_id for dynamics/memory integration
                from_state = self._workcell_from_states.get(workcell_id, {}) if workcell_id else {}
                state_id = from_state.get("state_id")
                session_id = (
                    self.memory_bridge._active_sessions.get(workcell_id) if workcell_id else None
                )
                self.ralph.after_dispatch(
                    issue=issue,
                    toolchain=result.toolchain,
                    success=False,
                    error=error_msg,
                    state_id=state_id,
                    session_id=session_id,
                )
                self.ralph.on_failure(issue, error_msg)
                # Sleeptime: notify failure and possibly consolidate
                consolidation_result = self.sleeptime.on_workcell_complete(success=False)
                if consolidation_result and consolidation_result.success:
                    self.controller._report = self.controller._load_report()
                    # Full-Scale Ralph: notify of consolidation for pattern/trap refresh
                    self.sleeptime.notify_ralph(self.ralph, consolidation_result)

        finally:
            self._running_tasks.discard(issue.id)

    def _build_speculate_dispatch_plan(
        self,
        issue: Issue,
        *,
        requested_parallelism: int,
        history_candidates: list[dict[str, Any]],
    ) -> SpeculateDispatchPlan | None:
        from cyntra.core.routing import speculate_toolchains

        candidates = speculate_toolchains(self.config, issue)
        if not candidates:
            candidates = list(self.config.toolchain_priority)

        available_toolchains = self.dispatcher.get_available_toolchains()
        available = set(available_toolchains)
        candidates = [c for c in candidates if c in available]

        if not candidates:
            return None

        requested_parallelism = max(1, int(requested_parallelism))
        baseline_parallelism = min(requested_parallelism, len(candidates))

        planner_universe_id, planner_universe_defaults, planner_action_space = (
            self._planner_universe_context()
        )
        from cyntra.cognition.planner.artifacts import system_state_snapshot

        now_ms = int(time.time() * 1000)
        system_state = system_state_snapshot(
            active_workcells=len(self._running_tasks) + 1,
            queue_depth=None,
            available_toolchains=available_toolchains,
            now_ms=now_ms,
        )
        job_type = "fab-world" if "asset:world" in (issue.tags or []) else "code"

        # Compute a conservative timeout cap across toolchains to ensure we never extend timeouts.
        timeout_caps: list[int] = []
        for toolchain in candidates[:baseline_parallelism]:
            toolchain_cfg = self.config.toolchains.get(toolchain)
            timeout_caps.append(
                int(getattr(toolchain_cfg, "timeout_seconds", 1800))
                if toolchain_cfg is not None
                else 1800
            )
        timeout_cap_seconds = min(timeout_caps) if timeout_caps else 1800

        selection = self.planner_integration.decide(
            issue=issue,
            job_type=job_type,
            universe_id=planner_universe_id,
            universe_defaults=planner_universe_defaults,
            action_space=planner_action_space,
            history_candidates=history_candidates,
            system_state=system_state,
            now_ms=now_ms,
            baseline_swarm_id="speculate_vote",
            baseline_max_candidates=baseline_parallelism,
            baseline_timeout_cap_seconds=int(timeout_cap_seconds),
            max_iterations=None,
        )
        parallelism = max(1, min(int(selection.max_candidates_executed), baseline_parallelism))
        candidates = candidates[:parallelism]

        return SpeculateDispatchPlan(
            candidates=candidates,
            selection=selection,
            parallelism=parallelism,
        )

    async def _dispatch_speculate_async(
        self,
        issue: Issue,
        *,
        parallelism: int,
        history_candidates: list[dict[str, Any]],
        dispatch_plan: SpeculateDispatchPlan | None = None,
    ) -> None:
        """Dispatch multiple parallel workcells for speculate+vote."""
        if dispatch_plan is None:
            dispatch_plan = self._build_speculate_dispatch_plan(
                issue,
                requested_parallelism=parallelism,
                history_candidates=history_candidates,
            )

        if not dispatch_plan or not dispatch_plan.candidates:
            console.print("  [red]No available toolchains for speculate[/red]")
            return

        candidates = list(dispatch_plan.candidates)
        selection = dispatch_plan.selection
        parallelism = dispatch_plan.parallelism
        console.print(
            f"\n[magenta]Speculate[/magenta] #{issue.id}: {issue.title} "
            f"(×{parallelism}: {', '.join(candidates)})"
        )

        # Create workcells BEFORE marking as running to prevent race condition
        # If all creations fail, issue won't be in _running_tasks and can be rescheduled
        workcells: list[tuple[str, str, Path]] = []
        suggested_template = self.workcell_manager.suggest_template(
            domain=self._infer_domain(issue),
            tags=issue.tags,
        )
        for toolchain in candidates:
            tag = f"spec-{toolchain}"
            try:
                path = self.workcell_manager.create(
                    issue.id,
                    speculate_tag=tag,
                    template=suggested_template,
                )
            except Exception as exc:
                self.state_manager.add_event(
                    issue.id,
                    "workcell.create_failed",
                    {
                        "toolchain": toolchain,
                        "speculate_tag": tag,
                        "error": str(exc),
                    },
                )
                console.print(f"  [red]✗[/red] Workcell create failed for {toolchain}: {exc}")
                continue
            workcells.append((toolchain, tag, path))

            # Dynamics: capture from_state for each workcell
            workcell_id = path.name
            from_state = self._build_from_state(issue, workcell_id, toolchain)
            self._workcell_from_states[workcell_id] = from_state

            # Track dispatch start time for swarm episode emission
            self._dispatch_start_times[workcell_id] = time.time()

        if not workcells:
            self._handle_workcell_create_failure(
                issue, RuntimeError("All speculate workcell creations failed")
            )
            return

        # Only mark as running AFTER at least one workcell creation succeeds
        self._running_tasks.add(issue.id)

        # Use first workcell for ephemeral tracking (speculation has multiple)
        primary_workcell_id = workcells[0][2].name if workcells else None
        primary_toolchain = workcells[0][0] if workcells else None

        try:

            # Update issue status (uses ephemeral state to avoid dirtying repo)
            self.state_manager.update_issue_status(
                issue.id,
                "running",
                workcell_id=primary_workcell_id,
                toolchain=primary_toolchain,
            )
            self.state_manager.add_event(
                issue.id,
                "issue.started",
                {"speculate": True},
            )

            # Dispatch all candidates in parallel (one per toolchain).
            dispatch_tasks = []
            for toolchain, tag, path in workcells:
                self.state_manager.add_event(
                    issue.id,
                    "workcell.created",
                    {
                        "toolchain": toolchain,
                        "speculate_tag": tag,
                    },
                    workcell_id=path.name,
                )
                self.state_manager.add_event(
                    issue.id,
                    "workcell.started",
                    {
                        "toolchain": toolchain,
                        "speculate_tag": tag,
                    },
                    workcell_id=path.name,
                )
                toolchain_cfg = self.config.toolchains.get(toolchain)
                timeout_seconds = (
                    int(getattr(toolchain_cfg, "timeout_seconds", 1800))
                    if toolchain_cfg is not None
                    else 1800
                )
                planner_bundle = self.planner_integration.build_manifest_planner_bundle(
                    selection=selection,
                    swarm_id_executed="speculate_vote",
                    timeout_seconds_default=int(timeout_seconds),
                    max_iterations_executed=None,
                )
                dispatch_tasks.append(
                    asyncio.create_task(
                        self.dispatcher.dispatch_async(
                            issue,
                            path,
                            speculate_tag=tag,
                            toolchain_override=toolchain,
                            manifest_overrides={"planner": planner_bundle},
                        ),
                        name=f"speculate_{toolchain}_{tag}",
                    )
                )

            workcell_by_id = {path.name: path for _, _, path in workcells}
            workcell_toolchains = {path.name: toolchain for toolchain, _, path in workcells}

            # Early termination: Process results as they complete, stop on first success
            results: list[DispatchResult] = []
            early_winner: DispatchResult | None = None
            early_winner_path: Path | None = None

            if self.config.speculation.early_terminate:
                # Use FIRST_COMPLETED to process results as they arrive
                pending = set(dispatch_tasks)
                while pending and not early_winner:
                    done, pending = await asyncio.wait(
                        pending,
                        return_when=asyncio.FIRST_COMPLETED,
                    )

                    for task in done:
                        try:
                            result = task.result()
                            results.append(result)

                            # Verify immediately
                            if result.proof:
                                path = workcell_by_id.get(result.workcell_id)
                                if path:
                                    candidate_verified = await self.verifier.verify_async(
                                        result.proof,
                                        path,
                                    )
                                    self._maybe_store_strategy_profile(
                                        workcell_id=result.workcell_id,
                                        workcell_path=path,
                                        issue=issue,
                                        proof=result.proof,
                                        toolchain=result.toolchain,
                                        verified=candidate_verified,
                                    )

                                    # Check if this candidate passes
                                    if (
                                        candidate_verified
                                        and isinstance(result.proof.verification, dict)
                                        and result.proof.verification.get("all_passed", False)
                                    ):
                                        early_winner = result
                                        early_winner_path = path
                                        logger.info(
                                            "Early termination: found passing candidate",
                                            workcell_id=result.workcell_id,
                                            toolchain=result.toolchain,
                                            remaining_candidates=len(pending),
                                        )
                                        break
                        except Exception as exc:
                            logger.warning(
                                "Speculate task failed",
                                task_name=task.get_name(),
                                error=str(exc),
                            )

                # Cancel remaining tasks if we found an early winner
                if early_winner and pending:
                    logger.info(
                        "Cancelling remaining speculate candidates",
                        count=len(pending),
                    )
                    for task in pending:
                        task.cancel()
                    # Wait for cancellations to complete
                    await asyncio.gather(*pending, return_exceptions=True)
            else:
                # Original behavior: wait for all to complete, then verify
                completed = await asyncio.gather(*dispatch_tasks, return_exceptions=True)
                for item in completed:
                    if isinstance(item, Exception):
                        logger.warning("Speculate dispatch failed", error=str(item))
                    else:
                        results.append(item)

                # Verify all candidates
                for r in results:
                    if r.proof:
                        path = workcell_by_id.get(r.workcell_id)
                        if path:
                            candidate_verified = await self.verifier.verify_async(r.proof, path)
                            self._maybe_store_strategy_profile(
                                workcell_id=r.workcell_id,
                                workcell_path=path,
                                issue=issue,
                                proof=r.proof,
                                toolchain=r.toolchain,
                                verified=candidate_verified,
                            )

            proofs = [r.proof for r in results if r.proof]

            # Use early winner if found, otherwise vote
            winner_result: DispatchResult | None = None
            winner_path: Path | None = None

            if early_winner and early_winner_path:
                # Early termination found a passing candidate
                winner_result = early_winner
                winner_path = early_winner_path
                self.state_manager.add_event(
                    issue.id,
                    "speculate.early_winner",
                    {
                        "workcell_id": early_winner.workcell_id,
                        "toolchain": early_winner.toolchain,
                        "candidates_checked": len(results),
                    },
                )
                logger.info(
                    "Using early termination winner",
                    workcell_id=early_winner.workcell_id,
                    toolchain=early_winner.toolchain,
                )
            else:
                # Standard voting process
                self.state_manager.add_event(
                    issue.id,
                    "speculate.voting",
                    {
                        "candidates": candidates,
                        "count": len(candidates),
                    },
                )
                winner_proof = self.verifier.vote(proofs) if proofs else None

                if winner_proof:
                    for r in results:
                        if r.proof and r.proof.workcell_id == winner_proof.workcell_id:
                            winner_result = r
                            winner_path = workcell_by_id.get(r.workcell_id)
                            break

            # Fallback if vote didn't return a winner (e.g., all failed gates).
            if not winner_result:
                passing = [
                    r
                    for r in results
                    if r.proof
                    and isinstance(r.proof.verification, dict)
                    and r.proof.verification.get("all_passed", False)
                ]
                if passing:
                    passing.sort(
                        key=lambda x: x.proof.confidence if x.proof else 0,
                        reverse=True,
                    )
                    winner_result = passing[0]
                    winner_path = workcell_by_id.get(winner_result.workcell_id)
                else:
                    successful = [r for r in results if r.success and r.proof]
                    if successful:
                        successful.sort(
                            key=lambda x: x.proof.confidence if x.proof else 0,
                            reverse=True,
                        )
                        winner_result = successful[0]
                        winner_path = workcell_by_id.get(winner_result.workcell_id)

            # Speculation synthesis: persist cross-candidate learnings (best-effort).
            try:
                from cyntra.core.verifier.synthesis import SpeculationSynthesizer

                candidate_payloads: list[dict[str, Any]] = []
                result_by_workcell_id = {r.workcell_id: r for r in results}

                for toolchain, tag, path in workcells:
                    _ = toolchain, tag  # reserved for future synthesis evidence
                    r = result_by_workcell_id.get(path.name)
                    proof = r.proof if r else None

                    gates_passed: list[str] = []
                    gates_failed: list[str] = []
                    gate_pass_rate = 0.0
                    files_modified: list[str] = []
                    token_usage = 0
                    duration_ms = int(getattr(r, "duration_ms", 0) or 0) if r else 0
                    tool_sequence: list[str] = []
                    success = False

                    if proof:
                        if isinstance(proof.verification, dict):
                            gates = proof.verification.get("gates", {})
                            if isinstance(gates, dict):
                                for gate_name, gate_result in gates.items():
                                    if isinstance(gate_result, dict) and gate_result.get(
                                        "passed", False
                                    ):
                                        gates_passed.append(gate_name)
                                    elif isinstance(gate_result, dict):
                                        gates_failed.append(gate_name)
                            total = len(gates_passed) + len(gates_failed)
                            gate_pass_rate = len(gates_passed) / max(total, 1)
                            success = bool(proof.verification.get("all_passed", False))

                        if isinstance(proof.patch, dict):
                            raw_files = proof.patch.get("files_modified")
                            if isinstance(raw_files, list):
                                files_modified = [str(x) for x in raw_files if x]

                        if isinstance(proof.metadata, dict):
                            try:
                                token_usage = int(proof.metadata.get("tokens_used") or 0)
                            except (TypeError, ValueError):
                                token_usage = 0
                            try:
                                duration_ms = int(proof.metadata.get("duration_ms") or duration_ms)
                            except (TypeError, ValueError):
                                pass

                        if isinstance(proof.commands_executed, list):
                            for cmd in proof.commands_executed[:50]:
                                if not isinstance(cmd, dict):
                                    continue
                                tool = cmd.get("tool") or cmd.get("command") or cmd.get("name")
                                if isinstance(tool, str) and tool.strip():
                                    tool_sequence.append(tool.strip())

                    candidate_payloads.append(
                        {
                            "success": success,
                            "gate_pass_rate": gate_pass_rate,
                            "tool_sequence": tool_sequence,
                            "files_modified": files_modified,
                            "gates_passed": gates_passed,
                            "gates_failed": gates_failed,
                            "token_usage": token_usage,
                            "duration_ms": duration_ms,
                        }
                    )

                winner_index = None
                if winner_result:
                    for idx, (_, _, path) in enumerate(workcells):
                        if path.name == winner_result.workcell_id:
                            winner_index = idx
                            break

                synthesizer = SpeculationSynthesizer(db_path=self.transition_db.db_path)
                synthesis = synthesizer.synthesize(
                    candidates=candidate_payloads,
                    winner_index=winner_index,
                    issue_id=issue.id,
                    run_id=f"speculate_vote:{issue.id}",
                )

                if synthesis.observations:
                    self.state_manager.add_event(
                        issue.id,
                        "speculate.synthesis",
                        {
                            "winner_index": synthesis.winner_index,
                            "candidates": synthesis.candidates_count,
                            "observations": len(synthesis.observations),
                            "persisted": synthesis.persisted_count,
                        },
                    )
            except Exception:
                logger.debug("Speculation synthesis failed (non-fatal)", exc_info=True)

            # If still no winner, fail the issue using the first candidate (best-effort).
            if not winner_result or not winner_path:
                fallback_path = workcells[0][2]
                await self._handle_failure(issue, results[0] if results else None, fallback_path)
                for _, _, path in workcells[1:]:
                    self.workcell_manager.cleanup(path, keep_logs=False)
                return

            verified = (
                bool(winner_result.proof)
                and isinstance(winner_result.proof.verification, dict)
                and winner_result.proof.verification.get("all_passed", False)
            )

            # Memory: record only the winning workcell's execution
            winner_workcell_id = winner_path.name
            manifest_base = self.dispatcher._build_manifest(
                issue, winner_workcell_id, winner_result.toolchain, winner_result.speculate_tag
            )
            self.memory_bridge.on_workcell_start(
                workcell_id=winner_workcell_id,
                issue=issue,
                manifest=manifest_base,
            )
            self.memory_bridge.on_dispatch_complete(
                workcell_id=winner_workcell_id,
                workcell_path=winner_path,
                proof=winner_result.proof,
            )

            # Memory: record gate results for winner
            if winner_result.proof and isinstance(winner_result.proof.verification, dict):
                gates = winner_result.proof.verification.get("gates", {})
                for gate_name, gate_result in gates.items():
                    if isinstance(gate_result, dict):
                        self.memory_bridge.on_gate_result(
                            gate_name=gate_name,
                            passed=gate_result.get("passed", False),
                            score=gate_result.get("score"),
                            fail_codes=gate_result.get("fail_codes", []),
                        )

            if verified:
                outcome = await self._handle_success(issue, winner_result, winner_path)
                status = (
                    "success"
                    if outcome == "completed"
                    else "review_required"
                    if outcome == "review_required"
                    else "merge_failed"
                )
                success_for_sleeptime = outcome in {"completed", "review_required"}
                self.memory_bridge.on_workcell_end(winner_workcell_id, status)
                consolidation_result = self.sleeptime.on_workcell_complete(
                    success=success_for_sleeptime
                )
                if consolidation_result and consolidation_result.success:
                    self.controller._report = self.controller._load_report()
                    # Full-Scale Ralph: notify of consolidation for pattern/trap refresh
                    self.sleeptime.notify_ralph(self.ralph, consolidation_result)
            else:
                await self._handle_failure(issue, winner_result, winner_path)
                self.memory_bridge.on_workcell_end(winner_workcell_id, "failed")
                consolidation_result = self.sleeptime.on_workcell_complete(success=False)
                if consolidation_result and consolidation_result.success:
                    self.controller._report = self.controller._load_report()
                    # Full-Scale Ralph: notify of consolidation for pattern/trap refresh
                    self.sleeptime.notify_ralph(self.ralph, consolidation_result)

            # Cleanup non-winners (keep logs only for the chosen candidate).
            for _, _, path in workcells:
                if path.name == winner_path.name:
                    continue
                # Cleanup dispatch start time tracking for non-winners
                self._dispatch_start_times.pop(path.name, None)
                self.workcell_manager.cleanup(path, keep_logs=False)

        finally:
            self._running_tasks.discard(issue.id)

    async def _handle_success(
        self,
        issue: Issue,
        result: DispatchResult,
        workcell_path: Path,
    ) -> str:
        """Handle successful workcell completion."""
        if self._requires_review(issue):
            return self._handle_review_required(issue, result, workcell_path)

        merge_applied = True
        if result.proof and getattr(issue, "dk_apply_patch", True):
            merge_applied = self.dispatcher.apply_patch(result.proof, workcell_path)

        if not merge_applied:
            self._handle_merge_failure(issue, result, workcell_path)
            return "merge_failed"

        console.print(f"  [green]✓[/green] #{issue.id} completed")

        self._stats["issues_completed"] += 1
        self._stats["total_duration_ms"] += result.duration_ms

        # Dynamics: record successful transition
        workcell_id = workcell_path.name
        self._record_transition(workcell_id, issue, result, verified=True)

        # Update Beads
        self.state_manager.update_issue_status(issue.id, "done")

        # Log event
        self.state_manager.add_event(
            issue.id,
            "workcell.completed",
            {
                "toolchain": result.toolchain,
                "duration_ms": result.duration_ms,
                "speculate_tag": result.speculate_tag,
            },
            workcell_id=workcell_id,
        )
        self.state_manager.add_event(
            issue.id,
            "issue.completed",
            {
                "toolchain": result.toolchain,
                "duration_ms": result.duration_ms,
                "speculate_tag": result.speculate_tag,
            },
        )

        # Emit swarm episode for successful dispatch
        self._emit_swarm_episode(
            workcell_id=workcell_id,
            issue_id=issue.id,
            success=True,
            duration_ms=result.duration_ms,
            toolchain=result.toolchain,
        )

        # Cleanup workcell
        self.workcell_manager.cleanup(workcell_path, keep_logs=True)
        return "completed"

    def _handle_merge_failure(
        self,
        issue: Issue,
        result: DispatchResult,
        workcell_path: Path,
    ) -> None:
        """Handle merge failures after a verified workcell completion."""
        merge_error = None
        merge_branch = None
        if result.proof and isinstance(result.proof.patch, dict):
            merge_error = result.proof.patch.get("merge_error")
            merge_branch = result.proof.patch.get("merge_branch")

        console.print(f"  [red]✗[/red] #{issue.id} merge failed")

        self._stats["issues_failed"] += 1
        self._stats["total_duration_ms"] += result.duration_ms

        workcell_id = workcell_path.name
        self._record_transition(workcell_id, issue, result, verified=False)

        self.state_manager.add_event(
            issue.id,
            "merge.failed",
            {
                "workcell_id": workcell_id,
                "branch": merge_branch,
                "error": merge_error or "merge_failed",
            },
            workcell_id=workcell_id,
        )

        conflict_issue_id = self._ensure_merge_conflict_issue(
            issue=issue,
            workcell_path=workcell_path,
            merge_branch=merge_branch,
            merge_error=merge_error,
        )

        if conflict_issue_id:
            # Return the original issue to open and block it behind the merge-fix issue.
            self.state_manager.update_issue(issue.id, status="open")
            graph = self.state_manager.load_beads_graph()
            has_block = any(
                dep.from_id == conflict_issue_id
                and dep.to_id == issue.id
                and dep.dep_type == "blocks"
                for dep in graph.deps
            )
            if not has_block:
                self.state_manager.add_dep(conflict_issue_id, issue.id, dep_type="blocks")
        else:
            self.state_manager.update_issue(issue.id, status="blocked", tags=["merge-conflict"])

    def _requires_review(self, issue: Issue) -> bool:
        """Check if an issue requires human review before merging."""
        return int(getattr(issue, "dk_required_reviewers", 0) or 0) > 0

    def _handle_review_required(
        self,
        issue: Issue,
        result: DispatchResult,
        workcell_path: Path,
    ) -> str:
        """Handle verified output that requires human review before merge."""
        workcell_id = workcell_path.name
        branch = None
        diff_stats = None
        files_modified = None
        if result.proof and isinstance(result.proof.patch, dict):
            branch = result.proof.patch.get("branch")
            diff_stats = result.proof.patch.get("diff_stats")
            files_modified = result.proof.patch.get("files_modified")

        self._record_transition(workcell_id, issue, result, verified=True)

        self.state_manager.add_event(
            issue.id,
            "review.required",
            {
                "workcell_id": workcell_id,
                "branch": branch,
                "required_reviewers": issue.dk_required_reviewers,
            },
            workcell_id=workcell_id,
        )

        review_issue_id = self._ensure_review_required_issue(
            issue=issue,
            workcell_path=workcell_path,
            branch=branch,
            diff_stats=diff_stats,
            files_modified=files_modified,
        )

        if review_issue_id:
            self.state_manager.update_issue(
                issue.id,
                status="blocked",
                tags=["review-required"],
            )
            graph = self.state_manager.load_beads_graph()
            has_block = any(
                dep.from_id == review_issue_id
                and dep.to_id == issue.id
                and dep.dep_type == "blocks"
                for dep in graph.deps
            )
            if not has_block:
                self.state_manager.add_dep(review_issue_id, issue.id, dep_type="blocks")
        else:
            self.state_manager.update_issue(
                issue.id,
                status="blocked",
                tags=["review-required", "needs-human"],
            )

        console.print(f"  [yellow]⚠[/yellow] #{issue.id} review required before merge")
        return "review_required"

    def _ensure_review_required_issue(
        self,
        *,
        issue: Issue,
        workcell_path: Path,
        branch: str | None,
        diff_stats: dict | None,
        files_modified: list[str] | None,
    ) -> str | None:
        """Create or update a review-required bead for an issue.

        When running with --issue (target_issue), skip creating new issues to keep
        the run focused on the single target issue.
        """
        # Skip auto-issue creation when running in single-issue mode
        if self.target_issue:
            logger.debug(
                "Skipping review-required issue creation in single-issue mode",
                target_issue=self.target_issue,
                issue_id=issue.id,
            )
            return None

        graph = self.state_manager.load_beads_graph()
        existing = None
        for candidate in graph.issues:
            if candidate.status == "done":
                continue
            if candidate.dk_parent != issue.id:
                continue
            if "review-required" not in (candidate.tags or []):
                continue
            existing = candidate
            break

        base_description = existing.description if existing else ""
        description = self._build_review_required_description(
            issue=issue,
            base_description=base_description,
            workcell_path=workcell_path,
            branch=branch,
            diff_stats=diff_stats,
            files_modified=files_modified,
        )

        if existing:
            self.state_manager.update_issue(existing.id, description=description)
            return existing.id

        title = f"[REVIEW REQUIRED] {issue.title}"
        tags = sorted(
            set((issue.tags or []) + ["review-required", "needs-human", "human-review"])
        )

        new_issue_id = self.state_manager.create_issue(
            title=title,
            description=description,
            priority="P0",
            tags=tags,
        )

        if new_issue_id:
            update_fields: dict[str, str] = {
                "dk_parent": issue.id,
                "dk_risk": "high",
                "dk_required_reviewers": str(issue.dk_required_reviewers),
            }
            if issue.dk_tool_hint:
                update_fields["dk_tool_hint"] = issue.dk_tool_hint
            self.state_manager.update_issue(new_issue_id, **update_fields)

        return new_issue_id

    def _build_review_required_description(
        self,
        *,
        issue: Issue,
        base_description: str,
        workcell_path: Path,
        branch: str | None,
        diff_stats: dict | None,
        files_modified: list[str] | None,
    ) -> str:
        """Build a review-required issue description."""
        start_marker = "<!-- REVIEW_REQUIRED_AUTOGEN -->"
        end_marker = "<!-- /REVIEW_REQUIRED_AUTOGEN -->"
        workcell_str = str(workcell_path)
        branch_str = branch or "unknown"

        lines: list[str] = []
        lines.append(start_marker)
        lines.append("## Review Required")
        lines.append("Verified workcell output requires human review before merge.")
        lines.append("")
        lines.append(f"- Original issue: #{issue.id}")
        lines.append(f"- Workcell: `{workcell_str}`")
        lines.append(f"- Branch: `{branch_str}`")
        if diff_stats:
            files_changed = diff_stats.get("files_changed")
            insertions = diff_stats.get("insertions")
            deletions = diff_stats.get("deletions")
            lines.append(
                f"- Diff stats: {files_changed} files, +{insertions} -{deletions}"
            )
        if files_modified:
            lines.append("- Files modified:")
            for filename in files_modified[:20]:
                lines.append(f"  - `{filename}`")
        lines.append("")
        lines.append("### Suggested Resolution")
        lines.append("1) Inspect the workcell diff and logs.")
        lines.append(f"2) Merge `{branch_str}` into main manually.")
        lines.append("3) Run relevant gates/tests, then mark this bead done.")
        lines.append(end_marker)

        base = (base_description or "").strip()
        if start_marker in base and end_marker in base:
            start = base.find(start_marker)
            end = base.find(end_marker, start)
            if end != -1:
                base = (base[:start] + base[end + len(end_marker) :]).strip()

        return (base + "\n\n" + "\n".join(lines)).strip()

    def _ensure_merge_conflict_issue(
        self,
        *,
        issue: Issue,
        workcell_path: Path,
        merge_branch: str | None,
        merge_error: str | None,
    ) -> str | None:
        """Create or update a merge-conflict bead for an issue.

        When running with --issue (target_issue), skip creating new issues to keep
        the run focused on the single target issue.
        """
        # Skip auto-issue creation when running in single-issue mode
        if self.target_issue:
            logger.debug(
                "Skipping merge-conflict issue creation in single-issue mode",
                target_issue=self.target_issue,
                issue_id=issue.id,
            )
            return None

        graph = self.state_manager.load_beads_graph()
        existing = None
        for candidate in graph.issues:
            if candidate.status == "done":
                continue
            if candidate.dk_parent != issue.id:
                continue
            if "merge-conflict" not in (candidate.tags or []):
                continue
            existing = candidate
            break

        base_description = existing.description if existing else ""
        description = self._build_merge_conflict_description(
            issue=issue,
            base_description=base_description,
            workcell_path=workcell_path,
            merge_branch=merge_branch,
            merge_error=merge_error,
        )

        if existing:
            self.state_manager.update_issue(existing.id, description=description)
            return existing.id

        title = f"[MERGE CONFLICT] {issue.title}"
        tags = sorted(set((issue.tags or []) + ["merge-conflict"]))

        new_issue_id = self.state_manager.create_issue(
            title=title,
            description=description,
            priority="P0",
            tags=tags,
        )

        if new_issue_id:
            update_fields: dict[str, str] = {"dk_parent": issue.id, "dk_risk": "high"}
            if issue.dk_tool_hint:
                update_fields["dk_tool_hint"] = issue.dk_tool_hint
            self.state_manager.update_issue(new_issue_id, **update_fields)

        return new_issue_id

    def _build_merge_conflict_description(
        self,
        *,
        issue: Issue,
        base_description: str,
        workcell_path: Path,
        merge_branch: str | None,
        merge_error: str | None,
    ) -> str:
        """Build a merge conflict issue description."""
        start_marker = "<!-- MERGE_CONFLICT_AUTOGEN -->"
        end_marker = "<!-- /MERGE_CONFLICT_AUTOGEN -->"
        workcell_str = str(workcell_path)
        branch_str = merge_branch or "unknown"
        error_str = merge_error or "merge_failed"

        lines: list[str] = []
        lines.append(start_marker)
        lines.append("## Merge Conflict")
        lines.append("Automated merge into main failed after a verified workcell run.")
        lines.append("")
        lines.append(f"- Original issue: #{issue.id}")
        lines.append(f"- Workcell: `{workcell_str}`")
        lines.append(f"- Branch: `{branch_str}`")
        lines.append(f"- Error: {error_str}")
        lines.append("")
        lines.append("### Suggested Resolution")
        lines.append("1) Check out main and attempt the merge locally.")
        lines.append(f"2) Resolve conflicts from `{branch_str}`.")
        lines.append("3) Run relevant gates/tests, then mark this bead done.")
        lines.append(end_marker)

        base = (base_description or "").strip()
        if start_marker in base and end_marker in base:
            start = base.find(start_marker)
            end = base.find(end_marker, start)
            if end != -1:
                base = (base[:start] + base[end + len(end_marker) :]).strip()

        return (base + "\n\n" + "\n".join(lines)).strip()

    def _maybe_store_strategy_profile(
        self,
        *,
        workcell_id: str,
        workcell_path: Path,
        issue: Issue,
        proof: Any,
        toolchain: str,
        verified: bool,
    ) -> None:
        """
        Best-effort strategy profile extraction + storage.

        Guarded by manifest flag: `strategy.enabled: true`.
        """
        manifest_path = workcell_path / "manifest.json"
        if not manifest_path.exists():
            return

        try:
            manifest = json.loads(manifest_path.read_text())
        except Exception:
            return

        strategy_cfg = manifest.get("strategy")
        if not (isinstance(strategy_cfg, dict) and strategy_cfg.get("enabled") is True):
            return

        outcome = "passed" if verified else "failed"
        self.strategy_integration.extract_and_store(
            workcell_id=workcell_id,
            workcell_path=workcell_path,
            issue=issue,
            proof=proof,
            toolchain=toolchain,
            outcome=outcome,
        )

    def _handle_workcell_create_failure(self, issue: Issue, error: Exception) -> None:
        """Handle failures that occur before a workcell is created."""
        error_summary = str(error)
        console.print(f"  [red]✗[/red] #{issue.id} workcell create failed: {error_summary}")

        current_attempts = self.state_manager.increment_attempts(issue.id)
        self.state_manager.add_event(
            issue.id,
            "workcell.create_failed",
            {
                "toolchain": getattr(issue, "dk_tool_hint", None),
                "error": error_summary,
                "attempt": current_attempts,
            },
        )

        if current_attempts >= issue.dk_max_attempts:
            self.state_manager.update_issue_status(issue.id, "escalated")
            console.print(f"  [yellow]⚠[/yellow] #{issue.id} escalated (max attempts reached)")
            self._create_escalation_issue(issue, None, error_summary=error_summary)
        else:
            self.state_manager.update_issue_status(issue.id, "ready")
            console.print(f"  [dim]Attempt {current_attempts}/{issue.dk_max_attempts}[/dim]")

    async def _handle_failure(
        self,
        issue: Issue,
        result: DispatchResult | None,
        workcell_path: Path,
    ) -> None:
        """Handle workcell failure."""
        console.print(f"  [red]✗[/red] #{issue.id} failed")

        self._stats["issues_failed"] += 1
        if result:
            self._stats["total_duration_ms"] += result.duration_ms

        # Dynamics: record failed transition
        workcell_id = workcell_path.name
        self._record_transition(workcell_id, issue, result, verified=False)

        # Update attempts
        current_attempts = self.state_manager.increment_attempts(issue.id)

        # Prefer verification context over generic dispatch errors.
        error_summary = None
        if result and result.error:
            error_summary = result.error
        elif result and result.proof and isinstance(result.proof.verification, dict):
            blocking = result.proof.verification.get("blocking_failures") or []
            if blocking:
                error_summary = f"Gate failures: {', '.join(blocking)}"

        # Log event
        self.state_manager.add_event(
            issue.id,
            "workcell.failed",
            {
                "toolchain": result.toolchain if result else "unknown",
                "error": error_summary or "Unknown error",
                "attempt": current_attempts,
            },
            workcell_id=workcell_id,
        )
        self.state_manager.add_event(
            issue.id,
            "issue.failed",
            {
                "toolchain": result.toolchain if result else "unknown",
                "error": error_summary or "Unknown error",
                "attempt": current_attempts,
            },
        )

        # If this is an asset issue and fab-* gates provided repair hints, persist them back
        # onto the issue description so the next attempt has concrete guidance.
        if result:
            self._maybe_update_issue_with_repair_hints(issue, result, current_attempts)
            self._maybe_update_issue_with_next_steps(issue, result, current_attempts)

        # Check if should escalate
        if current_attempts >= issue.dk_max_attempts:
            self.state_manager.update_issue_status(issue.id, "escalated")
            console.print(f"  [yellow]⚠[/yellow] #{issue.id} escalated (max attempts reached)")

            # Create escalation issue
            self._create_escalation_issue(issue, result, error_summary)
        else:
            # Re-queue for another attempt; the scheduler already enforces max attempts.
            self.state_manager.update_issue_status(issue.id, "ready")
            console.print(f"  [dim]Attempt {current_attempts}/{issue.dk_max_attempts}[/dim]")

        # Emit swarm episode for failed dispatch
        self._emit_swarm_episode(
            workcell_id=workcell_id,
            issue_id=issue.id,
            success=False,
            duration_ms=result.duration_ms if result else 0,
            toolchain=result.toolchain if result else None,
        )

        # Cleanup workcell (keep logs for debugging)
        self.workcell_manager.cleanup(workcell_path, keep_logs=True)

    async def _handle_topology_failure(
        self,
        *,
        issue: Issue,
        dispatch_result: DispatchResult,
        topology_result: Any,
        workcell_id: str,
    ) -> None:
        """Handle topology execution failure."""
        console.print(f"  [red]✗[/red] #{issue.id} topology failed")

        self._stats["issues_failed"] += 1
        self._stats["total_duration_ms"] += dispatch_result.duration_ms

        self._record_transition(workcell_id, issue, dispatch_result, verified=False)

        current_attempts = self.state_manager.increment_attempts(issue.id)
        error_summary = topology_result.error or "Topology execution failed"
        topology_name = getattr(topology_result, "topology_name", "unknown")

        self.state_manager.add_event(
            issue.id,
            "topology.failed",
            {
                "topology": topology_name,
                "error": error_summary,
                "attempt": current_attempts,
            },
        )
        self.state_manager.add_event(
            issue.id,
            "issue.failed",
            {
                "toolchain": dispatch_result.toolchain,
                "error": error_summary,
                "attempt": current_attempts,
            },
        )

        self.ralph.after_dispatch(
            issue=issue,
            toolchain=dispatch_result.toolchain,
            success=False,
            error=error_summary,
            tokens_used=0,
        )
        self.ralph.on_failure(issue, error_summary)

        if current_attempts >= issue.dk_max_attempts:
            self.state_manager.update_issue_status(issue.id, "escalated")
            console.print(f"  [yellow]⚠[/yellow] #{issue.id} escalated (max attempts reached)")
            self._create_escalation_issue(issue, None, error_summary=error_summary)
        else:
            self.state_manager.update_issue_status(issue.id, "ready")
            console.print(f"  [dim]Attempt {current_attempts}/{issue.dk_max_attempts}[/dim]")

        consolidation_result = self.sleeptime.on_workcell_complete(success=False)
        if consolidation_result and consolidation_result.success:
            self.controller._report = self.controller._load_report()
            self.sleeptime.notify_ralph(self.ralph, consolidation_result)

        # Emit swarm episode for failed topology dispatch
        self._emit_swarm_episode(
            workcell_id=workcell_id,
            issue_id=issue.id,
            success=False,
            duration_ms=dispatch_result.duration_ms,
            toolchain=dispatch_result.toolchain,
        )

    def _maybe_update_issue_with_repair_hints(
        self,
        issue: Issue,
        result: DispatchResult,
        attempt: int,
    ) -> None:
        """Write the latest fab gate repair hints back to the issue description."""
        if not any(t.startswith("asset:") for t in (issue.tags or [])):
            return

        if not result.proof or not isinstance(result.proof.verification, dict):
            return

        gates = result.proof.verification.get("gates")
        if not isinstance(gates, dict):
            return

        failing_with_actions: list[tuple[str, list[dict[str, Any]]]] = []
        for gate_name, gate_result in gates.items():
            if not isinstance(gate_result, dict):
                continue
            if gate_result.get("passed") is True:
                continue
            actions = gate_result.get("next_actions")
            if isinstance(actions, list) and actions:
                typed_actions = [a for a in actions if isinstance(a, dict)]
                if typed_actions:
                    failing_with_actions.append((str(gate_name), typed_actions))

        if not failing_with_actions:
            return

        start_marker = "<!-- DEV_KERNEL_AUTOGEN_REPAIR -->"
        end_marker = "<!-- /DEV_KERNEL_AUTOGEN_REPAIR -->"

        base = (issue.description or "").strip()
        if start_marker in base and end_marker in base:
            start = base.find(start_marker)
            end = base.find(end_marker, start)
            if end != -1:
                base = (base[:start] + base[end + len(end_marker) :]).strip()

        lines: list[str] = []
        lines.append(start_marker)
        lines.append(f"## Kernel Repair Hints (Attempt {attempt})")
        lines.append("These instructions were generated from the most recent failed fab gate run.")
        lines.append("")

        for gate_name, actions in failing_with_actions:
            lines.append(f"### {gate_name}")
            for action in actions[:12]:
                priority = action.get("priority", 3)
                fail_code = action.get("fail_code", "UNKNOWN")
                instructions = str(action.get("instructions", "")).strip()
                if not instructions:
                    instructions = f"Fix {fail_code}"
                lines.append(f"- [P{priority}] `{fail_code}`: {instructions}")
            lines.append("")

        lines.append(end_marker)

        new_description = (base + "\n\n" + "\n".join(lines)).strip()
        try:
            self.state_manager.update_issue(issue.id, description=new_description)
        except Exception as e:
            logger.warning(
                "Failed to update issue with repair hints", issue_id=issue.id, error=str(e)
            )

    def _maybe_update_issue_with_next_steps(
        self,
        issue: Issue,
        result: DispatchResult,
        attempt: int,
    ) -> None:
        """
        Write merged "next steps" guidance back to the issue description.

        This is a cheap "multiplex thinking" adaptation: for each failing gate, derive K candidate
        next-step lists from (1) gate-provided next_actions, (2) debug-specialist hook suggestions,
        and (3) deterministic heuristics, then merge/dedupe into a single plan.
        """
        speculation = getattr(self.config, "speculation", None)
        candidates_per_gate = getattr(speculation, "next_step_candidates", 0) if speculation else 0
        max_steps = getattr(speculation, "next_step_max_steps", 12) if speculation else 12

        if not isinstance(candidates_per_gate, int) or candidates_per_gate <= 0:
            return

        if not result.proof or not isinstance(result.proof.verification, dict):
            return

        verification = result.proof.verification
        if verification.get("all_passed") is True:
            return

        from cyntra.core.runner.next_steps import (
            generate_next_steps_bundle,
            render_next_steps_markdown,
        )

        try:
            bundle = generate_next_steps_bundle(
                verification,
                candidates_per_gate=candidates_per_gate,
                max_steps=int(max_steps) if isinstance(max_steps, int) else 12,
            )
        except Exception as exc:
            logger.warning(
                "Failed to generate next steps bundle",
                issue_id=issue.id,
                error=str(exc),
            )
            return

        if not bundle.merged_steps:
            return

        start_marker = "<!-- DEV_KERNEL_AUTOGEN_NEXT_STEPS -->"
        end_marker = "<!-- /DEV_KERNEL_AUTOGEN_NEXT_STEPS -->"

        base = (issue.description or "").strip()
        if start_marker in base and end_marker in base:
            start = base.find(start_marker)
            end = base.find(end_marker, start)
            if end != -1:
                base = (base[:start] + base[end + len(end_marker) :]).strip()

        lines: list[str] = []
        lines.append(start_marker)
        lines.append(render_next_steps_markdown(bundle, attempt=attempt))
        lines.append(end_marker)

        new_description = (base + "\n\n" + "\n".join(lines)).strip() if base else "\n".join(lines)
        try:
            self.state_manager.update_issue(issue.id, description=new_description)
        except Exception as e:
            logger.warning(
                "Failed to update issue with next steps", issue_id=issue.id, error=str(e)
            )

    def _planner_universe_context(self) -> tuple[str, dict[str, Any], ActionSpace]:
        """
        Resolve universe defaults + swarm catalog for planner artifacts.

        Returns (universe_id, universe_defaults, action_space).
        """
        from cyntra.cognition.planner.action_space import action_space_for_swarms

        universe_id = self.universe_id or "unknown"
        universe_defaults: dict[str, Any] = {"swarm_id": None, "objective_id": None}
        swarm_ids: list[str] = ["serial_handoff", "speculate_vote"]

        if self.universe_config:
            universe_id = self.universe_config.universe_id

            defaults = (
                self.universe_config.raw.get("defaults")
                if isinstance(self.universe_config.raw, dict)
                else {}
            )
            if isinstance(defaults, dict):
                swarm_default = defaults.get("swarm_id")
                objective_default = defaults.get("objective_id")
                universe_defaults = {
                    "swarm_id": str(swarm_default)
                    if isinstance(swarm_default, str) and swarm_default
                    else None,
                    "objective_id": str(objective_default)
                    if isinstance(objective_default, str) and objective_default
                    else None,
                }

            swarms = self.universe_config.swarms
            if isinstance(swarms, dict):
                swarms_map = swarms.get("swarms")
                if isinstance(swarms_map, dict):
                    swarm_ids = sorted([str(k) for k in swarms_map if isinstance(k, str) and k])

        action_space = action_space_for_swarms(swarm_ids)
        return universe_id, universe_defaults, action_space

    def _create_escalation_issue(
        self,
        original_issue: Issue,
        result: DispatchResult | None,
        error_summary: str | None = None,
    ) -> None:
        """Create a new issue for human review after escalation.

        When running with --issue (target_issue), skip creating new issues to keep
        the run focused on the single target issue.
        """
        # Skip auto-issue creation when running in single-issue mode
        if self.target_issue:
            logger.debug(
                "Skipping escalation issue creation in single-issue mode",
                target_issue=self.target_issue,
                issue_id=original_issue.id,
            )
            return

        if any(
            t in {"escalation", "needs-human", "@human-escalated", "human-escalated"}
            for t in (original_issue.tags or [])
        ) or original_issue.title.startswith("[ESCALATION]"):
            console.print(
                f"  [dim]Escalation suppressed for #{original_issue.id} (already escalated)[/dim]"
            )
            return

        error = (
            error_summary
            or (result.error if result else None)
            or "Unknown error after max attempts"
        )

        title = f"[ESCALATION] {original_issue.title}"
        description = (
            f"Automated processing failed after {original_issue.dk_max_attempts} attempts.\n\n"
            f"## Original Issue #{original_issue.id}\n"
            f"{original_issue.description or '(no description)'}\n\n"
            f"## Failure Details\n{error}\n\n"
            f"## Action Required\nManual review and intervention needed."
        )
        tags = sorted(set((original_issue.tags or []) + ["escalation", "needs-human"]))

        try:
            new_issue_id = self.state_manager.create_issue(
                title=title,
                description=description,
                priority=original_issue.dk_priority or "P2",
                tags=tags,
            )

            if new_issue_id:
                self.state_manager.update_issue(
                    new_issue_id,
                    dk_parent=original_issue.id,
                    status="escalated",
                )
                console.print(f"  [dim]Created escalation issue #{new_issue_id}[/dim]")
        except Exception as e:
            logger.error("Failed to create escalation issue", error=str(e))

    def _display_schedule(self, plan: SchedulePlan, graph: BeadsGraph) -> None:
        """Display the scheduling plan."""
        issue_by_id = {issue.id: issue for issue in graph.issues}
        table = Table(title=f"Scheduled Work (Cycle {self._cycle_count})")
        table.add_column("Issue", style="cyan")
        table.add_column("Title")
        table.add_column("Priority")
        table.add_column("Risk")
        table.add_column("Mode")
        show_knobs = self.config.dry_run
        if show_knobs:
            table.add_column("Knobs")

        for issue_plan in plan.scheduled:
            issue = issue_by_id.get(issue_plan.issue_id)
            if not issue:
                continue
            mode = (
                "[magenta]speculate[/magenta]"
                if issue_plan.run_mode == "speculate"
                else "single"
            )
            row = [
                f"#{issue_plan.issue_id}",
                issue.title[:40] + ("..." if len(issue.title) > 40 else ""),
                issue.dk_priority or "P2",
                issue.dk_risk or "medium",
                mode,
            ]
            if show_knobs:
                parts: list[str] = []
                if issue_plan.run_mode == "speculate":
                    parts.append(f"par={issue_plan.parallelism}")
                parts.append(f"score={issue_plan.priority_score:.2f}")
                parts.append(issue_plan.admission_reason)
                row.append(", ".join(parts) if parts else "default")
            table.add_row(*row)

        console.print(table)

        if plan.skipped:
            console.print(f"[dim]Skipped {len(plan.skipped)} issues (slots/tokens)[/dim]")

    def _reconcile_running_issues(self, graph: BeadsGraph) -> bool:
        """
        Requeue issues marked as running without an active workcell.

        Returns True if any issues were updated.
        """
        active_issue_ids: set[str] = set()
        for wc_path in self.workcell_manager.list_active():
            info = self.workcell_manager.get_workcell_info(wc_path)
            issue_id = info.get("issue_id") if isinstance(info, dict) else None
            if issue_id:
                active_issue_ids.add(str(issue_id))

        updated_any = False
        for issue in graph.issues:
            if issue.status != "running":
                continue
            if issue.id in active_issue_ids:
                continue

            self.state_manager.update_issue(issue.id, status="ready")
            self.state_manager.add_event(
                issue.id,
                "issue.requeued",
                {"reason": "running_without_workcell"},
            )
            updated_any = True

        return updated_any

    def _display_summary(self) -> None:
        """Display run summary."""
        if self._stats["issues_completed"] > 0 or self._stats["issues_failed"] > 0:
            console.print("\n")
            summary = Panel(
                f"[green]Completed:[/green] {self._stats['issues_completed']}  "
                f"[red]Failed:[/red] {self._stats['issues_failed']}  "
                f"[dim]Cycles:[/dim] {self._cycle_count}  "
                f"[dim]Total Time:[/dim] {self._stats['total_duration_ms'] / 1000:.1f}s",
                title="Run Summary",
            )
            console.print(summary)

        # Display Ralph status if enabled
        if self.ralph.config.enabled:
            ralph_status = self.ralph.get_status()
            cb = ralph_status.get("circuit_breaker", {})
            rl = ralph_status.get("rate_limiter", {}).get("hourly", {})
            exit_det = ralph_status.get("exit_detection", {})

            ralph_summary = (
                f"[dim]Circuit:[/dim] {cb.get('state', 'unknown')}  "
                f"[dim]Calls:[/dim] {rl.get('calls', 0)}/{rl.get('calls_limit', 100)}/hr  "
                f"[dim]Done signals:[/dim] {exit_det.get('consecutive_done_signals', 0)}"
            )
            console.print(f"[dim]Ralph:[/dim] {ralph_summary}")

    def stop(self) -> None:
        """Stop the kernel loop."""
        self._running = False

    def _render_knowledge_graph_context(
        self,
        *,
        issue: "Issue",
        toolchain: str,
        job_type: str,
    ) -> str | None:
        """Render a compact knowledge graph prompt section for this issue."""
        db_path = self.config.repo_root / ".cyntra" / "dynamics" / "cyntra.db"
        if not db_path.exists():
            return None

        try:
            from cyntra.cognition.dynamics.transition_db import TransitionDB
            from cyntra.cognition.knowledge.graph import KnowledgeGraph
            from cyntra.cognition.knowledge.injection import InjectionContext, KnowledgeInjector
            from cyntra.infra.prompts.runtime import detect_domain
        except Exception:
            return None

        tdb = TransitionDB(db_path)
        try:
            graph = KnowledgeGraph(tdb.conn)
            graph.load()
            if graph.node_count <= 0:
                return None

            injector = KnowledgeInjector(graph)
            context = InjectionContext(
                domain=detect_domain(job_type),
                dk_size=getattr(issue, "dk_size", None),
                dk_risk=getattr(issue, "dk_risk", None),
                toolchain=toolchain,
            )
            rendered = injector.render_prompt_section(context, max_strategies=3)
            return rendered.strip() if isinstance(rendered, str) and rendered.strip() else None
        finally:
            try:
                tdb.close()
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────
    # Dynamics Transition Tracking
    # ─────────────────────────────────────────────────────────────────

    def _build_from_state(
        self,
        issue: Issue,
        workcell_id: str,
        toolchain: str,
    ) -> dict:
        """Build the initial state before workcell execution."""
        domain = self._infer_domain(issue)
        job_type = issue.dk_tool_hint or "code"

        features = {
            "phase": "plan",
            "failing_gate": "none",
            "attempt": issue.dk_attempts,
            "risk": issue.dk_risk or "medium",
            "size": issue.dk_size or "medium",
        }

        policy_key = {"toolchain": toolchain}

        return build_state_t1(
            domain=domain,
            job_type=job_type,
            features=features,
            policy_key=policy_key,
        )

    def _build_to_state(
        self,
        issue: Issue,
        result: DispatchResult | None,
        verified: bool,
    ) -> dict:
        """Build the terminal state after workcell execution."""
        domain = self._infer_domain(issue)
        job_type = issue.dk_tool_hint or "code"

        # Determine phase based on outcome
        if verified:
            phase = "verified"
        elif result and result.success:
            phase = "edit"  # Made changes but didn't pass gates
        else:
            phase = "failed"

        # Extract failing gate info from proof
        failing_gate = "none"
        if result and result.proof and isinstance(result.proof.verification, dict):
            gates = result.proof.verification.get("gates", {})
            for gate_name, gate_result in gates.items():
                if isinstance(gate_result, dict) and not gate_result.get("passed", False):
                    failing_gate = gate_name
                    break

        features = {
            "phase": phase,
            "failing_gate": failing_gate,
            "attempt": issue.dk_attempts + 1,
            "risk": issue.dk_risk or "medium",
            "size": issue.dk_size or "medium",
        }

        policy_key = {"toolchain": result.toolchain if result else "unknown"}

        return build_state_t1(
            domain=domain,
            job_type=job_type,
            features=features,
            policy_key=policy_key,
        )

    def _record_transition(
        self,
        workcell_id: str,
        issue: Issue,
        result: DispatchResult | None,
        verified: bool,
    ) -> None:
        """Record the state transition to the dynamics database."""
        from_state = self._workcell_from_states.get(workcell_id)
        if not from_state:
            logger.debug("No from_state for transition", workcell_id=workcell_id)
            return

        to_state = self._build_to_state(issue, result, verified)

        import uuid

        transition_id = f"tr_{uuid.uuid4().hex[:12]}"

        transition = {
            "transition_id": transition_id,
            "rollout_id": None,
            "from_state": from_state,
            "to_state": to_state,
            "transition_kind": "workcell_complete",
            "timestamp": _utc_now().isoformat(),
            "context": {
                "workcell_id": workcell_id,
                "issue_id": issue.id,
                "job_type": issue.dk_tool_hint or "code",
                "toolchain": result.toolchain if result else "unknown",
            },
            "action_label": {
                "tool": result.toolchain if result else "unknown",
                "command_class": "dispatch",
                "domain": self._infer_domain(issue),
            },
            "observations": {
                "verified": verified,
                "duration_ms": result.duration_ms if result else 0,
                "confidence": result.proof.confidence if result and result.proof else 0,
            },
        }

        try:
            self.transition_db.insert_transition(transition)
            self.transition_db.conn.commit()
            logger.debug(
                "Recorded transition",
                transition_id=transition_id,
                from_state=from_state.get("state_id"),
                to_state=to_state.get("state_id"),
            )
        except Exception as e:
            logger.warning("Failed to record transition", error=str(e))

        # Cleanup from_state tracking
        self._workcell_from_states.pop(workcell_id, None)

    def _infer_domain(self, issue: Issue) -> str:
        """Infer domain from issue tags."""
        tags = issue.tags or []
        if "fab" in tags or "asset" in tags:
            return "fab_asset"
        if "world" in tags or "scene" in tags:
            return "fab_world"
        return "code"

    def _emit_swarm_episode(
        self,
        workcell_id: str,
        issue_id: str,
        success: bool,
        duration_ms: int,
        toolchain: str | None = None,
    ) -> None:
        """
        Emit a swarm episode completion event for observability.

        This provides real-time episode data for the SwarmWaypoint visualization.
        """
        start_time = self._dispatch_start_times.pop(workcell_id, None)
        now_ms = int(time.time() * 1000)

        if start_time is not None:
            start_ms = int(start_time * 1000)
        else:
            # Fallback: compute from duration
            start_ms = now_ms - duration_ms

        # Build risk flags based on outcome
        risk_flags: list[str] = []
        if not success:
            risk_flags.append("failure")
        if duration_ms > 60000:  # > 1 minute
            risk_flags.append("slow")

        # Estimate work category breakdown
        # In practice, these would come from detailed telemetry
        work_categories = WorkCategories(
            llm=int(duration_ms * 0.6),  # ~60% LLM calls
            tools=int(duration_ms * 0.2),  # ~20% tool execution
            external=int(duration_ms * 0.1),  # ~10% external calls
            gates=int(duration_ms * 0.1),  # ~10% quality gates
        )

        episode = SwarmEpisode(
            id=f"dispatch-{workcell_id}",
            kind="dispatch",
            run_id=workcell_id,
            start_ms=start_ms,
            end_ms=now_ms,
            concurrency=1,
            latency_envelope=LatencyEnvelope(
                p50_ms=duration_ms,
                p95_ms=duration_ms,
                max_ms=duration_ms,
            ),
            work_categories=work_categories,
            risk_flags=risk_flags,
        )

        try:
            self._event_emitter.swarm_episode_complete(
                issue_id=issue_id,
                workcell_id=workcell_id,
                episode_data=episode.to_dict(),
            )
        except Exception as e:
            logger.debug("Failed to emit swarm episode", error=str(e))

    def _emit_swarm_cycle_episode(
        self,
        cycle_number: int,
        scheduled: int,
        completed: int,
        failed: int,
    ) -> None:
        """
        Emit a swarm cycle completion event for observability.

        This provides cycle-level aggregation for the SwarmWaypoint visualization.
        """
        now_ms = int(time.time() * 1000)

        if self._cycle_start_time is not None:
            start_ms = int(self._cycle_start_time * 1000)
            duration_ms = now_ms - start_ms
        else:
            start_ms = now_ms
            duration_ms = 0

        # Build risk flags based on cycle outcome
        risk_flags: list[str] = []
        if failed > 0:
            risk_flags.append("has_failures")
        if scheduled == 0:
            risk_flags.append("no_work")

        episode = SwarmEpisode(
            id=f"cycle-{cycle_number}",
            kind="cycle",
            cycle_number=cycle_number,
            start_ms=start_ms,
            end_ms=now_ms,
            concurrency=max(1, scheduled),
            latency_envelope=LatencyEnvelope(
                p50_ms=duration_ms,
                p95_ms=duration_ms,
                max_ms=duration_ms,
            ),
            risk_flags=risk_flags,
        )

        try:
            self._event_emitter.swarm_cycle_complete(
                cycle_number=cycle_number,
                episode_data=episode.to_dict(),
            )
        except Exception as e:
            logger.debug("Failed to emit swarm cycle episode", error=str(e))
