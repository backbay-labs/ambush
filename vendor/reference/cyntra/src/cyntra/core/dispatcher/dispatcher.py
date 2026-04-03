"""
Dispatcher - Spawns workcells, routes to toolchains, monitors execution.

Responsibilities:
- Create git worktrees for each task
- Write task manifests
- Route tasks to appropriate toolchains via adapters
- Monitor execution and collect results
- Handle timeouts and errors
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from cyntra.core.adapters import get_adapter
from cyntra.core.adapters.base import PatchProof
from cyntra.core.control.exploration_controller import ExplorationController
from cyntra.infra.hooks import HookContext, HookRunner, HookTrigger
from cyntra.core.routing import first_matching_rule, ordered_toolchain_candidates
from cyntra.core.manifests.schema import SecurityPolicy
from cyntra.core.state.manager import FileLock

if TYPE_CHECKING:
    from cyntra.core.scheduler.routing import KernelConfig
    from cyntra.core.state.models import Issue

logger = structlog.get_logger()


def _utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(UTC)


def _deep_merge_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """
    Deterministically merge dictionaries (recursively).

    Non-dict values in `override` replace values in `base`.
    """
    result: dict[str, Any] = dict(base)
    for key, value in override.items():
        existing = result.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            result[key] = _deep_merge_dicts(existing, value)
        else:
            result[key] = value
    return result


@dataclass
class DispatchResult:
    """Result of dispatching a task."""

    success: bool
    proof: PatchProof | None
    workcell_id: str
    issue_id: str
    toolchain: str
    duration_ms: int = 0
    error: str | None = None
    speculate_tag: str | None = None


@dataclass
class SpeculateResult:
    """Result of speculate+vote dispatch."""

    winner: DispatchResult | None
    candidates: list[DispatchResult] = field(default_factory=list)
    all_failed: bool = False


class Dispatcher:
    """
    Spawns workcells and routes tasks to toolchains.

    Uses the adapter system to execute tasks via different
    LLM-powered coding agents (Codex, Claude, etc).
    """

    def __init__(
        self, config: KernelConfig, controller: ExplorationController | None = None
    ) -> None:
        self.config = config
        self.controller = controller or ExplorationController(config)
        self._adapters: dict[str, Any] = {}
        self._init_adapters()
        self.hook_runner = HookRunner(config)

    def _init_adapters(self) -> None:
        """Initialize available adapters."""
        for name in self.config.toolchain_priority:
            tc_config = self.config.toolchains.get(name)
            if tc_config and not tc_config.enabled:
                continue

            adapter_config: dict[str, Any] = {}
            if tc_config:
                adapter_config.update(tc_config.config or {})
                if tc_config.model and "model" not in adapter_config:
                    adapter_config["model"] = tc_config.model
                if tc_config.path and "path" not in adapter_config:
                    adapter_config["path"] = tc_config.path
                if tc_config.env:
                    merged_env = dict(tc_config.env)
                    if isinstance(adapter_config.get("env"), dict):
                        merged_env = {**adapter_config["env"], **merged_env}
                    adapter_config["env"] = merged_env

            adapter = get_adapter(name, adapter_config)
            if adapter:
                self._adapters[name] = adapter
                logger.debug("Adapter initialized", name=name, available=adapter.available)

    def dispatch(
        self,
        issue: Issue,
        workcell_path: Path,
        speculate_tag: str | None = None,
        toolchain_override: str | None = None,
        memory_context: dict[str, Any] | None = None,
        manifest_overrides: dict[str, Any] | None = None,
    ) -> DispatchResult:
        """
        Dispatch a task to a workcell synchronously.

        1. Write task manifest
        2. Invoke toolchain via adapter
        3. Return result with proof
        """
        started_at = _utc_now()
        workcell_id = workcell_path.name

        # Determine toolchain
        toolchain = toolchain_override or self._route_toolchain(issue)

        # Build and write manifest
        manifest = self._build_manifest(issue, workcell_id, toolchain, speculate_tag)

        # Inject memory context if provided
        if memory_context:
            manifest["memory_context"] = memory_context

        if manifest_overrides:
            manifest = _deep_merge_dicts(manifest, manifest_overrides)

        run_dir_value = manifest.get("run_dir")
        if isinstance(run_dir_value, str) and run_dir_value:
            Path(run_dir_value).mkdir(parents=True, exist_ok=True)

        manifest_path = workcell_path / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))

        logger.info(
            "Dispatching to toolchain",
            issue_id=issue.id,
            toolchain=toolchain,
            workcell=workcell_id,
            speculate=speculate_tag,
        )

        # Get adapter
        adapter = self._adapters.get(toolchain)
        if not adapter:
            logger.error("No adapter available", toolchain=toolchain)
            return DispatchResult(
                success=False,
                proof=None,
                workcell_id=workcell_id,
                issue_id=issue.id,
                toolchain=toolchain,
                error=f"No adapter available for {toolchain}",
                speculate_tag=speculate_tag,
            )

        # Get timeout from config
        tc_config = self.config.toolchains.get(toolchain)
        timeout_seconds = 1800  # default 30 min
        if tc_config:
            timeout_seconds = getattr(tc_config, "timeout_seconds", 1800)
        planner = manifest.get("planner") if isinstance(manifest.get("planner"), dict) else {}
        timeout_override = (
            planner.get("timeout_seconds_override") if isinstance(planner, dict) else None
        )
        if isinstance(timeout_override, int) and timeout_override > 0:
            timeout_seconds = timeout_override

        # Execute via adapter
        try:
            proof = adapter.execute_sync(
                manifest=manifest,
                workcell_path=workcell_path,
                timeout_seconds=timeout_seconds,
            )

            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            success = proof.status in ("success", "partial")

            logger.info(
                "Dispatch completed",
                issue_id=issue.id,
                status=proof.status,
                duration_ms=duration_ms,
            )

            # Run post-execution hooks
            if success:
                hook_context = HookContext(
                    workcell_path=workcell_path,
                    workcell_id=workcell_id,
                    issue_id=issue.id,
                    proof=proof,
                    manifest=manifest,
                )
                hook_results = self.hook_runner.run_hooks(
                    HookTrigger.POST_EXECUTION,
                    hook_context,
                )
                # Attach hook results to proof
                if hook_results:
                    proof.review = {
                        "hooks_executed": [h.hook_name for h in hook_results],
                        "recommendations": [r for h in hook_results for r in h.recommendations],
                        "hook_outputs": {h.hook_name: h.output for h in hook_results},
                    }

            return DispatchResult(
                success=success,
                proof=proof,
                workcell_id=workcell_id,
                issue_id=issue.id,
                toolchain=toolchain,
                duration_ms=duration_ms,
                speculate_tag=speculate_tag,
            )

        except Exception as e:
            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            # Use logger.exception to capture full traceback
            logger.exception(
                "Dispatch failed",
                issue_id=issue.id,
                toolchain=toolchain,
                workcell_id=workcell_id,
                error_type=type(e).__name__,
            )

            return DispatchResult(
                success=False,
                proof=None,
                workcell_id=workcell_id,
                issue_id=issue.id,
                toolchain=toolchain,
                duration_ms=duration_ms,
                error=f"{type(e).__name__}: {e}",
                speculate_tag=speculate_tag,
            )

    async def dispatch_async(
        self,
        issue: Issue,
        workcell_path: Path,
        speculate_tag: str | None = None,
        toolchain_override: str | None = None,
        memory_context: dict[str, Any] | None = None,
        manifest_overrides: dict[str, Any] | None = None,
    ) -> DispatchResult:
        """
        Dispatch a task to a workcell asynchronously.
        """
        started_at = _utc_now()
        workcell_id = workcell_path.name

        # Determine toolchain
        toolchain = toolchain_override or self._route_toolchain(issue)

        # Build and write manifest
        manifest = self._build_manifest(issue, workcell_id, toolchain, speculate_tag)

        # Inject memory context if provided
        if memory_context:
            manifest["memory_context"] = memory_context

        if manifest_overrides:
            manifest = _deep_merge_dicts(manifest, manifest_overrides)

        run_dir_value = manifest.get("run_dir")
        if isinstance(run_dir_value, str) and run_dir_value:
            Path(run_dir_value).mkdir(parents=True, exist_ok=True)

        manifest_path = workcell_path / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))

        logger.info(
            "Dispatching async to toolchain",
            issue_id=issue.id,
            toolchain=toolchain,
            workcell=workcell_id,
        )

        # Get adapter
        adapter = self._adapters.get(toolchain)
        if not adapter:
            return DispatchResult(
                success=False,
                proof=None,
                workcell_id=workcell_id,
                issue_id=issue.id,
                toolchain=toolchain,
                error=f"No adapter available for {toolchain}",
                speculate_tag=speculate_tag,
            )

        # Get timeout
        tc_config = self.config.toolchains.get(toolchain)
        timeout_seconds = 1800
        if tc_config:
            timeout_seconds = getattr(tc_config, "timeout_seconds", 1800)
        planner = manifest.get("planner") if isinstance(manifest.get("planner"), dict) else {}
        timeout_override = (
            planner.get("timeout_seconds_override") if isinstance(planner, dict) else None
        )
        if isinstance(timeout_override, int) and timeout_override > 0:
            timeout_seconds = timeout_override

        try:
            proof = await adapter.execute(
                manifest=manifest,
                workcell_path=workcell_path,
                timeout=timedelta(seconds=timeout_seconds),
            )

            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            success = proof.status in ("success", "partial")

            # Run post-execution hooks asynchronously
            if success:
                hook_context = HookContext(
                    workcell_path=workcell_path,
                    workcell_id=workcell_id,
                    issue_id=issue.id,
                    proof=proof,
                    manifest=manifest,
                )
                hook_results = await self.hook_runner.run_hooks_async(
                    HookTrigger.POST_EXECUTION,
                    hook_context,
                )
                if hook_results:
                    proof.review = {
                        "hooks_executed": [h.hook_name for h in hook_results],
                        "recommendations": [r for h in hook_results for r in h.recommendations],
                        "hook_outputs": {h.hook_name: h.output for h in hook_results},
                    }

            return DispatchResult(
                success=success,
                proof=proof,
                workcell_id=workcell_id,
                issue_id=issue.id,
                toolchain=toolchain,
                duration_ms=duration_ms,
                speculate_tag=speculate_tag,
            )

        except Exception as e:
            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            # Use logger.exception to capture full traceback
            logger.exception(
                "Async dispatch failed",
                issue_id=issue.id,
                toolchain=toolchain,
                workcell_id=workcell_id,
                error_type=type(e).__name__,
            )

            return DispatchResult(
                success=False,
                proof=None,
                workcell_id=workcell_id,
                issue_id=issue.id,
                toolchain=toolchain,
                duration_ms=duration_ms,
                error=f"{type(e).__name__}: {e}",
                speculate_tag=speculate_tag,
            )

    async def dispatch_speculate(
        self,
        issue: Issue,
        workcell_paths: list[tuple[str, Path]],
    ) -> SpeculateResult:
        """
        Dispatch multiple parallel workcells for speculate+vote.

        Args:
            issue: The issue to work on
            workcell_paths: List of (speculate_tag, workcell_path) tuples

        Returns:
            SpeculateResult with winner and all candidates
        """
        logger.info(
            "Dispatching speculate+vote",
            issue_id=issue.id,
            parallelism=len(workcell_paths),
        )

        # Launch all dispatches in parallel
        tasks = [self.dispatch_async(issue, path, tag) for tag, path in workcell_paths]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter to successful results
        candidates: list[DispatchResult] = []
        for result in results:
            if isinstance(result, DispatchResult):
                candidates.append(result)
            elif isinstance(result, Exception):
                logger.error("Speculate dispatch failed", error=str(result))

        if not candidates:
            return SpeculateResult(winner=None, candidates=[], all_failed=True)

        # Find winner (first successful with passing gates)
        winner = None
        for candidate in candidates:
            if (
                candidate.success
                and candidate.proof
                and candidate.proof.verification.get("all_passed", False)
            ):
                winner = candidate
                break

        # If no verified winner, take best successful one
        if not winner:
            successful = [c for c in candidates if c.success]
            if successful:
                # Sort by confidence
                successful.sort(
                    key=lambda x: x.proof.confidence if x.proof else 0,
                    reverse=True,
                )
                winner = successful[0]

        return SpeculateResult(
            winner=winner,
            candidates=candidates,
            all_failed=winner is None,
        )

    def apply_patch(self, proof: PatchProof, workcell_path: Path) -> bool:
        """Apply the workcell's patch to the integration branch (main)."""
        lock_path = self.config.repo_root / ".cyntra" / "locks" / "merge.lock"
        lock = FileLock(lock_path, timeout=120.0)
        with lock.locked(exclusive=True) as acquired:
            if not acquired:
                self._set_merge_metadata(proof, status="failed", error="merge_lock_timeout")
                logger.error("Merge lock timeout", path=str(lock_path))
                return False

            try:
                branch = proof.patch.get("branch", "")
                if not branch:
                    result = subprocess.run(
                        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                        cwd=workcell_path,
                        capture_output=True,
                        text=True,
                    )
                    branch = result.stdout.strip()

                if not branch:
                    self._set_merge_metadata(proof, status="failed", error="missing_branch")
                    logger.error("No branch to merge")
                    return False

                target_branch = self._resolve_integration_branch()
                merge_repo_root = self._get_branch_worktree(target_branch) or self.config.repo_root
                restore_branch = self._get_current_branch(merge_repo_root)

                # Stash local changes only in the worktree where merge runs.
                stashed = False
                if not self._repo_is_clean(merge_repo_root):
                    stash_result = subprocess.run(
                        ["git", "stash", "push", "--include-untracked", "-m", f"cyntra-merge-{branch}"],
                        cwd=merge_repo_root,
                        capture_output=True,
                        text=True,
                    )
                    if stash_result.returncode == 0 and "No local changes" not in stash_result.stdout:
                        stashed = True
                        logger.info(
                            "Stashed local changes before merge",
                            branch=branch,
                            merge_repo_root=str(merge_repo_root),
                        )
                    elif stash_result.returncode != 0:
                        self._set_merge_metadata(
                            proof, status="failed", error="stash_failed_pre_merge", branch=branch
                        )
                        logger.error(
                            "Failed to stash before merge",
                            error=stash_result.stderr.strip(),
                            branch=branch,
                            merge_repo_root=str(merge_repo_root),
                        )
                        return False

                if restore_branch != target_branch:
                    checkout = subprocess.run(
                        ["git", "checkout", target_branch],
                        cwd=merge_repo_root,
                        capture_output=True,
                        text=True,
                    )
                    if checkout.returncode != 0:
                        if stashed:
                            subprocess.run(
                                ["git", "stash", "pop"],
                                cwd=merge_repo_root,
                                capture_output=True,
                                text=True,
                            )
                        self._set_merge_metadata(
                            proof,
                            status="failed",
                            error=f"checkout_target_failed: {checkout.stderr.strip()}",
                            branch=branch,
                        )
                        logger.error(
                            "Failed to checkout integration branch",
                            error=checkout.stderr.strip(),
                            target_branch=target_branch,
                            merge_repo_root=str(merge_repo_root),
                        )
                        return False

                merge = subprocess.run(
                    ["git", "merge", branch, "--no-ff", "-m", f"Merge {branch}"],
                    cwd=merge_repo_root,
                    capture_output=True,
                    text=True,
                )

                if merge.returncode != 0:
                    subprocess.run(
                        ["git", "merge", "--abort"],
                        cwd=merge_repo_root,
                        capture_output=True,
                        text=True,
                    )
                    if restore_branch and restore_branch != target_branch:
                        subprocess.run(
                            ["git", "checkout", restore_branch],
                            cwd=merge_repo_root,
                            capture_output=True,
                            text=True,
                        )
                    if stashed:
                        subprocess.run(
                            ["git", "stash", "pop"],
                            cwd=merge_repo_root,
                            capture_output=True,
                            text=True,
                        )
                    error_summary = merge.stderr.strip() or "merge_failed"
                    self._set_merge_metadata(
                        proof,
                        status="failed",
                        error=error_summary,
                        branch=branch,
                    )
                    logger.error("Failed to merge", error=error_summary, branch=branch)
                    return False

                if restore_branch and restore_branch != target_branch:
                    subprocess.run(
                        ["git", "checkout", restore_branch],
                        cwd=merge_repo_root,
                        capture_output=True,
                        text=True,
                    )

                if stashed:
                    subprocess.run(
                        ["git", "stash", "pop"],
                        cwd=merge_repo_root,
                        capture_output=True,
                        text=True,
                    )
                    logger.info(
                        "Restored stashed changes after merge",
                        branch=branch,
                        merge_repo_root=str(merge_repo_root),
                    )

                self._set_merge_metadata(proof, status="success", branch=branch)
                logger.info(
                    "Patch applied",
                    branch=branch,
                    target_branch=target_branch,
                    merge_repo_root=str(merge_repo_root),
                )
                return True

            except Exception as e:
                self._set_merge_metadata(proof, status="failed", error=str(e))
                logger.error("Failed to apply patch", error=str(e))
                return False

    def _get_branch_worktree(self, branch: str) -> Path | None:
        """
        Return a worktree path where `branch` is currently checked out.

        Uses `git worktree list --porcelain` and matches entries with
        `branch refs/heads/<branch>`.
        """
        result = subprocess.run(
            ["git", "worktree", "list", "--porcelain"],
            cwd=self.config.repo_root,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return None

        target_ref = f"refs/heads/{branch}"
        current_path: Path | None = None
        current_ref: str | None = None

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                if current_path and current_ref == target_ref:
                    return current_path
                current_path = None
                current_ref = None
                continue

            if line.startswith("worktree "):
                current_path = Path(line.removeprefix("worktree ").strip())
            elif line.startswith("branch "):
                current_ref = line.removeprefix("branch ").strip()

        if current_path and current_ref == target_ref:
            return current_path
        return None

    def _resolve_integration_branch(self) -> str:
        """
        Resolve the target integration branch for merges.

        Resolution order:
        1. `CYNTRA_INTEGRATION_BRANCH` environment override.
        2. Current branch in repo root (if not detached).
        3. Existing local branch `main`, then `master`.
        4. Fallback `main`.
        """
        env_branch = (os.environ.get("CYNTRA_INTEGRATION_BRANCH") or "").strip()
        if env_branch:
            return env_branch

        current = self._get_current_branch(self.config.repo_root)
        if current and current != "HEAD":
            return current

        for candidate in ("main", "master"):
            exists = subprocess.run(
                ["git", "show-ref", "--verify", f"refs/heads/{candidate}"],
                cwd=self.config.repo_root,
                capture_output=True,
                text=True,
            )
            if exists.returncode == 0:
                return candidate

        return "main"

    def _repo_is_clean(self, repo_root: Path) -> bool:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        return result.returncode == 0 and result.stdout.strip() == ""

    def _get_current_branch(self, repo_root: Path) -> str | None:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return None
        branch = result.stdout.strip()
        return branch or None

    def _set_merge_metadata(
        self,
        proof: PatchProof,
        *,
        status: str,
        error: str | None = None,
        branch: str | None = None,
    ) -> None:
        patch = proof.patch or {}
        patch["merge_status"] = status
        if branch:
            patch["merge_branch"] = branch
        if error:
            patch["merge_error"] = error
        proof.patch = patch

    def _route_toolchain(self, issue: Issue) -> str:
        """Route issue to appropriate toolchain based on rules."""
        # Check explicit hint from issue
        if issue.dk_tool_hint and issue.dk_tool_hint in self._adapters:
            return issue.dk_tool_hint

        candidates = ordered_toolchain_candidates(self.config, issue)
        chosen = self._first_available_toolchain(candidates)
        if chosen:
            return chosen

        # Default to first in priority
        return self.config.toolchain_priority[0] if self.config.toolchain_priority else "codex"

    def _first_available_toolchain(self, toolchains: list[str]) -> str | None:
        """Return first toolchain with an available adapter."""
        for name in toolchains:
            adapter = self._adapters.get(name)
            if adapter and adapter.available:
                return name
        return None

    def _build_manifest(
        self,
        issue: Issue,
        workcell_id: str,
        toolchain: str,
        speculate_tag: str | None,
    ) -> dict[str, Any]:
        """Build task manifest for workcell."""
        # Get issue tags for routing
        tags = getattr(issue, "tags", []) or []
        manifest_tags = list(tags)
        # Ensure dk_* dimensions are always available to adapters (for routing, prompt genomes,
        # knowledge injection, and reasoning-effort mapping).
        if issue.dk_size and not any(t.startswith("dk_size:") for t in manifest_tags):
            manifest_tags.append(f"dk_size:{issue.dk_size}")
        if issue.dk_risk and not any(t.startswith("dk_risk:") for t in manifest_tags):
            manifest_tags.append(f"dk_risk:{issue.dk_risk}")

        # Build quality gates based on issue tags (or explicit override on the issue).
        quality_gates = self._build_quality_gates(tags)

        # Detect world build jobs
        job_type = "code"  # Default
        world_config = None
        lease_hash = getattr(issue, "dk_lease_hash", None)

        if "asset:world" in tags:
            job_type = "fab-world"
            world_config = self._build_world_config(issue, tags)
            # World builds run their own gates as part of the fab-world pipeline.
            # Avoid accidentally running generic fab/code gates in the verifier.
            quality_gates = {}
        elif getattr(issue, "dk_quality_gates", None):
            dk_gates = issue.dk_quality_gates
            if isinstance(dk_gates, dict) and dk_gates:
                quality_gates = dk_gates

        run_id = workcell_id
        run_dir = self.config.repo_root / ".cyntra" / "runs" / run_id
        security_policy = self._build_security_policy(issue)

        manifest = {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "run_dir": str(run_dir),
            "workcell_id": workcell_id,
            "branch_name": f"wc/{issue.id}/{workcell_id.removeprefix(f'wc-{issue.id}-')}",
            "apply_patch": bool(getattr(issue, "dk_apply_patch", True)),
            "issue": {
                "id": issue.id,
                "title": issue.title,
                "description": issue.description,
                "acceptance_criteria": issue.acceptance_criteria or [],
                "context_files": issue.context_files or [],
                "forbidden_paths": issue.dk_forbidden_paths or [],
                "dk_priority": issue.dk_priority,
                "dk_risk": issue.dk_risk,
                "dk_size": issue.dk_size,
                "dk_tool_hint": issue.dk_tool_hint,
                "dk_estimated_tokens": issue.dk_estimated_tokens,
                "tags": manifest_tags,  # Include tags for gate routing + dk_* dimensions
            },
            "job_type": job_type,
            "toolchain": toolchain,
            "toolchain_config": {
                "model": self._get_model_for_toolchain(toolchain),
            },
            "quality_gates": quality_gates,
            "security_policy": security_policy,
            "speculate_mode": speculate_tag is not None,
            "speculate_tag": speculate_tag,
            "metadata": {
                "lease_hash": lease_hash,
            },
        }

        # Propagate execution_mode hint from the matched routing rule.
        matched_rule = first_matching_rule(self.config, issue)
        if matched_rule and matched_rule.execution_mode:
            manifest["toolchain_config"]["execution_mode"] = matched_rule.execution_mode

        strategy_cfg = self._build_strategy_config(issue=issue, toolchain=toolchain)
        if strategy_cfg:
            manifest["strategy"] = strategy_cfg

        try:
            from cyntra.infra.prompts.runtime import detect_domain, load_prompt_genome
            from cyntra.infra.prompts.selector import select_prompt_genome_id

            domain = detect_domain(str(job_type))
            prompt_genome_id = getattr(issue, "dk_prompt_genome_id", None)
            if not prompt_genome_id:
                prompt_genome_id = select_prompt_genome_id(
                    repo_root=self.config.repo_root,
                    domain=domain,
                    toolchain=toolchain,
                )

            if isinstance(prompt_genome_id, str) and prompt_genome_id.strip():
                manifest["toolchain_config"]["prompt_genome_id"] = prompt_genome_id.strip()

                # If the controller didn't set sampling yet, fall back to genome defaults.
                if "sampling" not in manifest["toolchain_config"]:
                    genome = load_prompt_genome(
                        prompts_root=self.config.repo_root / "prompts",
                        domain=domain,
                        toolchain=toolchain,
                        genome_id=prompt_genome_id.strip(),
                    )
                    if isinstance(genome, dict):
                        sampling_cfg = genome.get("sampling")
                        if isinstance(sampling_cfg, dict):
                            temperature = sampling_cfg.get("temperature")
                            top_p = sampling_cfg.get("top_p")
                            manifest["toolchain_config"]["sampling"] = {
                                "temperature": float(temperature)
                                if isinstance(temperature, (int, float))
                                else None,
                                "top_p": float(top_p) if isinstance(top_p, (int, float)) else None,
                            }
        except Exception:
            # Prompt genomes are optional; selection is best-effort.
            pass

        sampling_override = getattr(issue, "dk_sampling", None)
        if isinstance(sampling_override, dict) and sampling_override:
            temperature = sampling_override.get("temperature")
            top_p = sampling_override.get("top_p")
            sampling_override = {
                "temperature": float(temperature)
                if isinstance(temperature, (int, float))
                else None,
                "top_p": float(top_p) if isinstance(top_p, (int, float)) else None,
            }
        else:
            sampling_override = None

        decision = self.controller.decide(issue)
        controller_sampling = self.controller.sampling_for_issue(issue)
        sampling = sampling_override or controller_sampling
        if not sampling:
            sampling = manifest.get("toolchain_config", {}).get("sampling")
        if sampling:
            manifest["toolchain_config"]["sampling"] = sampling
        manifest["control"] = {
            "mode": decision.mode,
            "reason": decision.reason,
            "action_rate": decision.action_rate,
            "speculate_parallelism": decision.speculate_parallelism,
            "sampling": sampling,
        }

        if world_config:
            manifest["world_config"] = world_config

        return manifest

    def _build_quality_gates(self, tags: list[str]) -> dict[str, Any]:
        """
        Build quality gates configuration based on issue tags.

        Asset-tagged issues get fab-realism gates instead of/in addition to code gates.
        """
        # Default code gates
        gates: dict[str, Any] = {
            "test": self.config.gates.test_command,
            "typecheck": self.config.gates.typecheck_command,
            "lint": self.config.gates.lint_command,
        }
        build_command = getattr(self.config.gates, "build_command", None)
        if isinstance(build_command, str) and build_command.strip():
            gates["build"] = build_command

        max_diff_lines = self.config.gates.max_diff_lines
        max_diff_files = self.config.gates.max_diff_files
        if max_diff_lines is not None or max_diff_files is not None:
            diff_gate: dict[str, Any] = {"type": "diff-check"}
            if max_diff_lines is not None:
                diff_gate["max_lines"] = max_diff_lines
            if max_diff_files is not None:
                diff_gate["max_files"] = max_diff_files
            gates["max-diff-size"] = diff_gate

        if bool(self.config.gates.secret_detection):
            secret_gate: dict[str, Any] = {"type": "diff-check"}
            secret_gate["scan_diff"] = bool(self.config.gates.secret_detection_scan_diff)
            if self.config.gates.secret_detection_max_bytes:
                secret_gate["max_bytes"] = int(self.config.gates.secret_detection_max_bytes)
            gates["secret-detection"] = secret_gate

        # Check for asset tags that require fab-realism gate
        asset_tags = [t for t in tags if t.startswith("asset:")]
        gate_tags = [t for t in tags if t.startswith("gate:")]

        if asset_tags or "gate:realism" in gate_tags:
            # Determine asset category from tags
            category = "car"  # Default
            for tag in asset_tags:
                # Extract category from "asset:car", "asset:vehicle", etc.
                parts = tag.split(":")
                if len(parts) >= 2:
                    category = parts[1]
                    break

            # Normalize common aliases to supported fab gate categories/configs.
            category_aliases = {
                # Vehicles
                "vehicle": "car",
                # Furniture
                "chair": "furniture",
                "table": "furniture",
                # Architecture
                "building": "architecture",
                "house": "architecture",
                # Interiors (fab gate config is named "interior_library_v001")
                "interior_architecture": "interior",
                "library": "interior",
            }
            normalized_category = category_aliases.get(category, category)

            # Determine gate config from tags
            default_gate_config_by_category = {
                "car": "car_realism_v001",
                "furniture": "furniture_realism_v001",
                "architecture": "architecture_realism_v001",
                "interior": "interior_library_v001",
            }
            gate_config_id = default_gate_config_by_category.get(
                normalized_category, f"{normalized_category}_realism_v001"
            )
            for tag in gate_tags:
                if tag.startswith("gate:config:"):
                    gate_config_id = tag.replace("gate:config:", "")
                    break

            # Add fab-realism gate
            gates["fab-realism"] = {
                "type": "fab-realism",
                "category": category,
                "gate_config_id": gate_config_id,
                "command": f"python -m cyntra.fab.gate --asset {{asset_path}} --config {gate_config_id} --out {{output_dir}}",
            }

            # Optional engine integration gate (Godot Web export)
            if "gate:godot" in gate_tags or "gate:engine" in gate_tags:
                godot_config_id = "godot_integration_v001"
                for tag in gate_tags:
                    if tag.startswith("gate:godot-config:"):
                        godot_config_id = tag.replace("gate:godot-config:", "")
                        break

                gates["fab-godot"] = {
                    "type": "fab-godot",
                    "gate_config_id": godot_config_id,
                    # Workcell-relative path (works for monorepo tasks)
                    "template_dir": "fab/godot/template",
                }

            # Optional playability gate (NitroGen automated testing)
            # Check for gate:playability, gate:nitrogen, or gate:playability-config:*
            has_playability_tag = (
                "gate:playability" in gate_tags
                or "gate:nitrogen" in gate_tags
                or any(t.startswith("gate:playability-config:") for t in gate_tags)
            )
            if has_playability_tag:
                playability_config_id = "gameplay_playability_v001"
                for tag in gate_tags:
                    if tag.startswith("gate:playability-config:"):
                        playability_config_id = tag.replace("gate:playability-config:", "")
                        break

                gates["fab-playability"] = {
                    "type": "fab-playability",
                    "gate_config_id": playability_config_id,
                }

            # For asset-only issues, disable code gates
            if "gate:asset-only" in gate_tags:
                gates.pop("test", None)
                gates.pop("typecheck", None)
                gates.pop("lint", None)
                gates.pop("build", None)

        # Backbay Imperium (Rust + optional Godot QA) gates.
        if "gate:backbay" in gate_tags:
            gates["backbay-test"] = "cd research/backbay-imperium && cargo test"

        if "gate:backbay-qa" in gate_tags:
            gates["backbay-qa"] = (
                "cd research/backbay-imperium && ./scripts/build_godot_bridge.sh && cd ../.. && "
                "scripts/godot-qa-runner.sh --project research/backbay-imperium/client "
                "--scene res://tests/run_all_tests.tscn && "
                "scripts/godot-qa-runner.sh --project research/backbay-imperium/client "
                "--scene res://tests/qa_validate_scripts.tscn && "
                "python skills/development/visual-qa.py --mode compare --capture-mode all"
            )

        return gates

    def _build_security_policy(self, issue: Issue) -> dict[str, Any]:
        """Build a security policy snapshot for the agent prompt and proof."""
        policy = SecurityPolicy()
        forbidden = getattr(issue, "dk_forbidden_paths", None) or []
        policy.forbidden_paths = [str(path) for path in forbidden if path]
        return policy.to_dict()

    def _build_strategy_config(self, *, issue: Issue, toolchain: str) -> dict[str, Any] | None:
        """
        Build strategy telemetry + routing configuration for this manifest.

        This is intentionally compact and deterministic:
        - Always file-first (manifest captures decisions for replay)
        - No verbose chain-of-thought storage required
        """
        strategy = getattr(self.config, "strategy", None)
        if not strategy or not bool(getattr(strategy, "enabled", False)):
            return None

        prompt_style = str(getattr(strategy, "prompt_style", "compact") or "compact").strip()
        prompt_style = prompt_style.lower()
        if prompt_style not in {"compact", "full"}:
            prompt_style = "compact"

        cfg: dict[str, Any] = {
            "enabled": True,
            "prompt_style": prompt_style,
            "self_report": bool(getattr(strategy, "self_report", True)),
        }

        routing = getattr(strategy, "routing", None)
        if not routing or not bool(getattr(routing, "enabled", False)):
            return cfg

        mode = str(getattr(routing, "mode", "dataset_optimal") or "dataset_optimal").strip().lower()
        if mode not in {"dataset_optimal"}:
            return cfg

        # Deterministic A/B bucketing (based only on issue_id).
        ab_enabled = bool(getattr(routing, "ab_test_enabled", False))
        ab_ratio_raw = getattr(routing, "ab_test_ratio", 0.5)
        ab_ratio = float(ab_ratio_raw) if isinstance(ab_ratio_raw, (int, float)) else 0.5
        ab_ratio = max(0.0, min(1.0, ab_ratio))
        ab_salt = str(getattr(routing, "ab_test_salt", "") or "").strip() or "cyntra.strategy.ab.v1"

        bucket_value = int(
            hashlib.sha256(f"{ab_salt}:{issue.id}".encode("utf-8")).hexdigest(), 16
        ) % 10_000
        treatment_cutoff = int(ab_ratio * 10_000)
        is_treatment = (bucket_value < treatment_cutoff) if ab_enabled else True

        cfg["routing"] = {
            "mode": "dataset_optimal",
            "ab_test_enabled": ab_enabled,
            "ab_test_ratio": ab_ratio,
            "ab_bucket_value": bucket_value,
            "ab_bucket": "treatment" if is_treatment else "control",
        }

        if not is_treatment:
            return cfg

        # Fetch dataset-wide optimal patterns from the local dynamics DB.
        patterns = self._get_dataset_optimal_patterns(toolchain=toolchain, routing=routing)
        if not patterns:
            return cfg

        digest = hashlib.sha256(
            json.dumps(patterns, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )
        ).hexdigest()

        cfg["directive"] = {
            "source": "dataset_optimal",
            "toolchain_scope": toolchain if bool(getattr(routing, "per_toolchain", True)) else None,
            "outcome": str(getattr(routing, "outcome", "passed") or "passed"),
            "min_confidence": float(getattr(routing, "min_confidence", 0.5) or 0.5),
            "patterns": patterns,
            "directive_hash": f"stg_{digest[:12]}",
        }

        return cfg

    def _get_dataset_optimal_patterns(
        self, *, toolchain: str, routing: Any
    ) -> dict[str, str]:
        """Query dataset-wide optimal patterns (most common on successful runs)."""
        db_path = self.config.repo_root / ".cyntra" / "dynamics" / "cyntra.db"
        if not db_path.exists():
            return {}

        try:
            from cyntra.cognition.dynamics.transition_db import TransitionDB

            outcome = str(getattr(routing, "outcome", "passed") or "passed")
            min_conf = float(getattr(routing, "min_confidence", 0.5) or 0.5)
            per_toolchain = bool(getattr(routing, "per_toolchain", True))
            db = TransitionDB(db_path)
            try:
                return db.get_optimal_strategy_for(
                    toolchain=toolchain if per_toolchain else None,
                    outcome=outcome,
                    min_confidence=min_conf,
                )
            finally:
                db.close()
        except Exception:
            return {}

    def _build_world_config(self, issue: Issue, tags: list[str]) -> dict[str, Any]:
        """
        Build world-specific configuration for fab-world jobs.

        Extracts world parameters from issue description or tags.
        """
        # Default world config
        config = {
            "world_path": "fab/worlds/outora_library",  # Default to outora
            "seed": 42,
            "param_overrides": {},
        }

        # Look for world: tag
        for tag in tags:
            if tag.startswith("world:"):
                world_id = tag.split(":", 1)[1]
                config["world_path"] = f"fab/worlds/{world_id}"
                break

        # Look for seed: tag
        for tag in tags:
            if tag.startswith("seed:"):
                try:
                    seed = int(tag.split(":", 1)[1])
                    config["seed"] = seed
                except ValueError:
                    pass
                break

        # Look for param: tags (e.g., param:lighting.preset=cosmic)
        for tag in tags:
            if tag.startswith("param:"):
                param_spec = tag.split(":", 1)[1]
                if "=" in param_spec:
                    key, value = param_spec.split("=", 1)
                    config["param_overrides"][key] = value

        # Determine gates for this world
        gate_configs = []
        for tag in tags:
            if tag.startswith("gate:"):
                gate_name = tag.split(":", 1)[1]
                # Skip generic gate: tags like gate:realism
                if gate_name not in [
                    "realism",
                    "quality",
                    "godot",
                    "engine",
                    "playability",
                    "nitrogen",
                ]:
                    gate_configs.append(f"fab/gates/{gate_name}_v001.yaml")

        # Default gates for world jobs
        if not gate_configs:
            gate_configs = [
                "fab/gates/interior_library_v001.yaml",
                "fab/gates/godot_integration_v001.yaml",
            ]

        # Add playability gate based on world type
        world_id = config.get("world_path", "").split("/")[-1]
        playability_gate_map = {
            "enchanted_forest": "gameplay_playability_forest_v001",
            "dark_dungeon": "gameplay_playability_dungeon_v001",
            "orbital_station": "gameplay_playability_scifi_v001",
            "outora_library": "gameplay_playability_gothic_v001",
        }

        if world_id in playability_gate_map:
            gate_configs.append(f"fab/gates/{playability_gate_map[world_id]}.yaml")
        elif "gate:playability" in tags or "gate:nitrogen" in tags:
            # Use default playability gate
            gate_configs.append("fab/gates/gameplay_playability_v001.yaml")

        config["quality_gates"] = gate_configs

        return config

    def _get_model_for_toolchain(self, toolchain: str) -> str:
        """Get the model to use for a toolchain."""
        tc_config = self.config.toolchains.get(toolchain)
        if tc_config:
            model = getattr(tc_config, "model", None)
            if model:
                return model

        # Defaults
        defaults = {
            "codex": "gpt-5.2",
            "claude": "claude-opus-4-5-20251101",
        }
        return defaults.get(toolchain, "")

    def get_available_toolchains(self) -> list[str]:
        """Get list of available toolchains."""
        return [name for name, adapter in self._adapters.items() if adapter.available]
