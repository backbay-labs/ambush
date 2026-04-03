"""
Verifier - Runs quality gates, compares candidates, implements vote selection.

Responsibilities:
- Run quality gates on workcell output
- Validate diffs against forbidden paths
- Compare speculate candidates
- Select winner via voting algorithm
- Support manifest-driven gates (including fab-realism for assets)
"""

from __future__ import annotations

import contextlib
import json
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

import structlog

from hellcat.core.adapters.base import PatchProof
from hellcat.core.gates.results import (
    build_verification_payload,
    default_blocking_for_gate_type,
    emit_gates_event,
)
from hellcat.core.gates.results import (
    normalize_gate_result as normalize_gate_result_shared,
)
from hellcat.core.gates.runner import GateConfig, GateResult, GateRunner
from hellcat.core.state.manager import FileLock
from hellcat.infra.hooks import HookContext, HookRunner, HookTrigger

try:
    from hellcat.cognition.rollouts.builder import write_rollout
except ImportError:
    write_rollout = None

if TYPE_CHECKING:
    from hellcat.core.scheduler.routing import KernelConfig

logger = structlog.get_logger()


def _utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


@dataclass
class VerificationResult:
    """Result of verifying a workcell's output."""

    workcell_id: str
    all_passed: bool
    gate_results: dict[str, dict]
    blocking_failures: list[str]
    forbidden_path_violations: list[str]


@dataclass
class GateSpec:
    config: GateConfig
    parallel: bool = False
    fail_fast: bool = False
    blocking: bool = True
    cache: bool = True
    cache_ttl_seconds: int | None = None
    paths: list[str] | None = None
    paths_exclude: list[str] | None = None
    gate_type: str = "code"


class Verifier:
    """
    Runs quality gates and implements vote selection.

    The verifier is responsible for:
    1. Running all quality gates (test, typecheck, lint)
    2. Checking for forbidden path violations
    3. Scoring and selecting winners in speculate+vote mode
    """

    def __init__(self, config: KernelConfig) -> None:
        self.config = config
        self.hook_runner = HookRunner(config)

    def verify(self, proof: PatchProof, workcell_path: Path) -> bool:
        """
        Verify a workcell's output.

        Returns True if verification passes.
        """

        return self._run_verify_sync(proof, workcell_path)

    async def verify_async(self, proof: PatchProof, workcell_path: Path) -> bool:
        """Async verification with timeout/retry-aware gate execution."""
        return await self._run_verify_async(proof, workcell_path)

    def _run_verify_sync(self, proof: PatchProof, workcell_path: Path) -> bool:
        """Run verification in a synchronous context."""
        try:
            import asyncio

            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self._run_verify_async(proof, workcell_path))

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=1) as executor:
            def _run() -> bool:
                import asyncio

                return asyncio.run(self._run_verify_async(proof, workcell_path))

            future = executor.submit(_run)
            return future.result()

    async def _run_verify_async(self, proof: PatchProof, workcell_path: Path) -> bool:
        """Shared verification implementation for sync/async entrypoints."""
        workcell_id = workcell_path.name
        logs_dir = self.config.logs_dir

        # Check forbidden paths
        violations = self._check_forbidden_paths(proof)
        if violations:
            logger.warning(
                "Forbidden path violations",
                workcell_id=workcell_id,
                violations=violations,
            )
            results = {
                "forbidden_paths": self._normalize_gate_result(
                    name="forbidden_paths",
                    result={
                        "passed": False,
                        "violations": violations,
                        "reason": "Forbidden path modifications detected",
                        "duration_ms": 0,
                        "blocking": True,
                    },
                    gate_type="policy",
                )
            }
            verification = build_verification_payload(results)
            verification["all_passed"] = False
            proof.verification = verification
            self._persist_proof(proof, workcell_path)
            emit_gates_event(
                logs_dir=logs_dir,
                workcell_id=workcell_id,
                passed=False,
                results=verification.get("gates", {}),
                summary=verification.get("gate_summary"),
            )
            return False

        # If the toolchain execution itself failed, do not allow downstream gates to
        # "green" the run (a failed execution cannot be considered verified).
        if proof.status not in ("success", "partial"):
            verification = proof.verification if isinstance(proof.verification, dict) else {}
            gates = verification.get("gates")
            if not isinstance(gates, dict):
                gates = {}
            verification_payload = build_verification_payload(gates)
            blocking = verification_payload.get("blocking_failures")
            if not isinstance(blocking, list):
                blocking = []
            status_marker = f"status:{proof.status}"
            if status_marker not in blocking:
                blocking.append(status_marker)
            verification_payload["blocking_failures"] = blocking
            verification_payload["all_passed"] = False
            proof.verification = verification_payload
            self._persist_proof(proof, workcell_path)
            emit_gates_event(
                logs_dir=logs_dir,
                workcell_id=workcell_id,
                passed=False,
                results=verification_payload.get("gates", {}),
                summary=verification_payload.get("gate_summary"),
            )
            return False

        # PSN: maturity lockdown for battle-tested skills (ensure critical workflow
        # primitives aren't casually modified).
        lockdown_violations = self._check_skill_maturity_lockdown(workcell_path, proof)
        if lockdown_violations:
            results = {
                "psn-maturity-lockdown": self._normalize_gate_result(
                    name="psn-maturity-lockdown",
                    result={
                        "passed": False,
                        "blocked_skills": lockdown_violations,
                        "reason": "Attempted to modify mature skill(s) without override tag",
                        "duration_ms": 0,
                        "blocking": True,
                    },
                    gate_type="policy",
                )
            }
            verification = build_verification_payload(results)
            verification["all_passed"] = False
            proof.verification = verification

            self._persist_proof(proof, workcell_path)
            emit_gates_event(
                logs_dir=logs_dir,
                workcell_id=workcell_id,
                passed=False,
                results=verification.get("gates", {}),
                summary=verification.get("gate_summary"),
            )
            return False

        # Check if proof already has passing verification
        verification = proof.verification
        if isinstance(verification, dict) and verification.get("all_passed"):
            return True

        # Load gates from manifest (manifest-driven gates)
        gates_config = self._load_gates_from_manifest(workcell_path)

        changed_files = self._get_changed_files(proof)

        diff_gates: dict[str, Any] = {}
        fab_gates: dict[str, Any] = {}
        llm_eval_gates: dict[str, Any] = {}
        code_gates: dict[str, Any] = {}
        for name, cfg in gates_config.items():
            gate_type = ""
            if isinstance(cfg, dict) and isinstance(cfg.get("type"), str):
                gate_type = cfg.get("type", "")
            normalized_type = gate_type.strip().lower()
            if normalized_type in {"diff-check", "diff_check"} or name in {"max-diff-size", "secret-detection"}:
                diff_gates[name] = cfg
            elif name.startswith("fab-") or normalized_type.startswith("fab-"):
                fab_gates[name] = cfg
            elif name.startswith("llm-") or normalized_type == "llm-eval":
                llm_eval_gates[name] = cfg
            else:
                code_gates[name] = cfg

        results: dict[str, dict[str, Any]] = {}
        if diff_gates:
            diff_results = self._run_diff_gates(
                diff_gates,
                proof=proof,
                workcell_path=workcell_path,
                changed_files=changed_files,
            )
            results.update(diff_results)
            diff_verification = build_verification_payload(results)
            diff_blocking = diff_verification.get("blocking_failures", [])
            if isinstance(diff_blocking, list) and diff_blocking:
                diff_verification["all_passed"] = False
                proof.verification = diff_verification
                self._persist_proof(proof, workcell_path)
                emit_gates_event(
                    logs_dir=logs_dir,
                    workcell_id=workcell_id,
                    passed=False,
                    results=diff_verification.get("gates", {}),
                    summary=diff_verification.get("gate_summary"),
                )
                return False

        gate_cache = self._load_gate_cache()
        cache_entries = gate_cache.get("entries")
        if not isinstance(cache_entries, dict):
            cache_entries = {}
        cache_updated = False
        repo_head = self._get_repo_head(workcell_path)
        gate_files_map: dict[str, list[str]] = {}

        budget_ms = getattr(self.config.gates, "total_budget_ms", None)
        budget_deadline = None
        if isinstance(budget_ms, int) and budget_ms > 0:
            budget_deadline = time.monotonic() + (budget_ms / 1000.0)

        runner = GateRunner(
            logs_dir=workcell_path / "logs",
            cwd=workcell_path,
            gates_config=code_gates,
        )

        gate_specs, config_errors = self._normalize_gate_specs(
            code_gates,
            default_parallel=bool(getattr(self.config.gates, "parallel", False)),
            gate_type="code",
            default_cache=True,
        )
        llm_specs, llm_config_errors = self._normalize_gate_specs(
            llm_eval_gates,
            default_parallel=False,
            gate_type="llm-eval",
            default_cache=False,
        )
        config_errors.update(llm_config_errors)

        for name, error in config_errors.items():
            results[name] = self._normalize_gate_result(
                name=name,
                result={**error, "blocking": True},
                gate_type="config",
            )

        remaining_specs: list[GateSpec] = []
        for spec in [*gate_specs, *llm_specs]:
            if spec.config.name in results:
                continue
            gate_files = self._filter_gate_files(
                changed_files,
                include=spec.paths,
                exclude=spec.paths_exclude,
            )
            gate_files_map[spec.config.name] = gate_files
            if not gate_files:
                results[spec.config.name] = self._normalize_gate_result(
                    name=spec.config.name,
                    result={
                        "passed": True,
                        "skipped": True,
                        "reason": "no_matching_paths",
                        "duration_ms": 0,
                        "blocking": spec.blocking,
                    },
                    gate_type=spec.gate_type,
                )
                continue

            cache_key = self._build_gate_cache_key(
                proof,
                spec,
                gate_files=gate_files,
                repo_head=repo_head,
            )
            if spec.cache and cache_key and cache_key in cache_entries:
                cached = cache_entries.get(cache_key)
                cached_result = cached.get("result") if isinstance(cached, dict) else None
                created_at = cached.get("created_at") if isinstance(cached, dict) else None
                if spec.cache_ttl_seconds is not None and not self._is_cache_entry_fresh(
                    created_at, spec.cache_ttl_seconds
                ):
                    cache_entries.pop(cache_key, None)
                    cache_updated = True
                elif isinstance(cached_result, dict) and cached_result.get("passed") is True:
                    cached_payload = dict(cached_result)
                    cached_payload.setdefault("blocking", spec.blocking)
                    results[spec.config.name] = self._normalize_gate_result(
                        name=spec.config.name,
                        result=cached_payload,
                        gate_type=spec.gate_type,
                        cached=True,
                    )
                    continue
            remaining_specs.append(spec)

        sequential_specs = [spec for spec in remaining_specs if not spec.parallel]
        parallel_specs = [spec for spec in remaining_specs if spec.parallel]
        fail_fast_triggered = False

        for spec in sequential_specs:
            if budget_deadline is not None and time.monotonic() > budget_deadline:
                results[spec.config.name] = self._normalize_gate_result(
                    name=spec.config.name,
                    result={
                        "passed": False,
                        "skipped": True,
                        "reason": "budget_exceeded",
                        "duration_ms": 0,
                        "blocking": spec.blocking,
                    },
                    gate_type=spec.gate_type,
                )
                fail_fast_triggered = True
                continue

            try:
                gate_result = await runner.run_gate_async(
                    name=spec.config.name,
                    command=spec.config.command,
                    cwd=workcell_path,
                    timeout=spec.config.timeout,
                    cpu_seconds=spec.config.cpu_seconds,
                    memory_mb=spec.config.memory_mb,
                )
            except Exception as e:
                # Convert exception to failed gate result to prevent verification crash
                logger.exception(
                    "Gate execution failed unexpectedly",
                    gate_name=spec.config.name,
                    workcell_id=workcell_id,
                    error_type=type(e).__name__,
                )
                gate_result = GateResult(
                    name=spec.config.name,
                    passed=False,
                    exit_code=-1,
                    duration_ms=0,
                    output_path=None,
                    failure_summary=f"Gate execution error: {type(e).__name__}: {e}",
                    attempt=1,
                    flaky_detected=False,
                )

            normalized = self._normalize_gate_result(
                name=spec.config.name,
                result={
                    "passed": gate_result.passed,
                    "exit_code": gate_result.exit_code,
                    "duration_ms": gate_result.duration_ms,
                    "output_path": gate_result.output_path,
                    "failure_summary": gate_result.failure_summary,
                    "attempt": gate_result.attempt,
                    "flaky_detected": gate_result.flaky_detected,
                    "blocking": spec.blocking,
                },
                gate_type=spec.gate_type,
            )
            results[spec.config.name] = normalized

            if spec.cache and normalized.get("passed") is True and not normalized.get("flaky_detected"):
                cache_key = self._build_gate_cache_key(
                    proof,
                    spec,
                    gate_files=gate_files_map.get(spec.config.name),
                    repo_head=repo_head,
                )
                if cache_key:
                    cache_entries[cache_key] = {
                        "result": normalized,
                        "created_at": _utc_now().isoformat(),
                    }
                    cache_updated = True

            if spec.fail_fast and not normalized.get("passed"):
                fail_fast_triggered = True
                break

        if fail_fast_triggered:
            for spec in parallel_specs:
                if spec.config.name in results:
                    continue
                results[spec.config.name] = self._normalize_gate_result(
                    name=spec.config.name,
                    result={
                        "passed": True,
                        "skipped": True,
                        "reason": "fail_fast_triggered",
                        "duration_ms": 0,
                        "blocking": spec.blocking,
                    },
                    gate_type=spec.gate_type,
                )
            parallel_specs = []

        if parallel_specs and budget_deadline is not None and time.monotonic() > budget_deadline:
            for spec in parallel_specs:
                results[spec.config.name] = self._normalize_gate_result(
                    name=spec.config.name,
                    result={
                        "passed": False,
                        "skipped": True,
                        "reason": "budget_exceeded",
                        "duration_ms": 0,
                        "blocking": spec.blocking,
                    },
                    gate_type=spec.gate_type,
                )
            parallel_specs = []

        if parallel_specs:
            parallel_configs = [spec.config for spec in parallel_specs]
            try:
                parallel_results = await runner.run_all_gates(
                    cwd=workcell_path,
                    gates=parallel_configs,
                    parallel=True,
                )
            except Exception as e:
                # Convert exception to empty results dict - individual gates will be marked failed
                logger.exception(
                    "Parallel gate execution failed",
                    workcell_id=workcell_id,
                    gate_count=len(parallel_configs),
                    error_type=type(e).__name__,
                )
                parallel_results = {}

            for spec in parallel_specs:
                gate_result = parallel_results.get(spec.config.name)
                if gate_result is None:
                    normalized = self._normalize_gate_result(
                        name=spec.config.name,
                        result={
                            "passed": False,
                            "reason": "missing_result",
                            "duration_ms": 0,
                            "blocking": spec.blocking,
                        },
                        gate_type=spec.gate_type,
                    )
                else:
                    normalized = self._normalize_gate_result(
                        name=spec.config.name,
                        result={
                            "passed": gate_result.passed,
                            "exit_code": gate_result.exit_code,
                            "duration_ms": gate_result.duration_ms,
                            "output_path": gate_result.output_path,
                            "failure_summary": gate_result.failure_summary,
                            "attempt": gate_result.attempt,
                            "flaky_detected": gate_result.flaky_detected,
                            "blocking": spec.blocking,
                        },
                        gate_type=spec.gate_type,
                    )
                results[spec.config.name] = normalized

                if spec.cache and normalized.get("passed") is True and not normalized.get("flaky_detected"):
                    cache_key = self._build_gate_cache_key(
                        proof,
                        spec,
                        gate_files=gate_files_map.get(spec.config.name),
                        repo_head=repo_head,
                    )
                    if cache_key:
                        cache_entries[cache_key] = {
                            "result": normalized,
                            "created_at": _utc_now().isoformat(),
                        }
                        cache_updated = True

        if cache_updated:
            gate_cache["entries"] = cache_entries
            self._write_gate_cache(gate_cache)

        # Run fab gates: run realism-style gates first, then optional engine integration (fab-godot).
        fab_items = list(fab_gates.items())
        godot_gate: tuple[str, Any] | None = None
        non_godot_fab_gates: list[tuple[str, Any]] = []
        for name, cfg in fab_items:
            if name == "fab-godot":
                godot_gate = (name, cfg)
            else:
                non_godot_fab_gates.append((name, cfg))

        for gate_name, gate_config in non_godot_fab_gates:
            fab_result = self._run_fab_gate(gate_name, gate_config, workcell_path, proof)
            blocking = True
            if isinstance(gate_config, dict) and "blocking" in gate_config:
                blocking = bool(gate_config.get("blocking"))
            results[gate_name] = self._normalize_gate_result(
                name=gate_name,
                result={**fab_result, "blocking": blocking},
                gate_type="fab",
            )

        if godot_gate is not None:
            gate_name, gate_config = godot_gate
            upstream_failed = any(
                results.get(name, {}).get("passed") is False for name, _ in non_godot_fab_gates
            )
            if upstream_failed:
                blocking = True
                if isinstance(gate_config, dict) and "blocking" in gate_config:
                    blocking = bool(gate_config.get("blocking"))
                results[gate_name] = self._normalize_gate_result(
                    name=gate_name,
                    result={
                        "passed": True,
                        "skipped": True,
                        "reason": "Skipped fab-godot because an upstream fab gate failed",
                        "duration_ms": 0,
                        "blocking": blocking,
                    },
                    gate_type="fab",
                )
            else:
                fab_result = self._run_fab_gate(gate_name, gate_config, workcell_path, proof)
                blocking = True
                if isinstance(gate_config, dict) and "blocking" in gate_config:
                    blocking = bool(gate_config.get("blocking"))
                results[gate_name] = self._normalize_gate_result(
                    name=gate_name,
                    result={**fab_result, "blocking": blocking},
                    gate_type="fab",
                )

        psn_skill_tests = self._run_psn_skill_tests_gate(workcell_path=workcell_path, proof=proof)
        if psn_skill_tests is not None:
            results["psn-skill-tests"] = self._normalize_gate_result(
                name="psn-skill-tests",
                result={**psn_skill_tests, "blocking": True},
                gate_type="psn",
            )

        verification_payload = build_verification_payload(results)
        blocking_failures = verification_payload.get("blocking_failures", [])
        if not isinstance(blocking_failures, list):
            blocking_failures = []
        all_passed = bool(verification_payload.get("all_passed", False))

        if not all_passed:
            logger.warning(
                "Gate failures",
                workcell_id=workcell_id,
                failures=blocking_failures,
            )

            # Run on-gate-failure hooks
            manifest = self._load_manifest(workcell_path)
            hook_context = HookContext(
                workcell_path=workcell_path,
                workcell_id=workcell_id,
                issue_id=proof.issue_id,
                proof=proof,
                manifest=manifest,
                verification_result={
                    "results": results,
                    "all_passed": False,
                    "gate_summary": verification_payload.get("gate_summary"),
                },
                gate_failures=blocking_failures,
            )
            hook_results = self.hook_runner.run_hooks(
                HookTrigger.ON_GATE_FAILURE,
                hook_context,
            )
            # Attach debug analysis to verification
            if hook_results:
                results["debug_analysis"] = {
                    h.hook_name: h.output for h in hook_results if h.success
                }

        # Update proof verification
        proof.verification = verification_payload

        # Persist updated proof to disk
        self._persist_proof(proof, workcell_path)
        emit_gates_event(
            logs_dir=logs_dir,
            workcell_id=workcell_id,
            passed=all_passed,
            results=verification_payload.get("gates", {}),
            summary=verification_payload.get("gate_summary"),
        )

        return all_passed

    def _format_gate_results(self, results: dict[str, Any]) -> dict[str, dict[str, Any]]:
        formatted: dict[str, dict[str, Any]] = {}
        for name, result in results.items():
            if isinstance(result, dict):
                formatted[name] = result
                continue
            formatted[name] = {
                "passed": result.passed,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "output_path": result.output_path,
                "failure_summary": result.failure_summary,
                "attempt": result.attempt,
                "flaky_detected": result.flaky_detected,
            }
        return formatted

    def _normalize_gate_specs(
        self,
        gates: dict[str, Any],
        *,
        default_parallel: bool,
        gate_type: str,
        default_cache: bool,
    ) -> tuple[list[GateSpec], dict[str, dict[str, Any]]]:
        """Normalize gate configs into executable specs and config error results."""
        specs: list[GateSpec] = []
        errors: dict[str, dict[str, Any]] = {}

        def _coerce_bool(value: Any, default: bool) -> bool:
            if value is None:
                return default
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return bool(value)
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "y", "on"}
            return default

        def _coerce_int(value: Any, default: int) -> int:
            if value is None:
                return default
            if isinstance(value, bool):
                return default
            try:
                return int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Expected int, got {value!r}") from exc

        def _coerce_optional_int(value: Any, default: int | None) -> int | None:
            if value is None:
                return default
            if value == "":
                return default
            if isinstance(value, bool):
                return default
            try:
                return int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Expected int, got {value!r}") from exc

        def _coerce_patterns(value: Any, field: str) -> list[str] | None:
            if value is None:
                return None
            if isinstance(value, str):
                return [value]
            if isinstance(value, (list, tuple, set)):
                patterns = [str(v) for v in value if isinstance(v, str) and v.strip()]
                return patterns or None
            raise ValueError(f"Expected list/str for {field}, got {type(value).__name__}")

        for name, cfg in gates.items():
            if isinstance(cfg, dict) and cfg.get("type") == "config_error":
                errors[name] = {
                    "passed": False,
                    "reason": "config_error",
                    "error": cfg.get("error") or "Invalid quality_gates configuration",
                    "details": cfg,
                    "duration_ms": 0,
                    "blocking": True,
                }
                continue

            cfg_data: dict[str, Any] = {}
            if isinstance(cfg, str):
                cfg_data = {"command": cfg}
            elif isinstance(cfg, dict):
                cfg_data = dict(cfg)
            else:
                errors[name] = {
                    "passed": False,
                    "reason": "config_error",
                    "error": f"Unsupported gate config type: {type(cfg).__name__}",
                    "duration_ms": 0,
                    "blocking": True,
                }
                continue

            command = cfg_data.get("command") or cfg_data.get("cmd")
            if not isinstance(command, str) or not command.strip():
                errors[name] = {
                    "passed": False,
                    "reason": "config_error",
                    "error": "Gate config missing command",
                    "details": cfg_data,
                    "duration_ms": 0,
                    "blocking": True,
                }
                continue

            spec_type = gate_type
            if isinstance(cfg_data.get("type"), str):
                spec_type = str(cfg_data.get("type"))
            blocking_default = default_blocking_for_gate_type(spec_type)

            try:
                timeout = _coerce_int(
                    cfg_data.get("timeout"),
                    default=int(self.config.gates.timeout_seconds),
                )
                retries = _coerce_int(
                    cfg_data.get("retries", cfg_data.get("retry")),
                    default=int(self.config.gates.retry_flaky),
                )
                parallel = _coerce_bool(cfg_data.get("parallel"), default_parallel)
                fail_fast = _coerce_bool(cfg_data.get("fail_fast"), False)
                blocking = _coerce_bool(cfg_data.get("blocking"), blocking_default)
                cpu_seconds = _coerce_optional_int(
                    cfg_data.get("cpu_seconds"),
                    default=getattr(self.config.gates, "max_cpu_seconds", None),
                )
                memory_mb = _coerce_optional_int(
                    cfg_data.get("memory_mb"),
                    default=getattr(self.config.gates, "max_memory_mb", None),
                )
                cache = _coerce_bool(cfg_data.get("cache"), default_cache)
                cache_ttl_seconds = _coerce_optional_int(
                    cfg_data.get("cache_ttl_seconds"),
                    default=None,
                )
                paths = _coerce_patterns(cfg_data.get("paths") or cfg_data.get("include"), "paths")
                paths_exclude = _coerce_patterns(
                    cfg_data.get("paths_exclude") or cfg_data.get("exclude"),
                    "paths_exclude",
                )
            except ValueError as exc:
                errors[name] = {
                    "passed": False,
                    "reason": "config_error",
                    "error": str(exc),
                    "details": cfg_data,
                    "duration_ms": 0,
                    "blocking": True,
                }
                continue

            if retries < 1:
                retries = 1
            if timeout < 1:
                timeout = 1

            configs = GateConfig(
                name=name,
                command=command,
                blocking=blocking,
                timeout=timeout,
                retries=retries,
                parallel=parallel,
                fail_fast=fail_fast,
                cpu_seconds=cpu_seconds,
                memory_mb=memory_mb,
            )
            specs.append(
                GateSpec(
                    config=configs,
                    parallel=parallel,
                    fail_fast=fail_fast,
                    blocking=blocking,
                    cache=cache,
                    cache_ttl_seconds=cache_ttl_seconds,
                    paths=paths,
                    paths_exclude=paths_exclude,
                    gate_type=spec_type,
                )
            )

        return specs, errors

    def _normalize_gate_result(
        self,
        *,
        name: str,
        result: Any,
        gate_type: str,
        cached: bool = False,
    ) -> dict[str, Any]:
        """Normalize gate result into a shared schema."""
        return normalize_gate_result_shared(
            name=name,
            result=result,
            gate_type=gate_type,
            cached=cached,
            blocking_default=default_blocking_for_gate_type(gate_type),
        )

    def _gate_matches_paths(
        self,
        changed_files: list[str],
        *,
        include: list[str] | None,
        exclude: list[str] | None,
    ) -> bool:
        """Return True if gate should run based on path filters."""
        return bool(self._filter_gate_files(changed_files, include=include, exclude=exclude))

    def _filter_gate_files(
        self,
        changed_files: list[str],
        *,
        include: list[str] | None,
        exclude: list[str] | None,
    ) -> list[str]:
        """Filter changed files based on include/exclude globs."""
        if not include and not exclude:
            return list(changed_files)

        def _matches(path: str, patterns: list[str]) -> bool:
            normalized = path.replace("\\", "/")
            posix = PurePosixPath(normalized)

            def _pattern_variants(pattern: str) -> set[str]:
                """
                Expand `**` segments so `**/` can match zero path components.

                pathlib's `PurePath.match("**/*.txt")` does NOT match "foo.txt"
                at the repo root. Most users expect glob semantics where it does.
                """
                normalized_pattern = pattern.replace("\\", "/")
                parts = normalized_pattern.split("/")
                variants: set[str] = set()

                def _walk(idx: int, acc: list[str]) -> None:
                    if len(variants) >= 32:
                        return
                    if idx >= len(parts):
                        if acc:
                            variants.add("/".join(acc))
                        return
                    part = parts[idx]
                    if part == "**":
                        _walk(idx + 1, [*acc, part])
                        _walk(idx + 1, acc)
                    else:
                        _walk(idx + 1, [*acc, part])

                _walk(0, [])
                return variants or {normalized_pattern}

            for pattern in patterns:
                for variant in _pattern_variants(pattern):
                    if posix.match(variant):
                        return True
            return False

        candidates = list(changed_files)
        if include:
            candidates = [path for path in candidates if _matches(path, include)]
        if exclude:
            candidates = [path for path in candidates if not _matches(path, exclude)]

        return candidates

    def _get_changed_files(self, proof: PatchProof) -> list[str]:
        patch = proof.patch if isinstance(proof.patch, dict) else {}
        files = patch.get("files_modified")
        if not isinstance(files, list):
            return []
        return [str(f) for f in files if isinstance(f, str) and f.strip()]

    def _extract_gate_paths(self, gate_config: Any) -> tuple[list[str] | None, list[str] | None]:
        if not isinstance(gate_config, dict):
            return None, None

        def _coerce_patterns(value: Any) -> list[str] | None:
            if value is None:
                return None
            if isinstance(value, str):
                return [value]
            if isinstance(value, (list, tuple, set)):
                patterns = [str(v) for v in value if isinstance(v, str) and v.strip()]
                return patterns or None
            return None

        include = _coerce_patterns(gate_config.get("paths") or gate_config.get("include"))
        exclude = _coerce_patterns(gate_config.get("paths_exclude") or gate_config.get("exclude"))
        return include, exclude

    def _run_diff_gates(
        self,
        diff_gates: dict[str, Any],
        *,
        proof: PatchProof,
        workcell_path: Path,
        changed_files: list[str],
    ) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        for name, cfg in diff_gates.items():
            gate_type = "diff-check"
            if isinstance(cfg, dict) and isinstance(cfg.get("type"), str):
                gate_type = str(cfg.get("type"))
            blocking_override = cfg.get("blocking") if isinstance(cfg, dict) else None

            if name == "max-diff-size":
                raw = self._run_max_diff_gate(cfg, proof)
            elif name == "secret-detection":
                raw = self._run_secret_detection_gate(cfg, workcell_path, changed_files)
            else:
                raw = {
                    "passed": False,
                    "reason": "unsupported_diff_gate",
                    "error": f"Unknown diff gate: {name}",
                    "duration_ms": 0,
                }

            if isinstance(raw, dict) and blocking_override is not None:
                raw["blocking"] = bool(blocking_override)

            results[name] = self._normalize_gate_result(
                name=name,
                result=raw,
                gate_type=gate_type,
            )

        return results

    def _run_max_diff_gate(self, gate_config: Any, proof: PatchProof) -> dict[str, Any]:
        started = time.perf_counter()
        cfg = gate_config if isinstance(gate_config, dict) else {}
        patch = proof.patch if isinstance(proof.patch, dict) else {}
        diff_stats = patch.get("diff_stats") if isinstance(patch.get("diff_stats"), dict) else {}
        files_modified = patch.get("files_modified")

        def _coerce_int(value: Any) -> int | None:
            if value is None:
                return None
            if isinstance(value, bool):
                return None
            try:
                return int(value)
            except (TypeError, ValueError):
                return None

        max_lines = _coerce_int(cfg.get("max_lines") or cfg.get("max_diff_lines"))
        if max_lines is None:
            max_lines = _coerce_int(self.config.gates.max_diff_lines)
        max_files = _coerce_int(cfg.get("max_files") or cfg.get("max_diff_files"))
        if max_files is None:
            max_files = _coerce_int(self.config.gates.max_diff_files)

        if max_lines is None and max_files is None:
            duration_ms = int((time.perf_counter() - started) * 1000)
            return {
                "passed": True,
                "skipped": True,
                "reason": "no_thresholds_configured",
                "duration_ms": duration_ms,
            }

        files_changed = diff_stats.get("files_changed")
        if files_changed is None and isinstance(files_modified, list):
            files_changed = len(files_modified)

        insertions = diff_stats.get("insertions")
        deletions = diff_stats.get("deletions")
        has_line_stats = insertions is not None or deletions is not None
        total_lines = None
        if has_line_stats:
            total_lines = int(insertions or 0) + int(deletions or 0)

        if files_changed is None and total_lines is None:
            duration_ms = int((time.perf_counter() - started) * 1000)
            return {
                "passed": True,
                "skipped": True,
                "reason": "missing_diff_stats",
                "duration_ms": duration_ms,
            }

        failures: list[str] = []
        if max_files is not None and files_changed is not None and int(files_changed) > max_files:
            failures.append("max_files_exceeded")
        if max_lines is not None and total_lines is not None and int(total_lines) > max_lines:
            failures.append("max_lines_exceeded")

        duration_ms = int((time.perf_counter() - started) * 1000)
        return {
            "passed": len(failures) == 0,
            "reason": failures[0] if failures else None,
            "duration_ms": duration_ms,
            "diff_stats": diff_stats,
            "max_lines": max_lines,
            "max_files": max_files,
            "files_changed": files_changed,
            "total_lines": total_lines,
        }

    def _read_diff_text(self, workcell_path: Path, changed_files: list[str]) -> str | None:
        cmd = ["git", "diff", "--unified=0", "--no-color"]
        if changed_files:
            cmd.append("--")
            cmd.extend(changed_files)
        try:
            result = subprocess.run(
                cmd,
                cwd=workcell_path,
                capture_output=True,
                text=True,
                timeout=2,
            )
        except Exception:
            return None
        if result.returncode != 0:
            return None
        return result.stdout

    def _scan_diff_text(
        self,
        diff_text: str,
        patterns: list[re.Pattern[str]],
        *,
        max_lines: int | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        matches: list[dict[str, Any]] = []
        scanned = 0
        current_file: str | None = None
        for line in diff_text.splitlines():
            if line.startswith("+++ "):
                current_file = line[6:] if line.startswith("+++ b/") else None
                continue
            if line.startswith("--- ") or line.startswith("@@"):
                continue
            if not line.startswith("+") or line.startswith("+++"):
                continue
            scanned += 1
            if max_lines is not None and scanned > max_lines:
                break
            content = line[1:]
            for pattern in patterns:
                if pattern.search(content):
                    matches.append(
                        {
                            "path": current_file or "<diff>",
                            "pattern": pattern.pattern,
                            "source": "diff",
                        }
                    )
                    break
        return matches, scanned

    def _run_secret_detection_gate(
        self,
        gate_config: Any,
        workcell_path: Path,
        changed_files: list[str],
    ) -> dict[str, Any]:
        started = time.perf_counter()
        cfg = gate_config if isinstance(gate_config, dict) else {}
        include, exclude = self._extract_gate_paths(cfg)
        scan_files = self._filter_gate_files(changed_files, include=include, exclude=exclude)

        if not scan_files:
            duration_ms = int((time.perf_counter() - started) * 1000)
            return {
                "passed": True,
                "skipped": True,
                "reason": "no_matching_paths",
                "duration_ms": duration_ms,
            }

        scan_diff = cfg.get("scan_diff")
        if scan_diff is None:
            scan_diff = bool(self.config.gates.secret_detection_scan_diff)
        else:
            scan_diff = bool(scan_diff)

        patterns = cfg.get("patterns")
        if isinstance(patterns, str):
            patterns = [patterns]
        if not isinstance(patterns, list):
            patterns = [
                r"AKIA[0-9A-Z]{16}",
                r"ASIA[0-9A-Z]{16}",
                r"ghp_[0-9A-Za-z]{36}",
                r"xox[baprs]-[0-9A-Za-z-]{10,48}",
                r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
            ]
        compiled = [re.compile(p) for p in patterns if isinstance(p, str) and p.strip()]

        max_bytes = cfg.get("max_bytes") or cfg.get("max_kb")
        if max_bytes is None:
            max_bytes = self.config.gates.secret_detection_max_bytes
        try:
            max_bytes = int(max_bytes)
        except (TypeError, ValueError):
            max_bytes = 200_000
        if max_bytes < 1_000:
            max_bytes = max_bytes * 1024

        diff_lines_limit = cfg.get("max_diff_lines") or cfg.get("max_lines")
        try:
            diff_lines_limit = int(diff_lines_limit) if diff_lines_limit is not None else None
        except (TypeError, ValueError):
            diff_lines_limit = None
        if diff_lines_limit is None:
            diff_lines_limit = 5000

        matches: list[dict[str, Any]] = []
        skipped_files = 0
        scanned_files = 0
        diff_lines_scanned = 0
        root = workcell_path.resolve()

        if scan_diff:
            diff_text = self._read_diff_text(workcell_path, scan_files)
            if diff_text:
                diff_matches, diff_lines_scanned = self._scan_diff_text(
                    diff_text,
                    compiled,
                    max_lines=diff_lines_limit,
                )
                if diff_matches:
                    duration_ms = int((time.perf_counter() - started) * 1000)
                    return {
                        "passed": False,
                        "reason": "secrets_detected",
                        "duration_ms": duration_ms,
                        "matches": diff_matches[:20],
                        "match_count": len(diff_matches),
                        "diff_lines_scanned": diff_lines_scanned,
                        "files_scanned": scanned_files,
                        "files_skipped": skipped_files,
                    }

        for rel_path in scan_files:
            candidate = Path(rel_path)
            resolved = candidate if candidate.is_absolute() else workcell_path / candidate
            try:
                resolved = resolved.resolve()
            except Exception:
                skipped_files += 1
                continue
            if root not in resolved.parents and resolved != root:
                skipped_files += 1
                continue
            if not resolved.exists() or not resolved.is_file():
                skipped_files += 1
                continue
            try:
                if resolved.stat().st_size > max_bytes:
                    skipped_files += 1
                    continue
                content = resolved.read_text(errors="ignore")
            except Exception:
                skipped_files += 1
                continue
            if "\x00" in content:
                skipped_files += 1
                continue
            scanned_files += 1
            for pattern in compiled:
                if pattern.search(content):
                    matches.append({"path": str(rel_path), "pattern": pattern.pattern})

        duration_ms = int((time.perf_counter() - started) * 1000)
        if matches:
            return {
                "passed": False,
                "reason": "secrets_detected",
                "duration_ms": duration_ms,
                "matches": matches[:20],
                "match_count": len(matches),
                "diff_lines_scanned": diff_lines_scanned,
                "files_scanned": scanned_files,
                "files_skipped": skipped_files,
            }

        return {
            "passed": True,
            "reason": "no_secrets_found",
            "duration_ms": duration_ms,
            "diff_lines_scanned": diff_lines_scanned,
            "files_scanned": scanned_files,
            "files_skipped": skipped_files,
        }

    def _build_gate_cache_key(
        self,
        proof: PatchProof,
        spec: GateSpec,
        *,
        gate_files: list[str] | None = None,
        repo_head: str | None = None,
    ) -> str | None:
        patch = proof.patch if isinstance(proof.patch, dict) else {}
        payload = {
            "gate": spec.config.name,
            "gate_type": spec.gate_type,
            "command": spec.config.command,
            "timeout": spec.config.timeout,
            "retries": spec.config.retries,
            "paths": sorted(spec.paths or []),
            "paths_exclude": sorted(spec.paths_exclude or []),
            "gate_files": sorted(gate_files or []),
            "repo_head": repo_head,
            "base_commit": patch.get("base_commit"),
            "head_commit": patch.get("head_commit"),
            "files_modified": sorted(patch.get("files_modified") or []),
            "diff_stats": patch.get("diff_stats") or {},
        }
        try:
            encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        except Exception:
            return None
        return sha256(encoded).hexdigest()

    def _get_repo_head(self, workcell_path: Path) -> str | None:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=workcell_path,
                capture_output=True,
                text=True,
                timeout=2,
            )
        except Exception:
            return None
        if result.returncode != 0:
            return None
        head = result.stdout.strip()
        return head or None

    def _gate_cache_path(self) -> Path:
        return self.config.repo_root / ".hellcat" / "cache" / "gate_cache.json"

    def _load_gate_cache(self) -> dict[str, Any]:
        cache_path = self._gate_cache_path()
        lock = FileLock(cache_path.with_suffix(".lock"), timeout=2.0)
        if not lock.acquire(exclusive=False):
            return {"entries": {}}
        try:
            if not cache_path.exists():
                return {"entries": {}}
            data = json.loads(cache_path.read_text())
            if not isinstance(data, dict):
                return {"entries": {}}
            entries = data.get("entries")
            if not isinstance(entries, dict):
                data["entries"] = {}
            return data
        except Exception as exc:
            logger.warning("Failed to load gate cache", error=str(exc))
            return {"entries": {}}
        finally:
            lock.release()

    def _write_gate_cache(self, cache: dict[str, Any]) -> None:
        cache_path = self._gate_cache_path()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        lock = FileLock(cache_path.with_suffix(".lock"), timeout=2.0)
        if not lock.acquire(exclusive=True):
            logger.warning("Failed to acquire gate cache lock")
            return
        try:
            cache_path.write_text(json.dumps(cache, indent=2, default=str))
        except Exception as exc:
            logger.warning("Failed to write gate cache", error=str(exc))
        finally:
            lock.release()

    def _is_cache_entry_fresh(self, created_at: str | None, ttl_seconds: int | None) -> bool:
        if ttl_seconds is None:
            return True
        if not created_at:
            return False
        try:
            normalized = created_at.replace("Z", "+00:00")
            ts = datetime.fromisoformat(normalized)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
        except Exception:
            return False
        return (_utc_now() - ts).total_seconds() <= ttl_seconds

    def _normalize_gate_configs(self, gates: dict[str, Any]) -> list[GateConfig]:
        configs: list[GateConfig] = []
        for name, cfg in gates.items():
            if isinstance(cfg, str):
                configs.append(GateConfig(name=name, command=cfg))
                continue
            if isinstance(cfg, dict):
                command = cfg.get("command") or cfg.get("cmd")
                if not isinstance(command, str) or not command.strip():
                    logger.warning("Gate config missing command", gate=name)
                    continue
                timeout = int(cfg.get("timeout", 300))
                retries = int(cfg.get("retries", 1))
                configs.append(
                    GateConfig(
                        name=name,
                        command=command,
                        timeout=timeout,
                        retries=retries,
                    )
                )
                continue
            logger.warning("Unsupported gate config type", gate=name, type=str(type(cfg)))
        return configs

    def _check_skill_maturity_lockdown(self, workcell_path: Path, proof: PatchProof) -> list[str]:
        """
        Block edits to mature skills unless explicitly overridden.

        Override tag: `psn:allow-mature-skill-edit`
        """
        manifest = self._load_manifest(workcell_path)
        issue = manifest.get("issue") if isinstance(manifest.get("issue"), dict) else {}
        tags = issue.get("tags") if isinstance(issue.get("tags"), list) else []
        tag_set = {str(t) for t in tags}
        if "psn:allow-mature-skill-edit" in tag_set:
            return []

        patch = proof.patch if isinstance(proof.patch, dict) else {}
        files_modified = patch.get("files_modified")
        if not isinstance(files_modified, list):
            return []

        skill_ids: set[str] = set()
        for path in files_modified:
            if not isinstance(path, str) or not path.strip():
                continue
            skill_id = self._infer_skill_id_from_repo_path(path)
            if skill_id:
                skill_ids.add(skill_id)

        if not skill_ids:
            return []

        db_path = self.config.repo_root / ".hellcat" / "memory" / "hellcat-mem.db"
        try:
            from hellcat.cognition.memory.database import MemoryDB
            from hellcat.domain.skills.maturity import SkillMaturity

            db = MemoryDB(db_path)
        except Exception:
            return []

        blocked: list[str] = []
        try:
            for skill_id in sorted(skill_ids):
                rows = db.get_skill_maturity(skill_id=skill_id, limit=1)
                if not rows:
                    continue
                entry = SkillMaturity(
                    successes=int(rows[0].get("successes") or 0),
                    failures=int(rows[0].get("failures") or 0),
                )
                try:
                    if entry.is_mature():
                        blocked.append(skill_id)
                except Exception:
                    continue
        finally:
            with contextlib.suppress(Exception):
                db.close()

        return blocked

    def _infer_skill_id_from_repo_path(self, path: str) -> str | None:
        p = PurePosixPath(path.replace("\\", "/"))
        parts = p.parts
        if len(parts) >= 3 and parts[0] == "skills":
            category = parts[1]
            filename = parts[2]
            if filename.endswith((".yaml", ".yml", ".py")):
                name = Path(filename).stem
                if filename.endswith(".py"):
                    name = name.replace("_", "-")
                return f"{category}:{name}"

        # Allow package-local mirrors.
        if len(parts) >= 6 and parts[:4] == ("kernel", "src", "hellcat", "skills"):
            category = parts[4]
            filename = parts[5]
            if filename.endswith((".yaml", ".yml", ".py")):
                name = Path(filename).stem
                if filename.endswith(".py"):
                    name = name.replace("_", "-")
                return f"{category}:{name}"

        return None

    def _run_psn_skill_tests_gate(
        self,
        *,
        workcell_path: Path,
        proof: PatchProof,
    ) -> dict[str, Any] | None:
        """
        PSN gate: run strict example tests for modified skills.

        This is enabled only for PSN-tagged issues, and only when at least one
        skill under `skills/<category>/` is modified.
        """
        manifest = self._load_manifest(workcell_path)
        issue = manifest.get("issue") if isinstance(manifest.get("issue"), dict) else {}
        tags = issue.get("tags") if isinstance(issue.get("tags"), list) else []
        tag_set = {str(t) for t in tags}
        if not any(t.startswith("psn:") for t in tag_set):
            return None

        patch = proof.patch if isinstance(proof.patch, dict) else {}
        files_modified = patch.get("files_modified")
        if not isinstance(files_modified, list):
            return None

        skill_ids: set[str] = set()
        for rel_path in files_modified:
            if not isinstance(rel_path, str) or not rel_path.strip():
                continue
            if not rel_path.replace("\\", "/").startswith("skills/"):
                continue
            inferred = self._infer_skill_id_from_repo_path(rel_path)
            if inferred:
                skill_ids.add(inferred)

        if not skill_ids:
            return None

        skills_root = workcell_path / "skills"
        if not skills_root.exists():
            return {
                "passed": False,
                "duration_ms": 0,
                "reason": f"Missing skills directory in workcell: {skills_root}",
                "skills": sorted(skill_ids),
            }

        started = time.perf_counter()
        try:
            from hellcat.domain.skills.registry import SkillRegistry
            from hellcat.domain.skills.runner import SkillRunner
            from hellcat.domain.skills.testing import run_skill_tests
            from hellcat.domain.skills.trace import TraceRecorder

            registry = SkillRegistry(skills_root=skills_root)
            runner = SkillRunner(registry=registry)
            recorder = TraceRecorder(workcell_path / "logs" / "psn")

            ordered = sorted(skill_ids)
            results, total_failures = run_skill_tests(
                ordered,
                registry=registry,
                runner=runner,
                recorder=recorder,
                strict=True,
                workcell_id=workcell_path.name,
                issue_id=proof.issue_id,
            )

            duration_ms = int((time.perf_counter() - started) * 1000)
            return {
                "passed": total_failures == 0,
                "duration_ms": duration_ms,
                "skills": [r.__dict__ for r in results],
                "total_failures": total_failures,
                "strict": True,
            }
        except Exception as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            logger.exception(
                "PSN skill tests gate failed unexpectedly",
                workcell_id=workcell_path.name,
                skill_count=len(skill_ids),
            )
            return {
                "passed": False,
                "duration_ms": duration_ms,
                "error": str(exc),
                "skills": sorted(skill_ids),
            }

    def _load_gates_from_manifest(self, workcell_path: Path) -> dict[str, Any]:
        """Load quality gates from workcell manifest.json."""
        manifest_path = workcell_path / "manifest.json"

        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text())
                if "quality_gates" in manifest:
                    gates = manifest.get("quality_gates")
                    if isinstance(gates, dict):
                        logger.debug("Loaded gates from manifest", gates=list(gates.keys()))
                        return gates
                    logger.warning(
                        "Invalid quality_gates format in manifest",
                        value_type=str(type(gates)),
                    )
                    return {
                        "config_error": {
                            "type": "config_error",
                            "error": "quality_gates must be a mapping",
                            "value_type": str(type(gates)),
                        }
                    }
            except Exception as e:
                logger.warning("Failed to load manifest", error=str(e))
                return {
                    "config_error": {
                        "type": "config_error",
                        "error": "failed_to_load_manifest",
                        "details": str(e),
                    }
                }

        # Fallback to config defaults
        gates = {
            "test": self.config.gates.test_command,
            "typecheck": self.config.gates.typecheck_command,
            "lint": self.config.gates.lint_command,
        }
        build_command = getattr(self.config.gates, "build_command", None)
        if isinstance(build_command, str) and build_command.strip():
            gates["build"] = build_command
        return gates

    def _load_manifest(self, workcell_path: Path) -> dict[str, Any]:
        """Load full manifest from workcell."""
        manifest_path = workcell_path / "manifest.json"

        if manifest_path.exists():
            try:
                return json.loads(manifest_path.read_text())
            except Exception as e:
                logger.warning("Failed to load manifest", error=str(e))

        return {}

    def _run_fab_gate(
        self,
        gate_name: str,
        gate_config: dict[str, Any],
        workcell_path: Path,
        proof: PatchProof,
    ) -> dict[str, Any]:
        """Run a fab-* gate (e.g. fab-gate realism, fab-godot, fab-playability)."""
        import subprocess
        import time

        logger.info("Running fab gate", gate=gate_name, config=gate_config)

        start_time = time.time()
        gate_output_dir = workcell_path / "logs" / "fab" / gate_name

        # Handle playability gate specially (in-process)
        if gate_name == "fab-playability":
            return self._run_playability_gate(gate_config, workcell_path, proof, gate_output_dir)

        try:
            # Find asset file in workcell
            asset_path = self._find_asset_file(workcell_path, proof)
            if not asset_path:
                return {
                    "passed": False,
                    "exit_code": 1,
                    "error": "No asset file found",
                    "duration_ms": int((time.time() - start_time) * 1000),
                    "output_path": str(gate_output_dir),
                }

            gate_config_id = gate_config.get("gate_config_id", "car_realism_v001")

            if gate_name == "fab-godot":
                template_dir = gate_config.get("template_dir") or gate_config.get("template")
                cmd = [
                    "python",
                    "-m",
                    "hellcat.fab.godot",
                    "--asset",
                    str(asset_path),
                    "--config",
                    gate_config_id,
                    "--out",
                    str(gate_output_dir),
                    "--json",
                ]
                if template_dir:
                    cmd.extend(["--template-dir", str(template_dir)])
            else:
                # Run the Fab realism gate CLI
                cmd = [
                    "python",
                    "-m",
                    "hellcat.fab.gate",
                    "--asset",
                    str(asset_path),
                    "--config",
                    gate_config_id,
                    "--out",
                    str(gate_output_dir),
                    "--json",
                ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=workcell_path,
                timeout=1800,  # 30 minute timeout (rendering + critics)
            )

            duration_ms = int((time.time() - start_time) * 1000)

            # Parse result: prefer structured verdict over exit code.
            passed = result.returncode == 0
            gate_result: dict[str, Any] = {
                "passed": passed,
                "exit_code": result.returncode,
                "duration_ms": duration_ms,
                "output_path": str(gate_output_dir),
            }

            # Try to parse JSON output
            if result.stdout:
                try:
                    output = json.loads(result.stdout)
                    verdict = output.get("verdict", "unknown")
                    gate_result["verdict"] = verdict
                    gate_result["scores"] = output.get("scores", {})
                    gate_result["failures"] = output.get("failures", {})
                    gate_result["next_actions"] = output.get("next_actions", [])
                    gate_result["artifacts"] = output.get("artifacts", {})

                    if verdict in ("pass", "fail", "escalate"):
                        passed = verdict == "pass"
                        gate_result["passed"] = passed
                except json.JSONDecodeError as e:
                    logger.warning(
                        "Fab gate output is not valid JSON",
                        gate=gate_name,
                        workcell_id=workcell_path.name,
                        error=str(e),
                        stdout_preview=result.stdout[:200] if result.stdout else None,
                    )

            if result.stderr:
                gate_result["stderr"] = result.stderr[:1000]

            logger.info(
                "Fab gate completed",
                gate=gate_name,
                passed=passed,
                duration_ms=duration_ms,
            )

            return gate_result

        except subprocess.TimeoutExpired:
            return {
                "passed": False,
                "exit_code": -1,
                "error": "Gate timeout",
                "duration_ms": int((time.time() - start_time) * 1000),
                "output_path": str(gate_output_dir),
            }
        except Exception as e:
            logger.error("Fab gate failed", gate=gate_name, error=str(e))
            return {
                "passed": False,
                "exit_code": -1,
                "error": str(e),
                "duration_ms": int((time.time() - start_time) * 1000),
                "output_path": str(gate_output_dir),
            }

    def _run_playability_gate(
        self,
        gate_config: dict[str, Any],
        workcell_path: Path,
        proof: PatchProof,
        output_dir: Path,
    ) -> dict[str, Any]:
        """Run the fab-playability gate (NitroGen automated playtesting)."""
        import time

        import yaml

        start_time = time.time()
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            from hellcat.fab.playability_gate import run_playability_gate

            # Load gate config YAML if specified
            gate_config_id = gate_config.get("gate_config_id", "gameplay_playability_v001")
            gate_config_path = self.config.repo_root / "fab" / "gates" / f"{gate_config_id}.yaml"

            if gate_config_path.exists():
                with open(gate_config_path) as f:
                    full_config = yaml.safe_load(f)
            else:
                logger.warning("Playability config not found", path=str(gate_config_path))
                full_config = gate_config

            # Find Godot project in workcell
            godot_project = self._find_godot_project(workcell_path)
            if not godot_project:
                return {
                    "passed": False,
                    "exit_code": 1,
                    "error": "No Godot project found for playability testing",
                    "duration_ms": int((time.time() - start_time) * 1000),
                    "output_path": str(output_dir),
                }

            # Extract world_id from manifest if available
            manifest = self._load_manifest(workcell_path)
            world_config = manifest.get("world_config", {})
            world_id = world_config.get("world_path", "").split("/")[-1] or "unknown"

            # Run the playability gate
            result = run_playability_gate(
                project_path=godot_project,
                config=full_config,
                output_dir=output_dir,
                world_id=world_id,
                run_id=proof.workcell_id,
                collect_metrics=True,
            )

            duration_ms = int((time.time() - start_time) * 1000)

            gate_result = {
                "passed": result.success,
                "exit_code": 0 if result.success else 1,
                "duration_ms": duration_ms,
                "metrics": result.to_dict()["metrics"],
                "failures": result.failures,
                "warnings": result.warnings,
                "output_path": str(output_dir),
            }

            # Write result to output dir
            result_path = output_dir / "playability_result.json"
            result_path.write_text(json.dumps(result.to_dict(), indent=2))

            logger.info(
                "Playability gate completed",
                passed=result.success,
                stuck_ratio=f"{result.metrics.stuck_ratio:.1%}",
                coverage=f"{result.metrics.coverage_estimate:.2f}",
                duration_ms=duration_ms,
            )

            return gate_result

        except ImportError as e:
            logger.error("Playability gate not available", error=str(e))
            return {
                "passed": False,
                "exit_code": 1,
                "error": f"Playability gate not available: {e}",
                "duration_ms": int((time.time() - start_time) * 1000),
                "output_path": str(output_dir),
            }
        except Exception as e:
            logger.error("Playability gate failed", error=str(e))
            return {
                "passed": False,
                "exit_code": 1,
                "error": str(e),
                "duration_ms": int((time.time() - start_time) * 1000),
                "output_path": str(output_dir),
            }

    def _find_godot_project(self, workcell_path: Path) -> Path | None:
        """Find a Godot project in the workcell."""
        # Common locations for Godot projects
        candidates = [
            workcell_path / "project",
            workcell_path / "godot",
            workcell_path / "game",
            workcell_path / "fab" / "godot" / "template",
            workcell_path
            / "fab"
            / "vault"
            / "godot"
            / "templates"
            / "fab_game_template"
            / "project",
        ]

        for candidate in candidates:
            if (candidate / "project.godot").exists():
                return candidate

        # Search for project.godot
        for project_file in workcell_path.rglob("project.godot"):
            return project_file.parent

        return None

    def _find_asset_file(self, workcell_path: Path, proof: PatchProof) -> Path | None:
        """Find the asset file in a workcell."""
        # Check proof for asset path
        if proof.patch:
            asset_path = proof.patch.get("asset_path")
            if asset_path:
                path = Path(asset_path)
                if path.is_absolute() and path.exists():
                    return path
                relative = workcell_path / asset_path
                if relative.exists():
                    return relative

        # Search for common asset patterns
        patterns = ["*.glb", "*.gltf", "*.blend", "asset.glb", "output.glb"]
        for pattern in patterns:
            matches = list(workcell_path.glob(pattern))
            if matches:
                return matches[0]
            # Also check common output directories
            for subdir in ["output", "assets", "export"]:
                matches = list((workcell_path / subdir).glob(pattern))
                if matches:
                    return matches[0]

        return None

    def _persist_proof(self, proof: PatchProof, workcell_path: Path) -> None:
        """Persist updated proof.json to workcell."""
        proof_path = workcell_path / "proof.json"
        try:
            proof_path.write_text(json.dumps(proof.to_dict(), indent=2, default=str))
            logger.debug("Persisted proof", path=str(proof_path))
            self._persist_rollout(workcell_path)
        except Exception as e:
            logger.warning("Failed to persist proof", error=str(e))

    def _persist_rollout(self, workcell_path: Path) -> None:
        """Build and persist rollout.json for this workcell."""
        if write_rollout is None:
            return
        try:
            write_rollout(workcell_path)
        except Exception as e:
            logger.warning("Failed to persist rollout", error=str(e))

    def vote(self, candidates: list[PatchProof]) -> PatchProof | None:
        """
        Select winner from speculate candidates via voting algorithm.

        Scoring components:
        1. Verification (all gates pass) - 40%
        2. Confidence score - 20%
        3. Diff size (smaller is better) - 15%
        4. Risk classification - 15%
        5. Execution time (faster is better) - 10%
        """
        scores: dict[str, float] = {}
        valid_candidates: list[PatchProof] = []

        for candidate in candidates:
            # Auto-reject if gates failed
            verification = candidate.verification
            all_passed = False
            if isinstance(verification, dict):
                all_passed = verification.get("all_passed", False)

            if not all_passed:
                scores[candidate.workcell_id] = 0
                continue

            score = self._score_candidate(candidate, candidates)
            scores[candidate.workcell_id] = score
            valid_candidates.append(candidate)

        if not valid_candidates:
            logger.warning("No valid candidates in vote")
            return None

        # Find winner
        best = max(valid_candidates, key=lambda c: scores[c.workcell_id])
        best_score = scores[best.workcell_id]

        logger.info(
            "Vote winner selected",
            winner=best.workcell_id,
            score=best_score,
            candidates=len(candidates),
        )

        # Check threshold
        threshold = self.config.speculation.vote_threshold * 100

        if best_score >= threshold:
            return best

        logger.warning(
            "Winner below threshold",
            score=best_score,
            threshold=threshold,
        )
        return None

    def _score_candidate(self, candidate: PatchProof, all_candidates: list[PatchProof]) -> float:
        """Score a single candidate."""
        score = 0.0

        # Verification: 40 points (already checked, so always add)
        score += 40

        # Confidence: 0-20 points
        score += candidate.confidence * 20

        # Diff size: 0-15 points (smaller is better)
        patch = candidate.patch or {}
        diff_stats = patch.get("diff_stats", {})
        this_lines = diff_stats.get("insertions", 0) + diff_stats.get("deletions", 0)

        max_lines = (
            max(
                (c.patch or {}).get("diff_stats", {}).get("insertions", 0)
                + (c.patch or {}).get("diff_stats", {}).get("deletions", 0)
                for c in all_candidates
            )
            or 1
        )

        score += (1 - this_lines / max_lines) * 15

        # Risk: 0-15 points
        risk_scores = {"low": 15, "medium": 10, "high": 5, "critical": 0}
        score += risk_scores.get(candidate.risk_classification, 5)

        # Speed: 0-10 points (faster is better)
        metadata = candidate.metadata or {}
        this_duration = metadata.get("duration_ms", 0) or 0

        max_duration = (
            max((c.metadata or {}).get("duration_ms", 0) or 0 for c in all_candidates) or 1
        )

        if max_duration > 0:
            score += (1 - this_duration / max_duration) * 10
        else:
            score += 10

        return score

    def _check_forbidden_paths(self, proof: PatchProof) -> list[str]:
        """Check if proof has forbidden path violations."""
        patch = proof.patch or {}
        return patch.get("forbidden_path_violations", [])
