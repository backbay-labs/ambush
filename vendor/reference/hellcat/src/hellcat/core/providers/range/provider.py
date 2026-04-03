"""
Attack Range Provider - Controlled cyber range execution.

This provider orchestrates Attack Range environments for:
- CTF tournaments (Range Raids)
- Security drill evaluations
- Detection engineering validation

Execution flow:
1. Load range template + drill spec
2. Spawn isolated range environment (microVM or container)
3. Emit ground truth events per scenario
4. Capture detections from Aegis shields
5. Score via drill-score gate
6. Produce Scorecard + ProofBundle artifacts
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from hellcat.core.gates.results import (
    build_verification_payload,
    emit_gates_event,
    normalize_gate_result,
    resolve_logs_dir,
)
from hellcat.core.providers.base import ExecutionContext, ExecutionResult, SandboxProvider
from hellcat.core.providers.capabilities import ExecutionCapabilities
from hellcat.core.providers.sandbox.runtime import (
    SandboxMount,
    SandboxRuntimeConfig,
    SandboxRuntimeFactory,
)

logger = logging.getLogger(__name__)


@dataclass
class RangeTemplate:
    """Range environment template definition."""

    schema_version: str = "1.0"
    template_id: str = ""
    name: str = ""
    version: str = "1.0.0"
    description: str = ""

    # Environment configuration
    environment: dict[str, Any] = field(default_factory=dict)

    # Scenario configuration
    scenario: dict[str, Any] = field(default_factory=dict)

    # Ground truth configuration
    ground_truth: dict[str, Any] = field(default_factory=dict)

    # Runtime configuration (container/microvm/process)
    runtime: dict[str, Any] = field(default_factory=dict)

    # Attack events to emit
    attack_events: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RangeTemplate:
        """Load from dictionary."""
        events = data.get("scenario", {}).get("attack_events", [])
        return cls(
            schema_version=data.get("schema_version", "1.0"),
            template_id=data.get("template_id", ""),
            name=data.get("name", ""),
            version=data.get("version", "1.0.0"),
            description=data.get("description", ""),
            environment=data.get("environment", {}),
            scenario=data.get("scenario", {}),
            ground_truth=data.get("ground_truth", {}),
            runtime=data.get("environment", {}).get("runtime", {}),
            attack_events=events,
        )

    @classmethod
    def from_file(cls, path: Path) -> RangeTemplate:
        """Load from JSON file."""
        return cls.from_dict(json.loads(path.read_text()))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        environment = dict(self.environment or {})
        if self.runtime:
            environment["runtime"] = dict(self.runtime)
        return {
            "schema_version": self.schema_version,
            "template_id": self.template_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "environment": environment,
            "scenario": self.scenario,
            "ground_truth": self.ground_truth,
        }


@dataclass
class DrillSpec:
    """Drill specification for scoring and evaluation."""

    schema_version: str = "1.0"
    drill_id: str = ""
    name: str = ""
    version: str = "1.0.0"

    # Range template reference
    range_template_ref: dict[str, str] = field(default_factory=dict)

    # Objective
    objective: dict[str, Any] = field(default_factory=dict)

    # Scoring configuration
    scoring: dict[str, Any] = field(default_factory=dict)

    # Outputs
    outputs: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DrillSpec:
        """Load from dictionary."""
        return cls(
            schema_version=data.get("schema_version", "1.0"),
            drill_id=data.get("drill_id", ""),
            name=data.get("name", ""),
            version=data.get("version", "1.0.0"),
            range_template_ref=data.get("range_template_ref", {}),
            objective=data.get("objective", {}),
            scoring=data.get("scoring", {}),
            outputs=data.get("outputs", []),
        )

    @classmethod
    def from_file(cls, path: Path) -> DrillSpec:
        """Load from JSON file."""
        return cls.from_dict(json.loads(path.read_text()))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "schema_version": self.schema_version,
            "drill_id": self.drill_id,
            "name": self.name,
            "version": self.version,
            "range_template_ref": self.range_template_ref,
            "objective": self.objective,
            "scoring": self.scoring,
            "outputs": self.outputs,
        }


@dataclass
class RangeInstance:
    """State of a running range instance."""

    instance_id: str
    template: RangeTemplate
    drill_spec: DrillSpec | None
    run_id: str

    # Execution state
    status: str = "created"  # created, starting, running, completed, failed
    started_at: datetime | None = None
    completed_at: datetime | None = None

    # Event tracking
    emitted_events: list[dict[str, Any]] = field(default_factory=list)
    detections: list[dict[str, Any]] = field(default_factory=list)

    # Artifacts
    artifacts_dir: Path | None = None
    runtime_handle: Any | None = None
    runtime_backend: str | None = None


class AttackRangeProvider(SandboxProvider):
    """
    Attack Range execution provider.

    Orchestrates controlled cyber range environments for:
    - Range Raids (attack simulations)
    - Security drills with ground truth scoring
    - Tournament matches with verifiable results
    """

    name = "attack_range"
    capabilities = ExecutionCapabilities(
        gpu=False,
        isolation_level="microvm",
        max_runtime=timedelta(hours=2),
        max_concurrent=8,
        persistent_volume=False,
        network_egress=False,
        network_policy=True,
        process_telemetry=True,
        file_telemetry=True,
        network_telemetry=True,
        gui_access=False,
    )

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.range_root = Path(self.config.get("range_root", ".hellcat/ranges"))
        self.range_root.mkdir(parents=True, exist_ok=True)
        self._instances: dict[str, RangeInstance] = {}
        self._runtime_factory = self.config.get("runtime_factory") or SandboxRuntimeFactory(
            default_backend=self.config.get("runtime_backend", "process")
        )

    async def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        """Execute a range raid or drill."""
        start_time = datetime.utcnow()
        ctx.ensure_shields()
        owned_ledger_writer = False

        # Emit step started event
        if ctx.ledger_writer or ctx.shield_manager:
            from hellcat.trust.ledger.events import StepStartedEvent
            await ctx.emit_event(StepStartedEvent(
                run_id=ctx.run_id,
                step_id=ctx.step_id,
                provider=self.name,
                manifest_id=ctx.manifest.manifest_id if ctx.manifest else "",
            ))

        try:
            # Load range template and drill spec from manifest/metadata
            template = self._load_template(ctx)
            drill_spec = self._load_drill_spec(ctx)

            # Create sandbox
            sandbox_id = await self.create_sandbox(ctx)
            instance = self._instances.get(sandbox_id)
            if instance:
                instance.template = template
                instance.drill_spec = drill_spec
                if not ctx.ledger_writer:
                    from hellcat.trust.ledger.writer import JSONLSink, LedgerWriter

                    ledger_path_value = ctx.metadata.get("ledger_path")
                    if not ledger_path_value and instance.artifacts_dir:
                        ledger_path_value = str(instance.artifacts_dir / "ledger.jsonl")
                    if ledger_path_value:
                        ledger_path = Path(ledger_path_value)
                        ctx.ledger_writer = LedgerWriter([JSONLSink(ledger_path)])
                        owned_ledger_writer = True
                self._write_run_artifacts(ctx, instance)
                self._write_range_template(instance)
                self._write_drill_spec_artifact(instance)

            # Start range environment
            await self._start_range(ctx, instance)

            # Run scenario (emit attack events)
            detections = await self._run_scenario(ctx, instance)

            # Generate ground truth artifacts
            ground_truth_path = await self._write_ground_truth(ctx, instance)
            detections_path = await self._write_detections(ctx, instance, detections)

            # Run drill-score gate if spec provided
            score_result = None
            if drill_spec and instance:
                score_result = await self._run_drill_score(ctx, instance)

            scorecard_path = None
            if instance:
                scorecard_path = self._write_scorecard(ctx, instance, score_result)

            # Stop range
            await self._stop_range(ctx, instance)

            # Build artifacts
            artifacts: dict[str, Path | bytes] = {}
            if ground_truth_path and ground_truth_path.exists():
                artifacts["ground_truth"] = ground_truth_path
            if detections_path and detections_path.exists():
                artifacts["detections"] = detections_path
            if score_result:
                artifacts["drill_score"] = score_result
            if scorecard_path and scorecard_path.exists():
                artifacts["scorecard"] = scorecard_path

            status = "success"
            exit_code = 0
            error_msg = None

            # Check score result for pass/fail
            if score_result and score_result.exists():
                score_data = json.loads(score_result.read_text())
                if not score_data.get("passed", True):
                    status = "failed"
                    exit_code = 1

            if instance:
                self._write_proof(ctx, instance, status, score_result)

        except Exception as e:
            logger.exception("Range execution failed")
            status = "error"
            exit_code = 1
            error_msg = str(e)
            artifacts = {}

        # Emit step completed event
        if ctx.ledger_writer or ctx.shield_manager:
            from hellcat.trust.ledger.events import StepCompletedEvent
            await ctx.emit_event(StepCompletedEvent(
                run_id=ctx.run_id,
                step_id=ctx.step_id,
                status=status,
                duration_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000),
                exit_code=exit_code,
            ))

        if owned_ledger_writer and ctx.ledger_writer:
            await ctx.ledger_writer.flush()

        return ExecutionResult(
            status=status,
            exit_code=exit_code,
            artifacts=artifacts,
            error_message=error_msg,
            started_at=start_time,
            completed_at=datetime.utcnow(),
        )

    def _load_template(self, ctx: ExecutionContext) -> RangeTemplate:
        """Load range template from context."""
        # Check metadata for template
        metadata = ctx.metadata

        if "range_template" in metadata:
            return RangeTemplate.from_dict(metadata["range_template"])

        if "range_template_path" in metadata:
            return RangeTemplate.from_file(Path(metadata["range_template_path"]))

        # Default template
        return RangeTemplate(
            template_id="range.default",
            name="Default Range",
            environment={"kind": "corp_net"},
            scenario={"red_team_mode": "scripted", "attack_events": []},
        )

    def _load_drill_spec(self, ctx: ExecutionContext) -> DrillSpec | None:
        """Load drill spec from context."""
        metadata = ctx.metadata

        if "drill_spec" in metadata:
            return DrillSpec.from_dict(metadata["drill_spec"])

        if "drill_spec_path" in metadata:
            return DrillSpec.from_file(Path(metadata["drill_spec_path"]))

        return None

    async def _start_range(self, ctx: ExecutionContext, instance: RangeInstance | None) -> None:
        """Start the range environment."""
        if instance:
            instance.status = "starting"
            instance.started_at = datetime.utcnow()

        logger.info(f"Starting range for run {ctx.run_id}")

        if instance:
            runtime = self._build_runtime(ctx, instance)
            if runtime:
                handle = await runtime.start(workdir=instance.artifacts_dir or Path.cwd())
                instance.runtime_handle = handle
                instance.runtime_backend = handle.backend
                ctx.metadata["runtime_handle"] = handle.metadata if hasattr(handle, "metadata") else {}

            instance.status = "running"

        if ctx.ledger_writer or ctx.shield_manager:
            from hellcat.trust.ledger.events import RangeStartedEvent
            await ctx.emit_event(
                RangeStartedEvent(
                    run_id=ctx.run_id,
                    template_id=instance.template.template_id if instance else "",
                    drill_id=instance.drill_spec.drill_id if instance and instance.drill_spec else "",
                )
            )

    async def _run_scenario(
        self,
        ctx: ExecutionContext,
        instance: RangeInstance | None,
    ) -> list[dict[str, Any]]:
        """Run the attack scenario and collect detections."""
        detections: list[dict[str, Any]] = []

        if not instance or not instance.template:
            return detections

        events = self._ordered_events(instance.template.attack_events)
        logger.info(f"Running scenario with {len(events)} attack events")

        delay_seconds = self._event_delay_seconds(ctx, instance)

        for event in events:
            # Emit attack event to ledger
            if ctx.ledger_writer or ctx.shield_manager:
                from hellcat.trust.ledger.events import AttackSimulationEvent

                attack_event = AttackSimulationEvent(
                    run_id=ctx.run_id,
                    event_id=event.get("event_id", ""),
                    event_type=event.get("event_type", ""),
                    attack_id=event.get("attack_id", ""),
                    objective_id=event.get("objective_id", ""),
                    severity=event.get("severity", "medium"),
                    source=event.get("source", ""),
                    target=event.get("target", ""),
                    timestamp=event.get("timestamp"),
                    tags=event.get("tags", []),
                )

                actions = await ctx.emit_event(attack_event)

                # Record emitted event
                instance.emitted_events.append(event)

                # Check for shield detections
                event_timestamp = event.get("timestamp")
                for action in actions:
                    if action.action == "alert":
                        detection = {
                            "detection_id": str(action.event_id) if hasattr(action, "event_id") else "",
                            "attack_event_id": event.get("event_id", ""),
                            "timestamp": event_timestamp or datetime.utcnow().isoformat() + "Z",
                            "shield": getattr(action, "shield_name", "unknown"),
                        }
                        detections.append(detection)
                        instance.detections.append(detection)

            if delay_seconds > 0:
                await asyncio.sleep(delay_seconds)

        return detections

    async def _write_ground_truth(
        self,
        ctx: ExecutionContext,
        instance: RangeInstance | None,
    ) -> Path | None:
        """Write ground truth events to file."""
        if not instance or not instance.artifacts_dir:
            return None

        ground_truth = {
            "schema_version": "1.0",
            "run_id": ctx.run_id,
            "template_id": instance.template.template_id if instance.template else "",
            "events": self._ordered_events(instance.emitted_events),
            "generated_at": self._generated_at(ctx, instance),
        }

        path = instance.artifacts_dir / "ground_truth.json"
        path.write_text(json.dumps(ground_truth, indent=2))
        return path

    async def _write_detections(
        self,
        ctx: ExecutionContext,
        instance: RangeInstance | None,
        detections: list[dict[str, Any]],
    ) -> Path | None:
        """Write detections to file."""
        if not instance or not instance.artifacts_dir:
            return None

        detection_data = {
            "schema_version": "1.0",
            "run_id": ctx.run_id,
            "detections": detections,
            "policy_violations": 0,  # TODO: count from ledger
            "generated_at": self._generated_at(ctx, instance),
        }

        path = instance.artifacts_dir / "detections.json"
        path.write_text(json.dumps(detection_data, indent=2))
        return path

    async def _run_drill_score(
        self,
        ctx: ExecutionContext,
        instance: RangeInstance,
    ) -> Path | None:
        """Run the drill-score gate on the results."""
        if not instance.artifacts_dir or not instance.drill_spec:
            return None

        # Write drill spec for the gate (if missing)
        spec_path = instance.artifacts_dir / "drill_spec.json"
        if not spec_path.exists():
            spec_path.write_text(json.dumps(instance.drill_spec.to_dict(), indent=2))

        # Run drill_score gate
        try:
            import sys

            from hellcat.core.gates.drill_score import main as drill_score_main

            # Capture original argv
            orig_argv = sys.argv

            try:
                sys.argv = [
                    "drill_score",
                    str(instance.artifacts_dir),
                    "--drill-spec", str(spec_path),
                    "--output", str(instance.artifacts_dir / "drill_score.json"),
                ]
                drill_score_main()
            finally:
                sys.argv = orig_argv

            return instance.artifacts_dir / "drill_score.json"

        except Exception as e:
            logger.warning(f"Failed to run drill-score gate: {e}")
            return None

    async def _stop_range(self, ctx: ExecutionContext, instance: RangeInstance | None) -> None:
        """Stop the range environment."""
        if instance:
            instance.status = "completed"
            instance.completed_at = datetime.utcnow()

        logger.info(f"Stopping range for run {ctx.run_id}")
        if instance and instance.runtime_handle:
            runtime = self._build_runtime(ctx, instance)
            if runtime:
                await runtime.stop(instance.runtime_handle)

        if ctx.ledger_writer or ctx.shield_manager:
            from hellcat.trust.ledger.events import RangeCompletedEvent
            await ctx.emit_event(
                RangeCompletedEvent(
                    run_id=ctx.run_id,
                    template_id=instance.template.template_id if instance else "",
                    status=instance.status if instance else "completed",
                    duration_ms=int(
                        (instance.completed_at - instance.started_at).total_seconds() * 1000
                    )
                    if instance and instance.started_at and instance.completed_at
                    else 0,
                    events_emitted=len(instance.emitted_events) if instance else 0,
                    detections=len(instance.detections) if instance else 0,
                )
            )

    def _resolve_artifacts_dir(self, ctx: ExecutionContext, sandbox_id: str) -> Path:
        """Resolve the artifacts directory for a run."""
        run_dir = ctx.metadata.get("run_dir") or ctx.metadata.get("artifacts_dir")
        path = Path(run_dir) if run_dir else self.range_root / sandbox_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _write_run_artifacts(self, ctx: ExecutionContext, instance: RangeInstance) -> None:
        """Write run-level artifacts for receipts."""
        if not instance.artifacts_dir:
            return
        if ctx.metadata.get("write_run_artifacts") is False:
            return

        run_dir = instance.artifacts_dir

        # Manifest
        if ctx.manifest:
            (run_dir / "manifest.json").write_text(
                json.dumps(ctx.manifest.to_dict(), indent=2)
            )

            if ctx.manifest.security:
                (run_dir / "security_policy.json").write_text(
                    json.dumps(ctx.manifest.security.to_dict(), indent=2)
                )

        # Context
        context: dict[str, Any] = {
            "universe_id": ctx.metadata.get("universe_id", "aegis-cyber-raids"),
            "universe_name": ctx.metadata.get("universe_name", "Aegis Cyber Raids"),
            "world_id": ctx.metadata.get("world_id", instance.template.template_id),
            "world_name": ctx.metadata.get("world_name", instance.template.name),
            "world_version": ctx.metadata.get("world_version", instance.template.version),
            "toolchain": ctx.manifest.toolchain if ctx.manifest else "attack_range",
            "provider": self.name,
            "git_sha": ctx.metadata.get("git_sha"),
            "receipt_id": ctx.metadata.get("receipt_id"),
        }
        extra_context = ctx.metadata.get("run_context")
        if isinstance(extra_context, dict):
            context.update(extra_context)

        (run_dir / "context.json").write_text(json.dumps(context, indent=2))

    def _write_range_template(self, instance: RangeInstance) -> None:
        if not instance.artifacts_dir:
            return
        payload = instance.template.to_dict()
        (instance.artifacts_dir / "range_template.json").write_text(
            json.dumps(payload, indent=2)
        )

    def _write_drill_spec_artifact(self, instance: RangeInstance) -> None:
        if not instance.artifacts_dir or not instance.drill_spec:
            return
        payload = instance.drill_spec.to_dict()
        (instance.artifacts_dir / "drill_spec.json").write_text(
            json.dumps(payload, indent=2)
        )

    def _write_scorecard(
        self,
        ctx: ExecutionContext,
        instance: RangeInstance,
        score_path: Path | None,
    ) -> Path | None:
        """Write a normalized scorecard summary."""
        if not instance.artifacts_dir:
            return None
        score_data: dict[str, Any] = {}
        if score_path and score_path.exists():
            try:
                score_data = json.loads(score_path.read_text())
            except json.JSONDecodeError:
                score_data = {}

        scorecard = {
            "schema_version": "1.0",
            "run_id": ctx.run_id,
            "template_id": instance.template.template_id,
            "drill_id": instance.drill_spec.drill_id if instance.drill_spec else "",
            "events_emitted": len(instance.emitted_events),
            "detections": len(instance.detections),
            "passed": score_data.get("passed", True),
            "score": score_data.get("score"),
            "metrics": score_data.get("metrics", {}),
            "generated_at": self._generated_at(ctx, instance),
        }

        path = instance.artifacts_dir / "scorecard.json"
        path.write_text(json.dumps(scorecard, indent=2))
        return path

    def _write_proof(
        self,
        ctx: ExecutionContext,
        instance: RangeInstance,
        status: str,
        score_path: Path | None,
    ) -> None:
        """Write proof.json for receipts."""
        if not instance.artifacts_dir:
            return

        score_data: dict[str, Any] = {}
        if score_path and score_path.exists():
            try:
                score_data = json.loads(score_path.read_text())
            except json.JSONDecodeError:
                score_data = {}

        verdict = {
            "passed": score_data.get("passed", status == "success"),
            "gate_id": score_data.get("gate_id", "drill-score"),
            "scores": {"overall": score_data.get("score")},
            "threshold": score_data.get("thresholds", {}).get("overall_threshold"),
        }

        verification = self._build_gate_verification(status, score_data, verdict)

        proof = {
            "schema_version": "1.0",
            "run_id": ctx.run_id,
            "provider": self.name,
            "status": status,
            "verdict": verdict,
            "verification": verification,
            "artifacts": {
                "ground_truth": "ground_truth.json",
                "detections": "detections.json",
                "scorecard": "scorecard.json",
                "drill_score": score_path.name if score_path else None,
            },
            "completed_at": self._generated_at(ctx, instance),
        }
        (instance.artifacts_dir / "proof.json").write_text(json.dumps(proof, indent=2))
        if verification.get("gates"):
            emit_gates_event(
                logs_dir=resolve_logs_dir(self.range_root),
                workcell_id=ctx.run_id,
                passed=bool(verification.get("all_passed", False)),
                results=verification.get("gates", {}),
                summary=verification.get("gate_summary"),
            )

    def _build_gate_verification(
        self,
        status: str,
        score_data: dict[str, Any],
        verdict: dict[str, Any],
    ) -> dict[str, Any]:
        gate_name = score_data.get("gate_id") or verdict.get("gate_id") or "drill-score"
        passed = bool(score_data.get("passed", verdict.get("passed", status == "success")))
        timing = score_data.get("timing") if isinstance(score_data.get("timing"), dict) else {}
        duration_ms = int(timing.get("duration_ms") or 0)
        errors = score_data.get("errors")
        failure_summary = None
        if not passed:
            if isinstance(errors, list) and errors:
                failure_summary = "; ".join(str(e) for e in errors[:3])
            else:
                failure_summary = score_data.get("verdict") or "gate_failed"

        raw_result: dict[str, Any] = {
            "passed": passed,
            "duration_ms": duration_ms,
            "blocking": True,
            "gate_type": "provider",
            "score": score_data.get("score"),
            "threshold": verdict.get("threshold"),
            "metrics": score_data.get("metrics"),
            "verdict": score_data.get("verdict") or verdict.get("verdict"),
            "failure_summary": failure_summary,
        }

        if not score_data:
            raw_result.update(
                {
                    "passed": status == "success",
                    "skipped": True,
                    "reason": "score_missing",
                }
            )

        normalized = normalize_gate_result(
            name=str(gate_name),
            result=raw_result,
            gate_type="provider",
        )
        verification = build_verification_payload({str(gate_name): normalized})
        if status != "success":
            blocking = verification.get("blocking_failures")
            if not isinstance(blocking, list):
                blocking = []
            status_marker = f"status:{status}"
            if status_marker not in blocking:
                blocking.append(status_marker)
            verification["blocking_failures"] = blocking
            verification["all_passed"] = False
        return verification

    def _ordered_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Deterministically order events by timestamp (fallback to original index)."""
        def _parse_ts(value: str | None) -> datetime | None:
            if not value:
                return None
            try:
                if value.endswith("Z"):
                    value = value[:-1] + "+00:00"
                return datetime.fromisoformat(value)
            except ValueError:
                return None

        indexed = list(enumerate(events))
        indexed.sort(
            key=lambda item: (
                _parse_ts(item[1].get("timestamp")) or datetime.min,
                item[0],
            )
        )
        return [event for _, event in indexed]

    def _event_delay_seconds(self, ctx: ExecutionContext, instance: RangeInstance) -> float:
        delay = ctx.metadata.get("event_delay_seconds")
        if delay is None:
            delay = instance.template.scenario.get("event_delay_seconds")
        if delay is None:
            delay = self.config.get("event_delay_seconds", 0.0)
        try:
            return float(delay)
        except (TypeError, ValueError):
            return 0.0

    def _generated_at(self, ctx: ExecutionContext, instance: RangeInstance) -> str:
        deterministic = ctx.metadata.get("deterministic")
        if deterministic is None:
            deterministic = bool(instance.template.environment.get("seed"))
        if deterministic:
            events = self._ordered_events(instance.emitted_events or instance.template.attack_events)
            first_ts = events[0].get("timestamp") if events else None
            if first_ts:
                return first_ts
            if instance.started_at:
                return instance.started_at.isoformat() + "Z"
        return datetime.utcnow().isoformat() + "Z"

    def _build_runtime(self, ctx: ExecutionContext, instance: RangeInstance) -> Any | None:
        """Build a sandbox runtime for the range."""
        runtime_cfg: dict[str, Any] = {}
        if isinstance(self.config.get("runtime"), dict):
            runtime_cfg.update(self.config.get("runtime", {}))
        if isinstance(instance.template.runtime, dict):
            runtime_cfg.update(instance.template.runtime)
        if isinstance(ctx.metadata.get("runtime"), dict):
            runtime_cfg.update(ctx.metadata.get("runtime", {}))

        backend = runtime_cfg.get("backend") or self.config.get("runtime_backend", "process")
        image = runtime_cfg.get("image") or self.config.get("container_image")
        command = runtime_cfg.get("command") or self.config.get("runtime_command")
        if isinstance(command, str):
            import shlex
            command = shlex.split(command)
        env = {}
        if isinstance(runtime_cfg.get("env"), dict):
            env.update(runtime_cfg.get("env", {}))
        if isinstance(ctx.metadata.get("runtime_env"), dict):
            env.update(ctx.metadata.get("runtime_env", {}))

        env.setdefault("HELLCAT_RUN_ID", ctx.run_id)
        if instance.artifacts_dir:
            env.setdefault("HELLCAT_RUN_DIR", str(instance.artifacts_dir))
        env.setdefault("RANGE_TEMPLATE_ID", instance.template.template_id)

        mounts: list[SandboxMount] = []
        raw_mounts = runtime_cfg.get("mounts") or []
        if isinstance(raw_mounts, list):
            for mount in raw_mounts:
                if not isinstance(mount, dict):
                    continue
                host = mount.get("host_path")
                container = mount.get("container_path")
                if not host or not container:
                    continue
                mounts.append(
                    SandboxMount(
                        host_path=Path(host),
                        container_path=str(container),
                        mode=str(mount.get("mode", "rw")),
                    )
                )

        backend_value = str(backend)
        if backend_value == "container":
            if not image:
                logger.warning("Container backend selected without image; falling back to process")
                backend_value = "process"
            else:
                import shutil
                runtime_bin = runtime_cfg.get("runtime_bin")
                if not runtime_bin and not (shutil.which("docker") or shutil.which("podman")):
                    logger.warning("Container backend selected without runtime; falling back to process")
                    backend_value = "process"
        config = SandboxRuntimeConfig(
            backend=backend_value,
            image=str(image) if image else None,
            command=command if isinstance(command, list) else None,
            env=env,
            mounts=mounts,
            network_mode=str(runtime_cfg.get("network_mode", "none")),
            workdir=runtime_cfg.get("workdir"),
            cpu_limit=runtime_cfg.get("cpu_limit"),
            memory_mb=runtime_cfg.get("memory_mb"),
            runtime_bin=runtime_cfg.get("runtime_bin"),
            name_prefix=str(runtime_cfg.get("name_prefix", "hellcat-range")),
        )
        return self._runtime_factory.build(config)

    async def stream_logs(self, ctx: ExecutionContext) -> AsyncIterator[str]:
        """Stream logs from a running range."""
        instance = self._instances.get(f"range-{ctx.run_id}")
        if not instance:
            return

        yield f"[range] Started at {instance.started_at}\n"
        yield f"[range] Template: {instance.template.name}\n"

        for event in instance.emitted_events:
            yield f"[attack] {event.get('event_type', 'unknown')}: {event.get('event_id', '')}\n"

        for detection in instance.detections:
            yield f"[detection] {detection.get('shield', 'unknown')}: {detection.get('attack_event_id', '')}\n"

    async def cancel(self, ctx: ExecutionContext) -> bool:
        """Cancel a running range."""
        instance = self._instances.get(f"range-{ctx.run_id}")
        if not instance:
            return False

        instance.status = "cancelled"
        instance.completed_at = datetime.utcnow()

        # TODO: Actually terminate the range environment

        return True

    async def health_check(self) -> bool:
        """Check provider health."""
        return self.range_root.exists()

    async def create_sandbox(self, ctx: ExecutionContext) -> str:
        """Create a sandbox for the range."""
        sandbox_id = f"range-{ctx.run_id}"
        sandbox_path = self._resolve_artifacts_dir(ctx, sandbox_id)

        instance = RangeInstance(
            instance_id=sandbox_id,
            template=RangeTemplate(),
            drill_spec=None,
            run_id=ctx.run_id,
            artifacts_dir=sandbox_path,
        )
        self._instances[sandbox_id] = instance

        return sandbox_id

    async def destroy_sandbox(self, sandbox_id: str) -> None:
        """Destroy a range sandbox."""
        self._instances.pop(sandbox_id, None)
