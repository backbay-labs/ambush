"""
Fab World Adapter - Execute deterministic world builds in workcells.

This adapter runs the local `fab-world` pipeline (implemented in `cyntra.fab.world`)
inside a workcell sandbox, producing a build manifest and optional gate results.

Note: workcells are isolation sandboxes; not every toolchain is an LLM agent.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog

from cyntra.core.adapters.base import CostEstimate, PatchProof, ToolchainAdapter
from cyntra.core.gates.results import (
    build_verification_payload,
    emit_gates_event,
    normalize_gate_result,
    resolve_logs_dir,
)

logger = structlog.get_logger()


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class WorldBuildResult:
    world_id: str
    run_id: str
    run_dir: Path
    manifest_path: Path
    manifest: dict[str, Any] | None


class FabWorldAdapter(ToolchainAdapter):
    """
    Adapter that builds a Fab World (non-LLM toolchain).

    Expected manifest shape (Dispatcher):
        manifest["world_config"] = {
          "world_path": "fab/worlds/outora_library",
          "seed": 42,
          "param_overrides": {"lighting.preset": "cosmic"},
          "quality_gates": ["fab/gates/interior_library_v001.yaml", ...],
        }
    """

    name = "fab-world"
    supports_mcp = False
    supports_streaming = False

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        if self._available is None:
            self._available = True
        return self._available

    async def health_check(self) -> bool:
        return True

    def estimate_cost(self, manifest: dict) -> CostEstimate:
        return CostEstimate(estimated_tokens=0, estimated_cost_usd=0.0, model="local")

    def execute_sync(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout_seconds: int = 1800,
    ) -> PatchProof:
        return asyncio.run(
            self.execute(
                manifest=manifest,
                workcell_path=workcell_path,
                timeout=timedelta(seconds=timeout_seconds),
            )
        )

    async def execute(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout: timedelta,
    ) -> PatchProof:
        started_at = _utc_now()
        workcell_id = str(manifest.get("workcell_id", "unknown"))
        issue_id = str((manifest.get("issue") or {}).get("id", "unknown"))

        logs_dir = workcell_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = logs_dir / "fab-world-stdout.log"
        stderr_path = logs_dir / "fab-world-stderr.log"

        world_config = manifest.get("world_config") or {}
        world_path = str(world_config.get("world_path") or "fab/worlds/outora_library")
        seed = int(world_config.get("seed") or 42)
        param_overrides = world_config.get("param_overrides") or {}

        repo_root = workcell_path
        if workcell_path.parent.name == ".workcells":
            repo_root = workcell_path.parent.parent

        run_dir = repo_root / ".cyntra" / "runs" / f"fab-world_{workcell_id}"
        run_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            "python",
            "-m",
            "cyntra.fab.world",
            "build",
            "--world",
            str((workcell_path / world_path).resolve()),
            "--output",
            str(run_dir.resolve()),
            "--seed",
            str(seed),
        ]
        for key, value in param_overrides.items():
            serialized = value
            if not isinstance(value, str):
                serialized = json.dumps(value)
            cmd.extend(["--param", f"{key}={serialized}"])

        logger.info(
            "fab-world build starting",
            workcell_id=workcell_id,
            issue_id=issue_id,
            world_path=world_path,
            seed=seed,
            run_dir=str(run_dir),
        )

        result = self._run_cmd(
            cmd=cmd,
            cwd=workcell_path / "kernel",
            timeout=timeout,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )

        build_result = self._load_build_result(run_dir)
        completed_at = _utc_now()
        duration_ms = int((completed_at - started_at).total_seconds() * 1000)

        status = "success" if result.returncode == 0 else "failed"
        verification = self._build_verification(status=status, build_result=build_result)

        if isinstance(verification, dict) and verification.get("gates"):
            emit_gates_event(
                logs_dir=resolve_logs_dir(workcell_path),
                workcell_id=workcell_id,
                passed=bool(verification.get("all_passed", False)),
                results=verification.get("gates", {}),
                summary=verification.get("gate_summary"),
            )

        patch: dict[str, Any] = {
            "files_modified": [],
            "diff_stats": {"files_changed": 0, "insertions": 0, "deletions": 0},
            "forbidden_path_violations": [],
        }
        artifacts: dict[str, Any] = {
            "run_dir": str(build_result.run_dir),
            "manifest_path": str(build_result.manifest_path),
        }
        if build_result.manifest:
            artifacts["world_id"] = build_result.manifest.get("world_id")
            artifacts["run_id"] = build_result.manifest.get("run_id")
            artifacts["final_outputs"] = build_result.manifest.get("final_outputs", [])
            publish_info = self._maybe_publish_to_viewer(build_result, repo_root, status=status)
            if publish_info:
                artifacts["viewer_publish"] = publish_info

        return PatchProof(
            schema_version="1.0.0",
            workcell_id=workcell_id,
            issue_id=issue_id,
            status=status,
            patch=patch,
            verification=verification,
            metadata={
                "toolchain": self.name,
                "model": "local",
                "started_at": started_at.isoformat().replace("+00:00", "Z"),
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "duration_ms": duration_ms,
                "exit_code": result.returncode,
            },
            commands_executed=[
                {
                    "command": " ".join(cmd),
                    "exit_code": result.returncode,
                    "duration_ms": duration_ms,
                    "stdout_path": str(stdout_path),
                    "stderr_path": str(stderr_path),
                }
            ],
            artifacts=artifacts,
            confidence=0.9 if status == "success" else 0.2,
            risk_classification="low",
        )

    def _maybe_publish_to_viewer(
        self,
        build_result: WorldBuildResult,
        repo_root: Path,
        *,
        status: str,
    ) -> dict[str, Any] | None:
        auto_publish = self.config.get("auto_publish_viewer", True)
        if isinstance(auto_publish, bool) and not auto_publish:
            return None

        if status != "success":
            return None

        viewer_dir = self._resolve_viewer_dir(repo_root)
        if not viewer_dir:
            return None

        if not build_result.manifest:
            return None

        world_id = str(build_result.manifest.get("world_id") or "")
        if not world_id or world_id == "unknown":
            return None

        try:
            publish_info = self._publish_to_viewer(build_result, viewer_dir, world_id)
            if publish_info:
                logger.info(
                    "fab-world published to viewer",
                    world_id=world_id,
                    viewer_dir=str(viewer_dir),
                )
            return publish_info
        except Exception as exc:
            logger.warning(
                "fab-world publish failed",
                world_id=world_id,
                viewer_dir=str(viewer_dir),
                error=str(exc),
            )
            return {"error": str(exc), "viewer_dir": str(viewer_dir)}

    def _resolve_viewer_dir(self, repo_root: Path) -> Path | None:
        configured = self.config.get("viewer_dir") or os.environ.get("CYNTRA_VIEWER_DIR")
        if configured:
            viewer_path = Path(str(configured))
            if not viewer_path.is_absolute():
                viewer_path = repo_root / viewer_path
            if viewer_path.exists():
                return viewer_path
            logger.warning("viewer dir not found", viewer_dir=str(viewer_path))
            return None

        default_viewer = repo_root / "fab" / "assets" / "viewer"
        if default_viewer.exists():
            return default_viewer
        return None

    def _publish_to_viewer(
        self,
        build_result: WorldBuildResult,
        viewer_dir: Path,
        world_id: str,
    ) -> dict[str, Any] | None:
        main_glb = build_result.run_dir / "world" / f"{world_id}.glb"
        if not main_glb.exists():
            raise FileNotFoundError(f"GLB not found: {main_glb}")

        viewer_glb_dir = viewer_dir / "assets" / "exports"
        viewer_glb_dir.mkdir(parents=True, exist_ok=True)
        dest_glb = viewer_glb_dir / f"{world_id}.glb"
        shutil.copy2(main_glb, dest_glb)

        publish_info: dict[str, Any] = {
            "viewer_dir": str(viewer_dir),
            "glb_path": str(dest_glb),
        }

        godot_index = build_result.run_dir / "godot" / "index.html"
        if godot_index.exists():
            viewer_game_dir = viewer_dir / "assets" / "games" / world_id
            viewer_game_dir.mkdir(parents=True, exist_ok=True)
            for item in (build_result.run_dir / "godot").iterdir():
                if item.is_file():
                    shutil.copy2(item, viewer_game_dir / item.name)
                elif item.is_dir():
                    shutil.copytree(item, viewer_game_dir / item.name, dirs_exist_ok=True)
            publish_info["godot_dir"] = str(viewer_game_dir)

        return publish_info

    def _build_verification(self, *, status: str, build_result: WorldBuildResult) -> dict[str, Any]:
        manifest = build_result.manifest or {}
        stages = manifest.get("stages") if isinstance(manifest, dict) else None
        if not isinstance(stages, list):
            verification = build_verification_payload({})
            if status != "success":
                verification["all_passed"] = False
            return verification

        validate_stage = None
        for stage in stages:
            if isinstance(stage, dict) and stage.get("id") == "validate":
                validate_stage = stage
                break

        metadata = validate_stage.get("metadata") if isinstance(validate_stage, dict) else None
        gates = metadata.get("gates") if isinstance(metadata, dict) else None
        if not isinstance(gates, list):
            verification = build_verification_payload({})
            if status != "success":
                verification["all_passed"] = False
            return verification

        stage_outputs: list[Path] = []
        outputs = validate_stage.get("outputs") if isinstance(validate_stage, dict) else None
        if isinstance(outputs, list):
            for entry in outputs:
                if not isinstance(entry, dict):
                    continue
                rel_path = entry.get("path")
                if not isinstance(rel_path, str) or not rel_path:
                    continue
                path = Path(rel_path)
                if not path.is_absolute():
                    path = build_result.run_dir / path
                stage_outputs.append(path)

        stage_errors = validate_stage.get("errors") if isinstance(validate_stage, dict) else None
        if not isinstance(stage_errors, list):
            stage_errors = []

        gate_results: dict[str, Any] = {}
        for idx, gate in enumerate(gates):
            if not isinstance(gate, dict):
                continue
            name = gate.get("gate")
            if not isinstance(name, str) or not name:
                continue
            passed = gate.get("passed") is True
            blocking_gate = bool(gate.get("blocking", True))

            output_path = None
            if idx < len(stage_outputs):
                output_path = str(stage_outputs[idx])

            failure_summary = gate.get("error") or gate.get("verdict")
            if not failure_summary and stage_errors:
                failure_summary = "; ".join(str(err) for err in stage_errors[:3])

            gate_results[name] = normalize_gate_result(
                name=name,
                result={
                    **dict(gate),
                    "gate": name,
                    "passed": passed,
                    "gate_type": "fab",
                    "blocking": blocking_gate,
                    "output_path": output_path,
                    "log_paths": [output_path] if output_path else [],
                    "failure_summary": failure_summary if not passed else None,
                    "duration_ms": int(validate_stage.get("duration_ms") or 0),
                },
                gate_type="fab",
            )

        verification = build_verification_payload(gate_results)
        if status != "success":
            verification["all_passed"] = False
        return verification

    def _run_cmd(
        self,
        *,
        cmd: list[str],
        cwd: Path,
        timeout: timedelta,
        stdout_path: Path,
        stderr_path: Path,
    ) -> subprocess.CompletedProcess[str]:
        timeout_seconds = max(int(timeout.total_seconds()), 1)
        env = os.environ.copy()
        raw_env = self.config.get("env")
        if isinstance(raw_env, dict):
            env.update({str(k): str(v) for k, v in raw_env.items()})
        try:
            completed = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                env=env,
            )
        except subprocess.TimeoutExpired as e:
            stdout_path.write_text(e.stdout or "")
            stderr_path.write_text((e.stderr or "") + "\nTIMEOUT\n")
            return subprocess.CompletedProcess(
                cmd, returncode=124, stdout=e.stdout or "", stderr=e.stderr or ""
            )

        stdout_path.write_text(completed.stdout or "")
        stderr_path.write_text(completed.stderr or "")
        return completed

    def _load_build_result(self, run_dir: Path) -> WorldBuildResult:
        manifest_path = run_dir / "manifest.json"
        manifest: dict[str, Any] | None = None
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text())
            except Exception:
                manifest = None
        world_id = str((manifest or {}).get("world_id", "unknown"))
        run_id = str((manifest or {}).get("run_id", "unknown"))
        return WorldBuildResult(
            world_id=world_id,
            run_id=run_id,
            run_dir=run_dir,
            manifest_path=manifest_path,
            manifest=manifest,
        )
