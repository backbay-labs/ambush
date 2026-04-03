"""
ComfyUI Adapter - Execute image generation workflows via ComfyUI.

This adapter runs ComfyUI workflows for image/video generation tasks,
supporting deterministic seed injection and parameter customization.

Note: This is a local toolchain adapter (not an LLM agent).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog

from cyntra.core.adapters.base import CostEstimate, PatchProof, ToolchainAdapter
from cyntra.fab.comfyui_client import (
    ComfyUIClient,
    ComfyUIConfig,
    ComfyUIConnectionError,
    ComfyUIExecutionError,
    ComfyUIResult,
    ComfyUITimeoutError,
)

logger = structlog.get_logger()


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class ComfyUITaskConfig:
    """Configuration for a ComfyUI generation task."""

    workflow_path: str
    seed: int = 42
    params: dict[str, Any] | None = None
    timeout_seconds: float = 300.0


class ComfyUIAdapter(ToolchainAdapter):
    """
    Adapter for ComfyUI image/video generation.

    This adapter executes ComfyUI workflows for deterministic asset generation.
    It's designed for use in the fab pipeline for texture generation, upscaling,
    and other image processing tasks.

    Expected manifest shape:
        manifest["comfyui_config"] = {
            "workflow_path": "fab/workflows/comfyui/txt2img_sdxl.json",
            "seed": 42,
            "params": {
                "positive_prompt": "a futuristic sports car",
                "negative_prompt": "blurry, low quality",
                "steps": 30,
                "cfg": 7.5,
            },
        }

    The adapter:
    1. Loads the workflow JSON from the specified path
    2. Injects the deterministic seed into all sampler nodes
    3. Injects custom parameters (prompts, steps, etc.)
    4. Queues the workflow and waits for completion
    5. Downloads outputs to the workcell
    6. Returns a PatchProof with artifacts

    Example usage:
        adapter = ComfyUIAdapter({"host": "localhost", "port": 8188})
        if await adapter.health_check():
            proof = await adapter.execute(manifest, workcell_path, timeout)
    """

    name = "comfyui"
    supports_mcp = False
    supports_streaming = False

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize ComfyUI adapter.

        Args:
            config: Configuration dict with:
                - host: ComfyUI server host (default: localhost)
                - port: ComfyUI server port (default: 8188)
                - timeout_minutes: Default timeout in minutes (default: 10)
                - workflow_dir: Base directory for workflow files
        """
        self.config = config or {}
        self.host = str(self.config.get("host", "localhost"))
        self.port = int(self.config.get("port", 8188))
        self.timeout_minutes = float(self.config.get("timeout_minutes", 10))
        self.workflow_dir = self.config.get("workflow_dir")
        self._available: bool | None = None
        self._client: ComfyUIClient | None = None

    @property
    def available(self) -> bool:
        """Check if adapter is available (sync check)."""
        if self._available is None:
            # For sync check, assume available and let health_check verify
            self._available = True
        return self._available

    def _get_client(self) -> ComfyUIClient:
        """Get or create the ComfyUI client."""
        if self._client is None:
            comfy_config = ComfyUIConfig(
                host=self.host,
                port=self.port,
                timeout_seconds=self.timeout_minutes * 60,
            )
            self._client = ComfyUIClient(comfy_config)
        return self._client

    async def health_check(self) -> bool:
        """
        Check if ComfyUI server is running and responsive.

        Returns:
            True if server is healthy, False otherwise
        """
        try:
            client = self._get_client()
            result = await client.health_check()
            self._available = result
            return result
        except Exception as e:
            logger.debug("ComfyUI health check failed", error=str(e))
            self._available = False
            return False

    def health_check_sync(self) -> bool:
        """Synchronous health check wrapper."""
        try:
            return asyncio.run(self.health_check())
        except Exception:
            return False

    def estimate_cost(self, manifest: dict) -> CostEstimate:
        """
        Estimate cost for ComfyUI execution.

        ComfyUI runs locally, so cost is zero (only GPU time/power).

        Args:
            manifest: Task manifest (unused for local toolchain)

        Returns:
            CostEstimate with zero tokens/cost
        """
        return CostEstimate(
            estimated_tokens=0,
            estimated_cost_usd=0.0,
            model="local-comfyui",
        )

    def execute_sync(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout_seconds: int = 600,
    ) -> PatchProof:
        """
        Synchronous execution wrapper.

        Args:
            manifest: Task manifest
            workcell_path: Path to workcell directory
            timeout_seconds: Timeout in seconds

        Returns:
            PatchProof with execution results
        """
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
        """
        Execute a ComfyUI workflow.

        Args:
            manifest: Task manifest with comfyui_config
            workcell_path: Path to workcell directory
            timeout: Maximum execution time

        Returns:
            PatchProof with status, artifacts, and metadata
        """
        started_at = _utc_now()
        workcell_id = str(manifest.get("workcell_id", "unknown"))
        issue = manifest.get("issue") or {}
        issue_id = str(issue.get("id", "unknown"))

        # Setup logging directory
        logs_dir = workcell_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        # Setup output directory
        output_dir = workcell_path / "comfyui_outputs"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Parse ComfyUI config from manifest
        comfyui_config = manifest.get("comfyui_config") or {}
        task_config = self._parse_task_config(comfyui_config, timeout)

        logger.info(
            "ComfyUI execution starting",
            workcell_id=workcell_id,
            issue_id=issue_id,
            workflow_path=task_config.workflow_path,
            seed=task_config.seed,
        )

        try:
            # Load workflow
            workflow_path = self._resolve_workflow_path(
                task_config.workflow_path,
                workcell_path,
            )
            if not workflow_path or not workflow_path.exists():
                return self._create_error_proof(
                    workcell_id=workcell_id,
                    issue_id=issue_id,
                    error=f"Workflow not found: {task_config.workflow_path}",
                    started_at=started_at,
                )

            workflow = ComfyUIClient.load_workflow(workflow_path)

            # Inject seed for determinism
            workflow = ComfyUIClient.inject_seed(workflow, task_config.seed)

            # Inject custom parameters
            if task_config.params:
                workflow = ComfyUIClient.inject_params(workflow, task_config.params)

            # Execute workflow
            client = self._get_client()

            # Health check first
            if not await client.health_check():
                return self._create_error_proof(
                    workcell_id=workcell_id,
                    issue_id=issue_id,
                    error="ComfyUI server not available",
                    started_at=started_at,
                )

            # Queue prompt
            prompt_id = await client.queue_prompt(workflow)

            # Wait for completion
            result = await client.wait_for_completion(
                prompt_id,
                timeout=task_config.timeout_seconds,
            )

            # Download outputs if successful
            downloaded: dict[str, list[Path]] = {}
            if result.status == "completed":
                downloaded = await client.download_outputs(result, output_dir)

            # Build proof
            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            return self._build_proof(
                workcell_id=workcell_id,
                issue_id=issue_id,
                result=result,
                downloaded=downloaded,
                workflow_path=str(workflow_path),
                seed=task_config.seed,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

        except ComfyUITimeoutError as e:
            return self._create_timeout_proof(
                workcell_id=workcell_id,
                issue_id=issue_id,
                error=str(e),
                started_at=started_at,
            )

        except ComfyUIConnectionError as e:
            return self._create_error_proof(
                workcell_id=workcell_id,
                issue_id=issue_id,
                error=f"Connection failed: {e}",
                started_at=started_at,
            )

        except ComfyUIExecutionError as e:
            return self._create_error_proof(
                workcell_id=workcell_id,
                issue_id=issue_id,
                error=f"Execution failed: {e}",
                started_at=started_at,
            )

        except Exception as e:
            logger.exception("ComfyUI execution error", error=str(e))
            return self._create_error_proof(
                workcell_id=workcell_id,
                issue_id=issue_id,
                error=f"Unexpected error: {e}",
                started_at=started_at,
            )

    def _parse_task_config(
        self,
        config: dict[str, Any],
        timeout: timedelta,
    ) -> ComfyUITaskConfig:
        """Parse task configuration from manifest."""
        return ComfyUITaskConfig(
            workflow_path=str(config.get("workflow_path", "")),
            seed=int(config.get("seed", 42)),
            params=config.get("params"),
            timeout_seconds=float(config.get("timeout_seconds", timeout.total_seconds())),
        )

    def _resolve_workflow_path(
        self,
        workflow_path: str,
        workcell_path: Path,
    ) -> Path | None:
        """
        Resolve workflow path to absolute path.

        Tries in order:
        1. Absolute path
        2. Relative to workcell
        3. Relative to repo root (workcell parent)
        4. Relative to configured workflow_dir

        Args:
            workflow_path: Workflow path from config
            workcell_path: Workcell directory

        Returns:
            Resolved Path or None if not found
        """
        if not workflow_path:
            return None

        path = Path(workflow_path)

        # Absolute path
        if path.is_absolute() and path.exists():
            return path

        # Relative to workcell
        candidate = workcell_path / path
        if candidate.exists():
            return candidate

        # Relative to repo root (common pattern for workcells in .workcells/)
        repo_root = workcell_path
        if workcell_path.parent.name == ".workcells":
            repo_root = workcell_path.parent.parent
        candidate = repo_root / path
        if candidate.exists():
            return candidate

        # Relative to configured workflow_dir
        if self.workflow_dir:
            candidate = Path(self.workflow_dir) / path
            if candidate.exists():
                return candidate

        return None

    def _build_proof(
        self,
        *,
        workcell_id: str,
        issue_id: str,
        result: ComfyUIResult,
        downloaded: dict[str, list[Path]],
        workflow_path: str,
        seed: int,
        started_at: datetime,
        completed_at: datetime,
        duration_ms: int,
    ) -> PatchProof:
        """Build PatchProof from execution result."""
        status = "success" if result.status == "completed" else "failed"

        # Build artifacts with output file paths
        artifacts: dict[str, Any] = {
            "prompt_id": result.prompt_id,
            "execution_time_ms": result.execution_time_ms,
            "outputs": {node_id: [str(p) for p in paths] for node_id, paths in downloaded.items()},
        }

        # Flatten output paths for easy access
        all_outputs: list[str] = []
        for paths in downloaded.values():
            all_outputs.extend(str(p) for p in paths)
        if all_outputs:
            artifacts["output_files"] = all_outputs

        if result.error:
            artifacts["error"] = result.error
        if result.node_errors:
            artifacts["node_errors"] = result.node_errors

        return PatchProof(
            schema_version="1.0.0",
            workcell_id=workcell_id,
            issue_id=issue_id,
            status=status,
            patch={
                "files_modified": [],
                "diff_stats": {"files_changed": 0, "insertions": 0, "deletions": 0},
                "forbidden_path_violations": [],
            },
            verification={
                "gates": {},
                "all_passed": status == "success",
                "blocking_failures": [] if status == "success" else ["comfyui_execution"],
            },
            metadata={
                "toolchain": self.name,
                "model": "local-comfyui",
                "workflow_path": workflow_path,
                "seed": seed,
                "started_at": started_at.isoformat().replace("+00:00", "Z"),
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "duration_ms": duration_ms,
            },
            commands_executed=[
                {
                    "command": f"comfyui queue {workflow_path}",
                    "exit_code": 0 if status == "success" else 1,
                    "duration_ms": duration_ms,
                }
            ],
            artifacts=artifacts,
            confidence=0.95 if status == "success" else 0.1,
            risk_classification="low",
        )

    def _create_error_proof(
        self,
        *,
        workcell_id: str,
        issue_id: str,
        error: str,
        started_at: datetime,
    ) -> PatchProof:
        """Create PatchProof for execution error."""
        completed_at = _utc_now()
        duration_ms = int((completed_at - started_at).total_seconds() * 1000)

        return PatchProof(
            schema_version="1.0.0",
            workcell_id=workcell_id,
            issue_id=issue_id,
            status="error",
            patch={
                "files_modified": [],
                "diff_stats": {"files_changed": 0, "insertions": 0, "deletions": 0},
                "forbidden_path_violations": [],
            },
            verification={
                "gates": {},
                "all_passed": False,
                "blocking_failures": ["comfyui_error"],
            },
            metadata={
                "toolchain": self.name,
                "model": "local-comfyui",
                "started_at": started_at.isoformat().replace("+00:00", "Z"),
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "duration_ms": duration_ms,
                "error": error,
            },
            artifacts={"error": error},
            confidence=0.0,
            risk_classification="low",
        )

    def _create_timeout_proof(
        self,
        *,
        workcell_id: str,
        issue_id: str,
        error: str,
        started_at: datetime,
    ) -> PatchProof:
        """Create PatchProof for timeout."""
        completed_at = _utc_now()
        duration_ms = int((completed_at - started_at).total_seconds() * 1000)

        return PatchProof(
            schema_version="1.0.0",
            workcell_id=workcell_id,
            issue_id=issue_id,
            status="timeout",
            patch={
                "files_modified": [],
                "diff_stats": {"files_changed": 0, "insertions": 0, "deletions": 0},
                "forbidden_path_violations": [],
            },
            verification={
                "gates": {},
                "all_passed": False,
                "blocking_failures": ["comfyui_timeout"],
            },
            metadata={
                "toolchain": self.name,
                "model": "local-comfyui",
                "started_at": started_at.isoformat().replace("+00:00", "Z"),
                "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "duration_ms": duration_ms,
                "error": error,
            },
            artifacts={"error": error},
            confidence=0.0,
            risk_classification="low",
        )
