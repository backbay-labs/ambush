"""
StrikeCellManager - Creates, executes, and cleans up StrikeCells.

Adapted from the kernel's WorkcellManager pattern. Supports Docker-based
isolation (production) and a subprocess fallback (local dev/testing).
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import structlog

from hellcat.offensive.strikecell.browser import BrowserConfig, BrowserManager
from hellcat.offensive.strikecell.cell import StrikeCell, StrikeCellResult, StrikeCellState
from hellcat.offensive.strikecell.manifest import StrikeManifest

logger = structlog.get_logger()

_DOCKER_IMAGE = "hellcat/strikecell:latest"


class StrikeCellManager:
    """
    Manages Docker-isolated (or subprocess-based) execution environments
    for security operators.
    """

    def __init__(
        self,
        base_dir: Path,
        *,
        use_docker: bool = True,
        docker_image: str = _DOCKER_IMAGE,
        archives_dir: Path | None = None,
    ) -> None:
        self.base_dir = base_dir
        self.use_docker = use_docker
        self.docker_image = docker_image
        self.archives_dir = archives_dir or (base_dir / "archives")

        # Cell registry keyed by cell ID
        self._cells: dict[str, StrikeCell] = {}

        # Browser manager for Playwright MCP integration
        self._browser_manager = BrowserManager(
            base_dir=base_dir / "browsers",
        )

        # Ensure directories exist
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.archives_dir.mkdir(parents=True, exist_ok=True)

        if self.use_docker and not self._docker_available():
            logger.warning(
                "strikecell.docker_unavailable",
                msg="Docker not found; falling back to subprocess mode",
            )
            self.use_docker = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create(
        self,
        operator_name: str,
        target_url: str,
        manifest: StrikeManifest,
    ) -> StrikeCell:
        """
        Create a new StrikeCell for an operator execution.

        Allocates cell directories, writes the manifest, and optionally
        starts a Docker container.
        """
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        short_uuid = uuid.uuid4().hex[:6]
        cell_id = f"sc-{operator_name}-{timestamp}-{short_uuid}"

        cell_root = self.base_dir / cell_id
        logs_dir = cell_root / "logs"
        artifacts_dir = cell_root / "artifacts"
        workspace_dir = cell_root / "workspace"

        for d in (logs_dir, artifacts_dir, workspace_dir):
            d.mkdir(parents=True, exist_ok=True)

        # Serialise manifest into workspace
        manifest_path = workspace_dir / "manifest.json"
        manifest_path.write_text(json.dumps(asdict(manifest), indent=2))

        cell = StrikeCell(
            id=cell_id,
            operator_name=operator_name,
            target_url=target_url,
            state=StrikeCellState.CREATING,
            container_id=None,
            created_at=timestamp,
            completed_at=None,
            manifest=manifest,
            logs_dir=logs_dir,
            artifacts_dir=artifacts_dir,
        )

        logger.info(
            "strikecell.creating",
            cell_id=cell_id,
            operator=operator_name,
            target_url=target_url,
            use_docker=self.use_docker,
        )

        # Provision browser if enabled
        if manifest.browser_enabled:
            browser_cfg = BrowserConfig(**manifest.browser_config) if manifest.browser_config else BrowserConfig()
            browser_ctx = self._browser_manager.provision(cell_id, config=browser_cfg)
            manifest.mcp_server_name = browser_ctx.mcp_server_name
            # Write MCP config alongside manifest
            self._browser_manager.build_mcp_config_file(
                cell_id,
                output_path=workspace_dir / "mcp_config.json",
            )

        if self.use_docker:
            container_id = self._start_container(cell, workspace_dir)
            cell.container_id = container_id

        cell.state = StrikeCellState.READY
        self._cells[cell_id] = cell

        logger.info(
            "strikecell.ready",
            cell_id=cell_id,
            container_id=cell.container_id,
        )
        return cell

    def execute(self, cell: StrikeCell) -> StrikeCellResult:
        """
        Run the operator inside the StrikeCell and collect results.

        Uses Docker exec if a container is running, otherwise falls back
        to a local subprocess.
        """
        cell.state = StrikeCellState.RUNNING
        start_ms = _monotonic_ms()

        logger.info(
            "strikecell.executing",
            cell_id=cell.id,
            operator=cell.operator_name,
            timeout=cell.manifest.timeout_seconds,
        )

        try:
            if self.use_docker and cell.container_id:
                exit_code, error = self._run_docker(cell)
            else:
                exit_code, error = self._run_local(cell)
        except Exception as exc:
            duration_ms = _monotonic_ms() - start_ms
            cell.state = StrikeCellState.FAILED
            cell.completed_at = datetime.now(UTC).isoformat()
            logger.error(
                "strikecell.execution_error",
                cell_id=cell.id,
                error=str(exc),
            )
            return StrikeCellResult(
                cell_id=cell.id,
                success=False,
                exit_code=-1,
                duration_ms=duration_ms,
                proof_path=None,
                logs_path=cell.logs_dir,
                error=str(exc),
            )

        duration_ms = _monotonic_ms() - start_ms
        success = exit_code == 0

        cell.state = StrikeCellState.COMPLETED if success else StrikeCellState.FAILED
        cell.completed_at = datetime.now(UTC).isoformat()

        # Collect artifacts
        artifacts = self._collect_artifacts(cell)
        proof_path = cell.artifacts_dir / "proof.json"

        result = StrikeCellResult(
            cell_id=cell.id,
            success=success,
            exit_code=exit_code,
            duration_ms=duration_ms,
            proof_path=proof_path if proof_path.exists() else None,
            logs_path=cell.logs_dir,
            artifacts=artifacts,
            error=error,
        )

        logger.info(
            "strikecell.completed",
            cell_id=cell.id,
            success=success,
            exit_code=exit_code,
            duration_ms=duration_ms,
            artifact_count=len(artifacts),
        )
        return result

    def cleanup(self, cell: StrikeCell, *, keep_logs: bool = True) -> None:
        """
        Tear down a StrikeCell.

        Stops the container (SIGTERM -> 10 s -> SIGKILL), optionally
        archives logs and artifacts, then removes the cell directory.
        """
        logger.info(
            "strikecell.cleaning",
            cell_id=cell.id,
            keep_logs=keep_logs,
        )

        # Stop container if running
        if self.use_docker and cell.container_id:
            self._stop_container(cell.container_id)

        # Clean up browser instance
        self._browser_manager.cleanup(cell.id)

        # Archive before removal
        if keep_logs:
            self._archive_cell(cell)

        # Remove cell directory
        cell_root = self.base_dir / cell.id
        if cell_root.exists():
            shutil.rmtree(cell_root, ignore_errors=True)

        cell.state = StrikeCellState.CLEANED
        self._cells.pop(cell.id, None)

        logger.info("strikecell.cleaned", cell_id=cell.id)

    def list_active(self) -> list[StrikeCell]:
        """Return cells in CREATING, READY, or RUNNING state."""
        active_states = {
            StrikeCellState.CREATING,
            StrikeCellState.READY,
            StrikeCellState.RUNNING,
        }
        return [c for c in self._cells.values() if c.state in active_states]

    def get_cell(self, cell_id: str) -> StrikeCell | None:
        """Look up a cell by ID."""
        return self._cells.get(cell_id)

    # ------------------------------------------------------------------
    # Docker helpers
    # ------------------------------------------------------------------

    def _docker_available(self) -> bool:
        """Check whether the Docker daemon is reachable."""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _start_container(
        self,
        cell: StrikeCell,
        workspace_dir: Path,
    ) -> str:
        """Start a Docker container for the cell and return its ID."""
        env_vars: list[str] = []
        for key in ("ANTHROPIC_API_KEY",):
            val = os.environ.get(key)
            if val:
                env_vars.extend(["-e", f"{key}={val}"])

        env_vars.extend([
            "-e", f"TARGET_URL={cell.target_url}",
            "-e", f"OPERATOR_NAME={cell.operator_name}",
            "-e", f"CELL_ID={cell.id}",
        ])

        # Browser volume mounts (if browser is provisioned for this cell)
        browser_mounts = self._browser_manager.get_docker_mounts(cell.id)

        cmd: list[str] = [
            "docker", "run", "-d",
            "--name", cell.id,
            # Volume mounts
            "-v", f"{workspace_dir}:/workspace:rw",
            "-v", f"{cell.artifacts_dir}:/artifacts:rw",
            "-v", f"{cell.logs_dir}:/logs:rw",
            *browser_mounts,
            # Resource limits
            "--cpus", cell.manifest.cpu_limit,
            "--memory", cell.manifest.memory_limit,
            # Network
            "--network", "bridge",
            *env_vars,
            self.docker_image,
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to start container for {cell.id}: {result.stderr.strip()}"
            )

        container_id = result.stdout.strip()[:12]
        return container_id

    def _run_docker(self, cell: StrikeCell) -> tuple[int, str | None]:
        """Execute the operator command inside the running container."""
        cmd = [
            "docker", "exec",
            cell.id,
            "python", "-m", "hellcat.operators.run",
            "--manifest", "/workspace/manifest.json",
        ]

        log_path = cell.logs_dir / "execution.log"
        try:
            with open(log_path, "w") as log_fh:
                proc = subprocess.run(
                    cmd,
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                    timeout=cell.manifest.timeout_seconds,
                )
            return proc.returncode, None
        except subprocess.TimeoutExpired:
            logger.warning(
                "strikecell.timeout",
                cell_id=cell.id,
                timeout=cell.manifest.timeout_seconds,
            )
            return -1, f"Timed out after {cell.manifest.timeout_seconds}s"

    def _run_local(self, cell: StrikeCell) -> tuple[int, str | None]:
        """Subprocess fallback for local dev/testing (no Docker)."""
        cmd = [
            "python", "-m", "hellcat.operators.run",
            "--manifest", str(cell.logs_dir.parent / "workspace" / "manifest.json"),
        ]

        env = os.environ.copy()
        env.update({
            "TARGET_URL": cell.target_url,
            "OPERATOR_NAME": cell.operator_name,
            "CELL_ID": cell.id,
            "STRIKECELL_ARTIFACTS": str(cell.artifacts_dir),
            "STRIKECELL_LOGS": str(cell.logs_dir),
        })

        log_path = cell.logs_dir / "execution.log"
        try:
            with open(log_path, "w") as log_fh:
                proc = subprocess.run(
                    cmd,
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                    timeout=cell.manifest.timeout_seconds,
                    env=env,
                )
            return proc.returncode, None
        except subprocess.TimeoutExpired:
            logger.warning(
                "strikecell.timeout",
                cell_id=cell.id,
                timeout=cell.manifest.timeout_seconds,
            )
            return -1, f"Timed out after {cell.manifest.timeout_seconds}s"

    def _stop_container(self, container_id: str) -> None:
        """Stop a container with SIGTERM -> 10 s grace -> SIGKILL."""
        try:
            subprocess.run(
                ["docker", "stop", "-t", "10", container_id],
                capture_output=True,
                timeout=20,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Force kill
            with contextlib.suppress(subprocess.TimeoutExpired, FileNotFoundError):
                subprocess.run(
                    ["docker", "kill", container_id],
                    capture_output=True,
                    timeout=10,
                )

        # Remove container
        with contextlib.suppress(subprocess.TimeoutExpired, FileNotFoundError):
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                capture_output=True,
                timeout=10,
            )

    # ------------------------------------------------------------------
    # Artifact and archive helpers
    # ------------------------------------------------------------------

    def _collect_artifacts(self, cell: StrikeCell) -> list[str]:
        """Return filenames present in the cell's artifacts directory."""
        if not cell.artifacts_dir.exists():
            return []
        return [f.name for f in cell.artifacts_dir.iterdir() if f.is_file()]

    def _archive_cell(self, cell: StrikeCell) -> None:
        """Copy logs and artifacts to the archives directory."""
        archive_path = self.archives_dir / cell.id
        archive_path.mkdir(parents=True, exist_ok=True)

        # Archive logs
        if cell.logs_dir.exists():
            dst = archive_path / "logs"
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(cell.logs_dir, dst, dirs_exist_ok=True)

        # Archive artifacts
        if cell.artifacts_dir.exists():
            dst = archive_path / "artifacts"
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(cell.artifacts_dir, dst, dirs_exist_ok=True)

        # Copy manifest
        cell_root = self.base_dir / cell.id
        manifest_src = cell_root / "workspace" / "manifest.json"
        if manifest_src.exists():
            shutil.copy(manifest_src, archive_path / "manifest.json")

        logger.info(
            "strikecell.archived",
            cell_id=cell.id,
            archive=str(archive_path),
        )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _monotonic_ms() -> int:
    """Current monotonic time in milliseconds."""
    return int(time.monotonic() * 1000)
