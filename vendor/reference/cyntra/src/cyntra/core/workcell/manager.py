"""
WorkcellManager - Creates and manages isolated git worktree execution environments.

Responsibilities:
- Create git worktrees for task isolation
- Manage workcell lifecycle
- Apply workcell templates for scoped contexts
- Archive logs on cleanup
- Prevent cross-workcell contamination
"""

from __future__ import annotations

import json
import os
import re
import signal
import shutil
import subprocess
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from cyntra.core.workcell.templates import (
    BUILTIN_TEMPLATES,
    TemplateApplicator,
    WorkcellTemplate,
)

if TYPE_CHECKING:
    from cyntra.core.scheduler.routing import KernelConfig

logger = structlog.get_logger()


class WorkcellManager:
    """
    Manages isolated git worktree execution environments.
    """

    def __init__(self, config: KernelConfig, repo_root: Path) -> None:
        self.config = config
        self.repo_root = repo_root
        self.workcells_dir = config.workcells_dir
        self.archives_dir = config.archives_dir
        self.template_applicator = TemplateApplicator(repo_root)

        # Ensure directories exist
        self.workcells_dir.mkdir(parents=True, exist_ok=True)
        self.archives_dir.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        issue_id: str,
        speculate_tag: str | None = None,
        template: str | WorkcellTemplate | None = None,
    ) -> Path:
        """
        Create an isolated workcell (git worktree) for a task.

        Args:
            issue_id: The issue ID this workcell is for.
            speculate_tag: Optional speculation tag for parallel runs.
            template: Optional template ID (string) or WorkcellTemplate object.
                     Built-in templates: "full", "kernel-dev", "fab-asset",
                     "fab-playtest", "app-desktop", "bench-evolution"

        Returns the path to the workcell directory.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        tag_slug = self._slugify_speculate_tag(speculate_tag)
        suffix = ""
        workcell_name = ""
        branch_name = ""
        workcell_path = self.workcells_dir

        for _ in range(6):
            extra_parts = [part for part in (tag_slug, suffix) if part]
            name_suffix = "-".join([str(issue_id), timestamp, *extra_parts])
            workcell_name = f"wc-{name_suffix}"
            branch_tail = "-".join([timestamp, *extra_parts])
            branch_name = f"wc/{issue_id}/{branch_tail}"
            workcell_path = self.workcells_dir / workcell_name

            if not workcell_path.exists() and not self._branch_exists(branch_name):
                break

            suffix = uuid.uuid4().hex[:6]
        else:
            raise RuntimeError("Failed to allocate unique workcell name")

        logger.info(
            "Creating workcell",
            workcell_id=workcell_name,
            issue_id=issue_id,
            speculate_tag=speculate_tag,
        )

        # Resolve template up front so we can apply sparse checkout before the
        # first checkout (prevents huge repos from exhausting disk space).
        resolved_template: WorkcellTemplate | None = None
        if template:
            if isinstance(template, str):
                # Allow repo-local templates to override built-ins so each
                # repository can tailor sparse checkout behavior safely.
                try:
                    resolved_template = self.template_applicator.load_template(template)
                except ValueError:
                    # Fallback to built-in templates if no repo-local override exists.
                    if template in BUILTIN_TEMPLATES:
                        resolved_template = BUILTIN_TEMPLATES[template]
                    else:
                        logger.warning(
                            "Template not found, using full checkout",
                            template=template,
                        )
            elif isinstance(template, WorkcellTemplate):
                resolved_template = template

        base_ref = self._resolve_base_ref()

        # Create isolated worktree from the configured integration branch/ref
        # (no checkout yet).
        result = subprocess.run(
            [
                "git",
                "worktree",
                "add",
                "--no-checkout",
                str(workcell_path),
                "-b",
                branch_name,
                base_ref,
            ],
            cwd=self.repo_root,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            self._cleanup_failed_worktree(workcell_path, branch_name)
            raise RuntimeError(f"Failed to create worktree: {result.stderr}")

        # Apply sparse checkout before checking out files.
        applied_sparse = False
        if resolved_template and resolved_template.sparse_checkout:
            try:
                self.template_applicator.apply_sparse_checkout(workcell_path, resolved_template)
                applied_sparse = True
            except Exception as exc:
                self._cleanup_failed_worktree(workcell_path, branch_name)
                raise RuntimeError(f"Failed to apply sparse checkout: {exc}") from exc

        # Checkout the new branch (now constrained by sparse checkout if enabled).
        checkout = subprocess.run(
            ["git", "checkout", "--force", branch_name],
            cwd=workcell_path,
            capture_output=True,
            text=True,
        )
        if checkout.returncode != 0:
            self._cleanup_failed_worktree(workcell_path, branch_name)
            raise RuntimeError(f"Failed to checkout worktree: {checkout.stderr}")

        # Remove .beads from workcell (kernel owns it)
        beads_path = workcell_path / ".beads"
        if beads_path.exists():
            shutil.rmtree(beads_path, ignore_errors=True)

        # Remove .cyntra from workcell (kernel owns it)
        cyntra_path = workcell_path / ".cyntra"
        if cyntra_path.exists():
            shutil.rmtree(cyntra_path, ignore_errors=True)

        # Remove .mise.toml from workcell to avoid mise trust prompts
        # Toolchains use system-installed mise shims which work without per-dir trust
        mise_toml_path = workcell_path / ".mise.toml"
        if mise_toml_path.exists():
            mise_toml_path.unlink()
            logger.debug("Removed .mise.toml from workcell to avoid trust prompts")

        # Create logs directory
        logs_path = workcell_path / "logs"
        logs_path.mkdir(parents=True, exist_ok=True)

        # Sync prompt genomes/frontier into the workcell so adapters can load them
        # even when prompts are uncommitted locally.
        self._sync_prompts(workcell_path)

        # Apply template if specified
        workcell_env: dict[str, str] = {}
        if resolved_template:
            try:
                workcell_env = self.template_applicator.apply_template(
                    workcell_path,
                    resolved_template,
                    skip_sparse_checkout=applied_sparse,
                )
            except Exception as e:
                logger.error(
                    "Template application failed, continuing with full checkout",
                    template=resolved_template.id,
                    error=str(e),
                )

        # Create isolation marker
        marker = {
            "id": workcell_name,
            "issue_id": issue_id,
            "created": timestamp,
            "parent_commit": self._get_base_head(base_ref),
            "base_ref": base_ref,
            "speculate_tag": speculate_tag,
            "branch_name": branch_name,
            "template": resolved_template.id if resolved_template else None,
        }
        (workcell_path / ".workcell").write_text(json.dumps(marker, indent=2))

        logger.info(
            "Workcell created",
            workcell_id=workcell_name,
            path=str(workcell_path),
            template=resolved_template.id if resolved_template else "full",
        )
        return workcell_path

    def cleanup(self, workcell_path: Path, keep_logs: bool = True) -> None:
        """
        Safely remove a workcell.

        Optionally archives logs before removal.
        Kills any orphaned PTY processes before removing the worktree.
        """
        workcell_name = workcell_path.name

        logger.info("Cleaning up workcell", workcell_id=workcell_name, keep_logs=keep_logs)

        # Kill orphaned PTY processes before removing worktree
        self._kill_orphaned_pty(workcell_path)

        # Archive logs if requested
        if keep_logs:
            self._archive_logs(workcell_path)

        # Get branch name from marker
        branch_name = self._get_branch_for_workcell(workcell_path)

        # Remove worktree
        result = subprocess.run(
            ["git", "worktree", "remove", "--force", str(workcell_path)],
            cwd=self.repo_root,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            logger.warning(
                "Failed to remove worktree",
                workcell_id=workcell_name,
                error=result.stderr,
            )

        # Delete branch (best effort)
        if branch_name:
            subprocess.run(
                ["git", "branch", "-D", branch_name],
                cwd=self.repo_root,
                capture_output=True,
            )

        logger.info("Workcell cleaned up", workcell_id=workcell_name)

    def list_active(self) -> list[Path]:
        """List all active workcells."""
        if not self.workcells_dir.exists():
            return []

        return [
            p for p in self.workcells_dir.iterdir() if p.is_dir() and (p / ".workcell").exists()
        ]

    def get_workcell_info(self, workcell_path: Path) -> dict | None:
        """Get metadata for a workcell."""
        marker_path = workcell_path / ".workcell"

        if not marker_path.exists():
            return None

        return json.loads(marker_path.read_text())

    def _resolve_base_ref(self) -> str:
        """
        Resolve the branch/ref used as the workcell integration baseline.

        Resolution order:
        1. `CYNTRA_INTEGRATION_BRANCH` environment override.
        2. Current branch in `repo_root` (if not detached).
        3. Existing local branch `main`, then `master`.
        4. `HEAD` fallback.
        """
        env_ref = (os.environ.get("CYNTRA_INTEGRATION_BRANCH") or "").strip()
        if env_ref:
            return env_ref

        current = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=self.repo_root,
            capture_output=True,
            text=True,
        )
        if current.returncode == 0:
            branch = current.stdout.strip()
            if branch and branch != "HEAD":
                return branch

        for candidate in ("main", "master"):
            exists = subprocess.run(
                ["git", "show-ref", "--verify", f"refs/heads/{candidate}"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
            )
            if exists.returncode == 0:
                return candidate

        return "HEAD"

    def _get_base_head(self, base_ref: str) -> str:
        """Get the current HEAD SHA for a resolved baseline ref."""
        result = subprocess.run(
            ["git", "rev-parse", base_ref],
            cwd=self.repo_root,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return "unknown"

        return result.stdout.strip()

    def _get_branch_for_workcell(self, workcell_path: Path) -> str | None:
        """Get the branch name for a workcell."""
        info = self.get_workcell_info(workcell_path)

        if not info:
            return None

        branch_name = info.get("branch_name")
        if isinstance(branch_name, str) and branch_name:
            return branch_name

        issue_id = info.get("issue_id")
        created = info.get("created")

        if issue_id and created:
            return f"wc/{issue_id}/{created}"

        return None

    def _slugify_speculate_tag(self, speculate_tag: str | None) -> str | None:
        if not speculate_tag:
            return None
        safe = re.sub(r"[^a-zA-Z0-9_-]+", "-", speculate_tag).strip("-").lower()
        return safe[:24] if safe else None

    def _branch_exists(self, branch_name: str) -> bool:
        result = subprocess.run(
            ["git", "show-ref", "--verify", f"refs/heads/{branch_name}"],
            cwd=self.repo_root,
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def _cleanup_failed_worktree(self, workcell_path: Path, branch_name: str) -> None:
        if workcell_path.exists():
            result = subprocess.run(
                ["git", "worktree", "remove", "--force", str(workcell_path)],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                logger.warning(
                    "Failed to remove partial worktree",
                    workcell_id=workcell_path.name,
                    error=result.stderr,
                )

        if branch_name and self._branch_exists(branch_name):
            result = subprocess.run(
                ["git", "branch", "-D", branch_name],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                logger.warning(
                    "Failed to delete partial worktree branch",
                    branch_name=branch_name,
                    error=result.stderr,
                )

    def _kill_orphaned_pty(self, workcell_path: Path) -> None:
        """
        Kill any orphaned PTY processes associated with this workcell.

        Reads the .workcell marker to find PID info stored by the PTY adapter.
        Falls back to scanning for a pty_pid file in the logs directory.
        Uses SIGTERM -> wait 5s -> SIGKILL escalation.
        """
        pid = None

        # Try reading PID from .workcell marker
        info = self.get_workcell_info(workcell_path)
        if info:
            pid = info.get("pty_pid")

        # Try reading PID from logs/pty_pid file (written by PTY adapter)
        if pid is None:
            pid_file = workcell_path / "logs" / "pty_pid"
            if pid_file.exists():
                try:
                    pid = int(pid_file.read_text().strip())
                except (ValueError, OSError):
                    pass

        if pid is None:
            return

        # Check if process is alive
        try:
            os.kill(pid, 0)
        except (OSError, ProcessLookupError):
            return  # Already dead

        logger.warning(
            "Killing orphaned PTY process",
            workcell_id=workcell_path.name,
            pid=pid,
        )

        # SIGTERM first
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            try:
                os.kill(pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                return

        # Wait up to 5 seconds for graceful termination
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
                time.sleep(0.2)
            except (OSError, ProcessLookupError):
                logger.info(
                    "Orphaned PTY process terminated gracefully",
                    workcell_id=workcell_path.name,
                    pid=pid,
                )
                return

        # Escalate to SIGKILL
        logger.warning(
            "Sending SIGKILL to orphaned PTY process",
            workcell_id=workcell_path.name,
            pid=pid,
        )
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                os.kill(pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass

    def _archive_logs(self, workcell_path: Path) -> None:
        """
        Archive workcell logs recursively.

        This preserves the full directory structure including nested directories
        like logs/fab/ for render artifacts and critic reports.
        """
        workcell_name = workcell_path.name
        logs_path = workcell_path / "logs"

        if not logs_path.exists():
            return

        archive_path = self.archives_dir / workcell_name
        archive_path.mkdir(parents=True, exist_ok=True)

        # Copy entire logs directory recursively (preserves fab/ subdirectories)
        archive_logs_path = archive_path / "logs"
        if archive_logs_path.exists():
            shutil.rmtree(archive_logs_path)
        shutil.copytree(logs_path, archive_logs_path, dirs_exist_ok=True)

        # Also copy core artifacts if they exist.
        for filename in [
            "proof.json",
            "manifest.json",
            "telemetry.jsonl",
            "rollout.json",
            "strategy_profile.json",
            "prompt.md",
            ".workcell",
            "claude-pty.log",
        ]:
            src = workcell_path / filename
            if src.exists():
                shutil.copy(src, archive_path)

        # Copy any render output directories that may exist at workcell root
        for dirname in ["renders", "output", "assets"]:
            src_dir = workcell_path / dirname
            if src_dir.exists() and src_dir.is_dir():
                dst_dir = archive_path / dirname
                if dst_dir.exists():
                    shutil.rmtree(dst_dir)
                shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)

        logger.info(
            "Logs archived",
            workcell_id=workcell_name,
            archive=str(archive_path),
            preserved_structure=True,
        )

    def suggest_template(
        self,
        domain: str | None = None,
        tags: list[str] | None = None,
    ) -> str:
        """
        Suggest a template based on task domain and tags.

        Args:
            domain: Task domain (code, fab, data, creative)
            tags: Task tags

        Returns:
            Suggested template ID
        """
        tags = tags or []
        tags_lower = [t.lower() for t in tags]

        # Docs-only and documentation tasks
        if any(t in tags_lower for t in ["docs", "documentation"]):
            return "docs"

        # Check for specific patterns in tags
        if any(t in tags_lower for t in ["playtest", "nitrogen", "qa"]):
            return "fab-playtest"

        if any(t in tags_lower for t in ["bench", "evolution", "scenario"]):
            return "bench-evolution"

        if any(t in tags_lower for t in ["desktop", "tauri", "react", "frontend"]):
            return "app-desktop"

        if any(t in tags_lower for t in ["baia", "backbay", "imperium"]):
            return "app-backbay"

        if any(t in tags_lower for t in ["fab", "asset", "blender", "godot", "3d"]):
            return "fab-asset"

        # Check domain
        if domain and domain.startswith("fab"):
            return "fab-asset"

        if domain == "code":
            # Check if it's kernel-related
            if any(t in tags_lower for t in ["kernel", "cyntra", "workcell", "adapter"]):
                return "kernel-dev"

        # Default to a code-focused slice (avoids huge tracked binary assets).
        return "code"

    def _sync_prompts(self, workcell_path: Path) -> None:
        """
        Copy repo-level prompts into the workcell.

        Workcells are git worktrees and do not include untracked files from the
        main working tree. Copying prompts ensures prompt genomes and frontier
        files are available for prompt composition during execution.
        """
        src_root = self.repo_root / "prompts"
        if not src_root.is_dir():
            return

        dst_root = workcell_path / "prompts"
        dst_root.mkdir(parents=True, exist_ok=True)

        for src in src_root.rglob("*"):
            if not src.is_file():
                continue
            if src.name in {".DS_Store"}:
                continue
            try:
                rel = src.relative_to(src_root)
            except ValueError:
                continue
            dst = dst_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(src, dst)
            except OSError:
                # Best-effort; prompts are optional.
                continue
