"""
BrowserManager - Provisions isolated Playwright MCP server instances per StrikeCell.

Each cell gets its own ``--user-data-dir`` and MCP server instance to prevent
state leakage between concurrent browser sessions.

Usage::

    bm = BrowserManager(base_dir=Path("/tmp/hellcat-browsers"))
    ctx = bm.provision(cell_id="sc-recon-123", proxy="http://proxy:8080")
    # ... cell runs with ctx.mcp_server_name ...
    bm.cleanup(cell_id="sc-recon-123")
"""

from __future__ import annotations

import enum
import json
import os
import shutil
import signal
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class BrowserBackend(str, enum.Enum):
    """Supported browser backends for Playwright MCP."""

    CHROMIUM = "chromium"
    FIREFOX = "firefox"


@dataclass
class BrowserConfig:
    """Configuration for a StrikeCell's browser instance."""

    headless: bool = True
    backend: BrowserBackend = BrowserBackend.CHROMIUM
    viewport_width: int = 1280
    viewport_height: int = 720
    proxy: str | None = None
    extra_args: list[str] = field(default_factory=list)
    # Docker mode: use system Chromium instead of Playwright bundled
    use_system_chromium: bool = False
    system_chromium_path: str = "/usr/bin/chromium-browser"


@dataclass
class BrowserContext:
    """Runtime state for a provisioned browser instance."""

    cell_id: str
    mcp_server_name: str
    user_data_dir: Path
    pid: int | None = None
    config: BrowserConfig = field(default_factory=BrowserConfig)


class BrowserManager:
    """
    Manages isolated Playwright MCP browser instances for StrikeCells.

    Each cell gets its own user-data-dir and MCP server name to prevent
    state leakage. Each cell (playwright-<cell_id>) gets a unique browser
    profile.
    """

    def __init__(
        self,
        base_dir: Path,
        *,
        npx_command: str = "npx",
        mcp_package: str = "@playwright/mcp@latest",
    ) -> None:
        self.base_dir = base_dir
        self.npx_command = npx_command
        self.mcp_package = mcp_package
        self._contexts: dict[str, BrowserContext] = {}

        self.base_dir.mkdir(parents=True, exist_ok=True)

    def provision(
        self,
        cell_id: str,
        config: BrowserConfig | None = None,
    ) -> BrowserContext:
        """
        Provision an isolated Playwright MCP server for a StrikeCell.

        Creates a unique user-data-dir, assigns an MCP server name,
        and returns a BrowserContext with the connection details.
        The actual MCP server process is started by the Claude SDK
        based on the generated config — this method prepares the
        filesystem and metadata.
        """
        if cell_id in self._contexts:
            logger.warning(
                "browser.already_provisioned",
                cell_id=cell_id,
            )
            return self._contexts[cell_id]

        config = config or BrowserConfig()
        user_data_dir = self.base_dir / cell_id
        user_data_dir.mkdir(parents=True, exist_ok=True)

        # MCP server name: playwright-<cell_id>
        mcp_server_name = f"playwright-{cell_id}"

        ctx = BrowserContext(
            cell_id=cell_id,
            mcp_server_name=mcp_server_name,
            user_data_dir=user_data_dir,
            config=config,
        )

        self._contexts[cell_id] = ctx

        logger.info(
            "browser.provisioned",
            cell_id=cell_id,
            mcp_server_name=mcp_server_name,
            user_data_dir=str(user_data_dir),
            headless=config.headless,
            backend=config.backend.value,
        )

        return ctx

    def build_mcp_config(self, cell_id: str) -> dict[str, Any]:
        """
        Build the MCP server configuration dict for a provisioned cell.

        Returns a dict suitable for passing to the Claude SDK's
        ``mcpServers`` parameter.
        """
        ctx = self._contexts.get(cell_id)
        if ctx is None:
            raise ValueError(f"No browser provisioned for cell {cell_id}")

        args = [self.mcp_package, f"--user-data-dir={ctx.user_data_dir}"]

        if ctx.config.use_system_chromium:
            args.extend([
                "--executable-path", ctx.config.system_chromium_path,
                "--browser", "chromium",
            ])

        if ctx.config.proxy:
            args.append(f"--proxy-server={ctx.config.proxy}")

        for extra in ctx.config.extra_args:
            args.append(extra)

        env: dict[str, str] = {}
        if ctx.config.headless:
            env["PLAYWRIGHT_HEADLESS"] = "true"
        if ctx.config.use_system_chromium:
            env["PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD"] = "1"

        return {
            ctx.mcp_server_name: {
                "command": self.npx_command,
                "args": args,
                "env": env,
            }
        }

    def build_mcp_config_file(
        self,
        cell_id: str,
        output_path: Path | None = None,
    ) -> Path:
        """
        Write an MCP server config JSON file for a provisioned cell.

        Returns the path to the written config file.
        """
        config = self.build_mcp_config(cell_id)
        ctx = self._contexts[cell_id]

        if output_path is None:
            output_path = ctx.user_data_dir / "mcp_config.json"

        output_path.write_text(json.dumps(config, indent=2))

        logger.debug(
            "browser.mcp_config_written",
            cell_id=cell_id,
            path=str(output_path),
        )

        return output_path

    def get_docker_mounts(self, cell_id: str) -> list[str]:
        """
        Return Docker volume mount arguments for a browser's user data dir.

        Used by StrikeCellManager to mount the browser profile into the
        container when running in Docker mode.
        """
        ctx = self._contexts.get(cell_id)
        if ctx is None:
            return []

        return [
            "-v", f"{ctx.user_data_dir}:/browser-data:rw",
        ]

    def cleanup(self, cell_id: str) -> None:
        """
        Clean up a browser instance: kill process and remove user data dir.
        """
        ctx = self._contexts.pop(cell_id, None)
        if ctx is None:
            return

        # Kill browser process if we have a PID
        if ctx.pid is not None:
            try:
                os.kill(ctx.pid, signal.SIGTERM)
                logger.info(
                    "browser.process_terminated",
                    cell_id=cell_id,
                    pid=ctx.pid,
                )
            except (ProcessLookupError, PermissionError):
                pass

        # Remove user data directory
        if ctx.user_data_dir.exists():
            shutil.rmtree(ctx.user_data_dir, ignore_errors=True)
            logger.debug(
                "browser.data_removed",
                cell_id=cell_id,
                path=str(ctx.user_data_dir),
            )

        logger.info("browser.cleaned", cell_id=cell_id)

    def cleanup_all(self) -> None:
        """Clean up all provisioned browser instances."""
        cell_ids = list(self._contexts.keys())
        for cell_id in cell_ids:
            self.cleanup(cell_id)

    def get_context(self, cell_id: str) -> BrowserContext | None:
        """Look up a browser context by cell ID."""
        return self._contexts.get(cell_id)

    def active_count(self) -> int:
        """Number of currently provisioned browser instances."""
        return len(self._contexts)
