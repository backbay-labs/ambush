"""
Canary Test Runner - Execute smoke tests that verify features work end-to-end.

Canary tests are the final gate before completion. They actually run the app
and verify the feature is accessible and functional from a user perspective.

Uses agent-browser (https://github.com/vercel-labs/agent-browser) for headless
browser automation with AI-friendly snapshot+ref workflow.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog
import yaml

if TYPE_CHECKING:
    pass

logger = structlog.get_logger()


def _check_agent_browser_installed() -> bool:
    """Check if agent-browser CLI is installed."""
    return shutil.which("agent-browser") is not None


def _run_agent_browser(
    *args: str,
    json_output: bool = True,
    timeout: int = 30,
) -> dict[str, Any] | str:
    """
    Run an agent-browser command and return the result.

    Args:
        *args: Command arguments (e.g., "open", "https://example.com")
        json_output: If True, parse output as JSON
        timeout: Command timeout in seconds

    Returns:
        Parsed JSON dict if json_output=True, else raw stdout string
    """
    cmd = ["agent-browser"]
    if json_output:
        cmd.append("--json")
    cmd.extend(args)

    logger.debug("Running agent-browser", command=" ".join(cmd))

    result = subprocess.run(
        cmd,
        capture_output=True,
        timeout=timeout,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"agent-browser failed: {result.stderr or result.stdout}"
        )

    if json_output:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            # Some commands don't return JSON even with --json flag
            return {"success": True, "raw_output": result.stdout}

    return result.stdout


@dataclass
class CanaryStepResult:
    """Result of a single canary test step."""

    name: str
    action: str
    passed: bool
    duration_ms: int
    error: str | None = None
    screenshot_path: str | None = None


@dataclass
class CanaryResult:
    """Result of running a canary test."""

    name: str
    passed: bool
    duration_ms: int
    steps: list[CanaryStepResult] = field(default_factory=list)
    error: str | None = None
    screenshots: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "duration_ms": self.duration_ms,
            "steps": [
                {
                    "name": s.name,
                    "action": s.action,
                    "passed": s.passed,
                    "duration_ms": s.duration_ms,
                    "error": s.error,
                }
                for s in self.steps
            ],
            "error": self.error,
            "screenshots": self.screenshots,
        }


@dataclass
class CanaryConfig:
    """Configuration for a canary test loaded from YAML."""

    name: str
    description: str
    trigger: dict[str, Any]
    setup: dict[str, Any]
    steps: list[dict[str, Any]]
    cleanup: dict[str, Any]
    timeout_ms: int = 120000
    retries: int = 1

    @classmethod
    def from_yaml(cls, path: Path) -> CanaryConfig:
        """Load canary config from YAML file."""
        content = yaml.safe_load(path.read_text())
        return cls(
            name=content["name"],
            description=content.get("description", ""),
            trigger=content.get("trigger", {}),
            setup=content.get("setup", {}),
            steps=content.get("steps", []),
            cleanup=content.get("cleanup", {}),
            timeout_ms=content.get("timeout_ms", 120000),
            retries=content.get("retries", 1),
        )


class CanaryRunner:
    """
    Runs canary smoke tests to verify features work end-to-end.

    Uses agent-browser for browser automation with the following workflow:
    1. Start the application (app setup)
    2. Open browser with agent-browser
    3. Take snapshots to get accessibility tree with refs
    4. Perform actions using refs (@e1, @e2, etc.)
    5. Capture screenshots as evidence
    6. Report pass/fail with details

    See: https://github.com/vercel-labs/agent-browser
    """

    def __init__(
        self,
        canaries_dir: Path,
        output_dir: Path | None = None,
        use_agent_browser: bool = True,
    ) -> None:
        self.canaries_dir = canaries_dir
        self.output_dir = output_dir or Path(".hellcat/canary-results")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.use_agent_browser = use_agent_browser and _check_agent_browser_installed()
        self._browser_open = False
        self._current_snapshot: dict[str, Any] | None = None

        if use_agent_browser and not self.use_agent_browser:
            logger.warning(
                "agent-browser not installed, falling back to basic checks. "
                "Install with: npm install -g agent-browser && agent-browser install"
            )

    def list_canaries(self) -> list[str]:
        """List all available canary tests."""
        if not self.canaries_dir.exists():
            return []
        return [p.stem for p in self.canaries_dir.glob("*.yaml")]

    def load_canary(self, name: str) -> CanaryConfig | None:
        """Load a canary config by name."""
        path = self.canaries_dir / f"{name}.yaml"
        if not path.exists():
            return None
        return CanaryConfig.from_yaml(path)

    def should_run(self, canary: CanaryConfig, changed_files: list[Path]) -> bool:
        """Determine if a canary should run based on trigger paths."""
        trigger = canary.trigger

        if trigger.get("always"):
            return True

        if trigger.get("manual_only"):
            return False

        trigger_paths = trigger.get("paths", [])
        if not trigger_paths:
            return False

        # Check if any changed file matches trigger patterns
        import fnmatch

        for changed in changed_files:
            for pattern in trigger_paths:
                if fnmatch.fnmatch(str(changed), pattern):
                    return True

        return False

    async def run_canary(self, name: str) -> CanaryResult:
        """Run a canary test by name."""
        started_at = time.time()

        canary = self.load_canary(name)
        if not canary:
            return CanaryResult(
                name=name,
                passed=False,
                duration_ms=0,
                error=f"Canary '{name}' not found",
            )

        logger.info("Running canary test", name=name)

        # Setup
        app_process = None
        try:
            app_process = await self._setup(canary)
        except Exception as e:
            duration_ms = int((time.time() - started_at) * 1000)
            return CanaryResult(
                name=name,
                passed=False,
                duration_ms=duration_ms,
                error=f"Setup failed: {e}",
            )

        # Run steps
        step_results: list[CanaryStepResult] = []
        screenshots: list[str] = []
        all_passed = True

        try:
            for step_config in canary.steps:
                step_result = await self._run_step(step_config, canary)
                step_results.append(step_result)

                if step_result.screenshot_path:
                    screenshots.append(step_result.screenshot_path)

                if not step_result.passed:
                    critical = step_config.get("critical", True)
                    if critical:
                        all_passed = False
                        break

        except Exception as e:
            logger.error("Canary step failed", name=name, error=str(e))
            all_passed = False

        finally:
            # Cleanup
            await self._cleanup(canary, app_process)

        duration_ms = int((time.time() - started_at) * 1000)

        result = CanaryResult(
            name=name,
            passed=all_passed,
            duration_ms=duration_ms,
            steps=step_results,
            screenshots=screenshots,
        )

        # Save result
        result_path = self.output_dir / f"{name}.json"
        result_path.write_text(json.dumps(result.to_dict(), indent=2))

        logger.info(
            "Canary test completed",
            name=name,
            passed=all_passed,
            duration_ms=duration_ms,
            steps_run=len(step_results),
        )

        return result

    async def _setup(self, canary: CanaryConfig) -> subprocess.Popen | None:
        """Run setup steps and start the app."""
        setup = canary.setup

        # Install dependencies
        if install_cmd := setup.get("install_command"):
            logger.info("Running install command", command=install_cmd)
            result = subprocess.run(install_cmd, shell=True, capture_output=True)
            if result.returncode != 0:
                raise RuntimeError(f"Install failed: {result.stderr.decode()}")

        # Start app
        app_process = None
        if start_cmd := setup.get("start_command"):
            logger.info("Starting app", command=start_cmd)
            env = {**dict(subprocess.os.environ), **(setup.get("env") or {})}
            app_process = subprocess.Popen(
                start_cmd,
                shell=True,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        # Wait for app to be ready
        if wait_url := setup.get("wait_for_url"):
            timeout_ms = setup.get("wait_timeout_ms", 30000)
            await self._wait_for_url(wait_url, timeout_ms)

        return app_process

    async def _wait_for_url(self, url: str, timeout_ms: int) -> None:
        """Wait for URL to become available."""
        import urllib.error
        import urllib.request

        deadline = time.time() + (timeout_ms / 1000)

        while time.time() < deadline:
            try:
                urllib.request.urlopen(url, timeout=2)
                logger.info("App is ready", url=url)
                return
            except urllib.error.URLError:
                await asyncio.sleep(1)

        raise TimeoutError(f"App not ready after {timeout_ms}ms")

    async def _run_step(
        self,
        step: dict[str, Any],
        canary: CanaryConfig,
    ) -> CanaryStepResult:
        """Run a single canary step using agent-browser if available."""
        started_at = time.time()
        action = step["action"]
        name = step.get("name", action)

        logger.debug("Running canary step", name=name, action=action)

        try:
            screenshot_path = None

            if self.use_agent_browser:
                screenshot_path = await self._run_step_agent_browser(step, canary)
            else:
                await self._run_step_fallback(step, canary)

            duration_ms = int((time.time() - started_at) * 1000)

            return CanaryStepResult(
                name=name,
                action=action,
                passed=True,
                duration_ms=duration_ms,
                screenshot_path=screenshot_path,
            )

        except Exception as e:
            duration_ms = int((time.time() - started_at) * 1000)
            return CanaryStepResult(
                name=name,
                action=action,
                passed=False,
                duration_ms=duration_ms,
                error=str(e),
            )

    async def _run_step_agent_browser(
        self,
        step: dict[str, Any],
        canary: CanaryConfig,
    ) -> str | None:
        """Run a step using agent-browser CLI."""
        action = step["action"]
        screenshot_path = None

        if action == "navigate":
            url = step["url"]
            if not self._browser_open:
                _run_agent_browser("open", url)
                self._browser_open = True
            else:
                _run_agent_browser("open", url)
            # Take initial snapshot after navigation
            self._current_snapshot = _run_agent_browser("snapshot", "-i", "-c")

        elif action == "snapshot":
            # Get accessibility tree with refs
            self._current_snapshot = _run_agent_browser(
                "snapshot",
                "-i",  # Interactive elements only
                "-c",  # Compact output
            )

        elif action == "assert_visible":
            # Use snapshot to check if element exists
            selector = step.get("selector")
            if selector:
                # Take a fresh snapshot and check for element
                snapshot = _run_agent_browser("snapshot", "-i", "-c", "-s", selector)
                if not snapshot.get("success"):
                    raise AssertionError(f"Element not found: {selector}")
            else:
                # Just take snapshot and verify we have elements
                snapshot = _run_agent_browser("snapshot", "-i", "-c")
                if not snapshot.get("data", {}).get("snapshot"):
                    raise AssertionError("No elements found in snapshot")

        elif action == "assert_no_console_errors":
            # Check browser console for errors
            result = _run_agent_browser("errors")
            errors = result.get("data", {}).get("errors", [])
            if errors:
                raise AssertionError(f"Console errors found: {errors}")

        elif action == "click":
            selector = step.get("selector")
            ref = step.get("ref")
            if ref:
                _run_agent_browser("click", ref)
            elif selector:
                _run_agent_browser("click", selector)
            else:
                raise ValueError("click requires 'selector' or 'ref'")

        elif action == "fill" or action == "type":
            selector = step.get("selector")
            ref = step.get("ref")
            text = step.get("text", step.get("value", ""))
            if ref:
                _run_agent_browser("fill", ref, text)
            elif selector:
                _run_agent_browser("fill", selector, text)
            else:
                raise ValueError("fill requires 'selector' or 'ref'")

        elif action == "wait":
            wait_ms = step.get("timeout_ms", step.get("ms", 1000))
            _run_agent_browser("wait", str(wait_ms), json_output=False)

        elif action == "wait_for_selector":
            selector = step.get("selector")
            if selector:
                _run_agent_browser("wait", selector)
            else:
                raise ValueError("wait_for_selector requires 'selector'")

        elif action == "screenshot":
            screenshot_name = step.get("name", f"canary-{int(time.time())}")
            screenshot_path = str(self.output_dir / f"{screenshot_name}.png")
            _run_agent_browser("screenshot", screenshot_path, json_output=False)

        elif action == "assert_text":
            selector = step.get("selector")
            expected = step.get("text", step.get("expected", ""))
            if selector:
                result = _run_agent_browser("get", "text", selector)
                actual = result.get("data", {}).get("text", "")
                if expected not in actual:
                    raise AssertionError(
                        f"Text mismatch: expected '{expected}' in '{actual}'"
                    )
            else:
                raise ValueError("assert_text requires 'selector'")

        elif action == "run_command":
            cmd = step["command"]
            result = subprocess.run(cmd, shell=True, capture_output=True)
            if result.returncode != 0:
                raise RuntimeError(f"Command failed: {result.stderr.decode()}")

        else:
            logger.warning(f"Unknown canary action: {action}")

        return screenshot_path

    async def _run_step_fallback(
        self,
        step: dict[str, Any],
        canary: CanaryConfig,
    ) -> None:
        """Run a step without agent-browser (basic HTTP checks only)."""
        action = step["action"]

        if action == "navigate":
            import urllib.request

            url = step["url"]
            urllib.request.urlopen(url, timeout=step.get("timeout_ms", 5000) / 1000)

        elif action == "run_command":
            cmd = step["command"]
            result = subprocess.run(cmd, shell=True, capture_output=True)
            if result.returncode != 0:
                raise RuntimeError(f"Command failed: {result.stderr.decode()}")

        elif action == "wait":
            await asyncio.sleep(step.get("timeout_ms", 1000) / 1000)

        elif action in ("assert_visible", "assert_no_console_errors", "click",
                        "fill", "type", "screenshot", "assert_text"):
            logger.warning(
                f"{action} requires agent-browser - skipping. "
                "Install with: npm install -g agent-browser"
            )

        else:
            logger.warning(f"Unknown canary action: {action}")

    async def _cleanup(
        self,
        canary: CanaryConfig,
        app_process: subprocess.Popen | None,
    ) -> None:
        """Run cleanup steps."""
        cleanup = canary.cleanup

        # Close agent-browser session
        if self.use_agent_browser and self._browser_open:
            try:
                _run_agent_browser("close", json_output=False, timeout=10)
            except Exception as e:
                logger.warning("Failed to close agent-browser", error=str(e))
            self._browser_open = False
            self._current_snapshot = None

        # Stop app process
        if app_process:
            app_process.terminate()
            try:
                app_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                app_process.kill()

        # Run stop command
        if stop_cmd := cleanup.get("stop_command"):
            subprocess.run(stop_cmd, shell=True, capture_output=True)

        # Run cleanup command
        if cleanup_cmd := cleanup.get("cleanup_command"):
            subprocess.run(cleanup_cmd, shell=True, capture_output=True)


async def run_canary_gate(
    canaries_dir: Path,
    name: str,
    output_dir: Path | None = None,
) -> CanaryResult:
    """Run a canary test as a gate."""
    runner = CanaryRunner(canaries_dir, output_dir)
    return await runner.run_canary(name)
