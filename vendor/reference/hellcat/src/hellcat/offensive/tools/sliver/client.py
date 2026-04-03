"""SliverClient - CLI wrapper for Sliver C2 framework.

Wraps the sliver-client binary for implant generation, session management,
and post-exploitation commands. Uses JSON output mode for easier parsing.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import structlog

from hellcat.offensive.tools.sliver.models import SliverBeacon, SliverImplant, SliverSession
from hellcat.offensive.tools.sliver.parser import SliverParser

logger = structlog.get_logger()

_TIMEOUTS: dict[str, int] = {
    "generate": 300,
    "command": 120,
    "default": 60,
}


class SliverClient:
    """Sliver C2 client wrapping the sliver-client CLI."""

    TIMEOUTS = _TIMEOUTS

    def __init__(self, binary: str = "sliver-client") -> None:
        self._binary = binary

    def is_available(self) -> bool:
        """Check if the sliver-client binary is on PATH."""
        return shutil.which(self._binary) is not None

    def list_sessions(self) -> list[SliverSession]:
        """List all active Sliver sessions."""
        result = self._run(["sessions", "-j"])
        if result is None:
            return []
        return SliverParser.parse_sessions(result)

    def list_beacons(self) -> list[SliverBeacon]:
        """List all active beacons."""
        result = self._run(["beacons", "-j"])
        if result is None:
            return []
        return SliverParser.parse_beacons(result)

    def list_implants(self) -> list[SliverImplant]:
        """List generated implants."""
        result = self._run(["implants", "-j"])
        if result is None:
            return []
        return SliverParser.parse_implants(result)

    def generate_implant(
        self,
        c2_url: str,
        os: str = "linux",
        arch: str = "amd64",
        implant_format: str = "exe",
        beacon: bool = False,
    ) -> SliverImplant | None:
        """Generate a new Sliver implant."""
        cmd = ["generate"]
        if beacon:
            cmd = ["generate", "beacon"]
        cmd.extend([
            "--mtls", c2_url, "--os", os, "--arch", arch, "-f", implant_format, "-j",
        ])

        result = self._run(cmd, timeout_type="generate")
        if result is None:
            return None

        try:
            data = json.loads(result)
            return SliverImplant(
                implant_id=data.get("id", ""),
                name=data.get("name", ""),
                os=data.get("os", os),
                arch=data.get("arch", arch),
                format=implant_format,
                c2_urls=[c2_url],
                is_beacon=beacon,
            )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("sliver.generate_parse_error", error=str(exc))
            return None

    def execute_command(
        self, session_id: str, command: str,
    ) -> str:
        """Execute a command in an active session."""
        result = self._run(
            ["use", session_id, "--", "execute", "-o", command],
            timeout_type="command",
        )
        return result or ""

    def _run(
        self, args: list[str], timeout_type: str = "default",
    ) -> str | None:
        """Run a sliver-client command and return stdout."""
        timeout = _TIMEOUTS.get(timeout_type, _TIMEOUTS["default"])
        cmd = [self._binary, *args]

        logger.debug("sliver.executing", cmd=cmd[:5])
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if proc.returncode != 0:
                logger.warning(
                    "sliver.nonzero_exit",
                    code=proc.returncode,
                    stderr=proc.stderr[:200],
                )
                return None
            return proc.stdout
        except FileNotFoundError:
            logger.warning("sliver.binary_not_found", binary=self._binary)
            return None
        except subprocess.TimeoutExpired:
            logger.warning("sliver.timeout", timeout=timeout)
            return None
