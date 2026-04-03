"""CloudFox CLI client for AWS/GCP cloud offensive analysis."""
from __future__ import annotations

import shutil
import subprocess
from typing import Any

import structlog

from hellcat.offensive.tools.cloudfox.parser import CloudFoxParser

logger = structlog.get_logger()


class CloudFoxClient:
    """Wrapper around the CloudFox CLI for cloud enumeration."""

    def __init__(self, binary: str = "cloudfox") -> None:
        self._binary = binary

    def is_available(self) -> bool:
        """Check if the cloudfox binary is on PATH."""
        return shutil.which(self._binary) is not None

    def run_inventory(
        self, profile: str = "", timeout: int = 120
    ) -> list[dict[str, Any]]:
        """Run CloudFox inventory enumeration."""
        cmd = [self._binary, "aws", "inventory"]
        if profile:
            cmd.extend(["--profile", profile])
        cmd.extend(["--output-format", "json"])

        output = self._run(cmd, timeout=timeout)
        if output is None:
            return []
        return CloudFoxParser.parse(output)

    def run_permissions(
        self, profile: str = "", timeout: int = 120
    ) -> list[dict[str, Any]]:
        """Run CloudFox permissions analysis."""
        cmd = [self._binary, "aws", "permissions"]
        if profile:
            cmd.extend(["--profile", profile])
        cmd.extend(["--output-format", "json"])

        output = self._run(cmd, timeout=timeout)
        if output is None:
            return []
        return CloudFoxParser.parse(output)

    def _run(self, cmd: list[str], timeout: int = 120) -> str | None:
        """Execute a CloudFox command and return stdout."""
        logger.info("cloudfox.executing", cmd=cmd[:4])
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if proc.returncode != 0:
                logger.warning(
                    "cloudfox.failed",
                    returncode=proc.returncode,
                    stderr=proc.stderr[:500],
                )
                return None
            return proc.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("cloudfox.error", error=str(exc))
            return None
