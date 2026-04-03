"""PMapper CLI client for AWS IAM privilege escalation analysis."""
from __future__ import annotations

import shutil
import subprocess
from typing import Any

import structlog

from hellcat.offensive.tools.pmapper.parser import PMapperParser

logger = structlog.get_logger()


class PMapperClient:
    """Wrapper around the PMapper CLI for IAM privesc analysis."""

    def __init__(self, binary: str = "pmapper") -> None:
        self._binary = binary

    def is_available(self) -> bool:
        """Check if the pmapper binary is on PATH."""
        return shutil.which(self._binary) is not None

    def query_privesc(
        self, principal: str = "", timeout: int = 120
    ) -> list[dict[str, Any]]:
        """Query PMapper for privilege escalation paths."""
        cmd = [self._binary, "query", "privesc"]
        if principal:
            cmd.extend(["--principal", principal])
        cmd.extend(["--format", "json"])

        output = self._run(cmd, timeout=timeout)
        if output is None:
            return []
        return PMapperParser.parse(output)

    def _run(self, cmd: list[str], timeout: int = 120) -> str | None:
        """Execute a PMapper command and return stdout."""
        logger.info("pmapper.executing", cmd=cmd[:4])
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if proc.returncode != 0:
                logger.warning(
                    "pmapper.failed",
                    returncode=proc.returncode,
                    stderr=proc.stderr[:500],
                )
                return None
            return proc.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("pmapper.error", error=str(exc))
            return None
