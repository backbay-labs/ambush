"""
MetasploitClient - Persistent msfconsole subprocess with thread-safe I/O.

Launches msfconsole as a long-running subprocess and sends commands via
stdin, reading output until a sentinel marker appears or a timeout fires.
All public methods are thread-safe via a reentrant lock.
"""

from __future__ import annotations

import select
import subprocess
import threading
import time
import uuid
from typing import IO

import structlog

from hellcat.offensive.tools.metasploit.models import MsfCommandResult, MsfSession

logger = structlog.get_logger()


# Timeout presets per command category (seconds).
_TIMEOUTS: dict[str, int] = {
    "exploit": 600,
    "bruteforce": 1800,
    "search": 60,
    "default": 120,
}


class MetasploitClient:
    """Persistent msfconsole subprocess wrapper.

    Usage::

        client = MetasploitClient()
        client.start()
        result = client.execute("search type:exploit name:eternalblue")
        client.stop()

    All public methods acquire an internal lock so concurrent callers
    from different threads are safe.
    """

    TIMEOUTS = _TIMEOUTS

    def __init__(self, msf_path: str = "msfconsole") -> None:
        self._msf_path = msf_path
        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._started = False

    def start(self) -> None:
        """Launch the msfconsole subprocess."""
        with self._lock:
            if self._started:
                return
            logger.info("metasploit.starting", path=self._msf_path)
            self._proc = subprocess.Popen(
                [self._msf_path, "-q", "-x", ""],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self._started = True
            # Read the initial banner/prompt
            self._read_until_prompt(self._proc.stdout, timeout=60)
            logger.info("metasploit.started", pid=self._proc.pid)

    def stop(self) -> None:
        """Gracefully shut down the msfconsole subprocess."""
        with self._lock:
            if not self._started or self._proc is None:
                return
            logger.info("metasploit.stopping", pid=self._proc.pid)
            try:
                self._proc.stdin.write("exit\n")  # type: ignore[union-attr]
                self._proc.stdin.flush()  # type: ignore[union-attr]
                self._proc.wait(timeout=15)
            except Exception:
                self._proc.kill()
            self._started = False
            self._proc = None
            logger.info("metasploit.stopped")

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._started and self._proc is not None and self._proc.poll() is None

    def execute(self, cmd: str, timeout_type: str = "default") -> MsfCommandResult:
        """Send a command to msfconsole and return the output.

        Thread-safe: acquires ``_lock`` for the entire read/write cycle.

        Args:
            cmd: Raw msfconsole command string.
            timeout_type: Key into ``TIMEOUTS`` dict.

        Returns:
            MsfCommandResult with the captured output.
        """
        timeout = _TIMEOUTS.get(timeout_type, _TIMEOUTS["default"])

        with self._lock:
            if not self._started or self._proc is None:
                return MsfCommandResult(
                    command=cmd, output="", success=False,
                    error="MetasploitClient not started",
                )
            return self._execute_locked(cmd, timeout)

    def search_module(self, query: str) -> list[dict[str, str]]:
        """Run ``search <query>`` and parse the results table."""
        from hellcat.offensive.tools.metasploit.parser import MetasploitParser

        result = self.execute(f"search {query}", timeout_type="search")
        if not result.success:
            return []
        return MetasploitParser.parse_search(result.output)

    def use_module(self, path: str) -> MsfCommandResult:
        """Select a module with ``use <path>``."""
        return self.execute(f"use {path}")

    def set_option(self, name: str, value: str) -> MsfCommandResult:
        """Set a module option."""
        return self.execute(f"set {name} {value}")

    def run_exploit(self) -> MsfCommandResult:
        """Run the currently selected exploit module."""
        return self.execute("exploit", timeout_type="exploit")

    def get_sessions(self) -> dict[str, MsfSession]:
        """Return all active sessions."""
        from hellcat.offensive.tools.metasploit.parser import MetasploitParser

        result = self.execute("sessions -l")
        if not result.success:
            return {}
        return MetasploitParser.parse_sessions(result.output)

    def session_command(self, sid: str, cmd: str) -> MsfCommandResult:
        """Send a command to a specific session."""
        return self.execute(f"sessions -C {cmd} -i {sid}")

    def _execute_locked(self, cmd: str, timeout: int) -> MsfCommandResult:
        """Execute a command with sentinel-based output detection.

        Must be called with ``_lock`` held.
        """
        assert self._proc is not None
        sentinel = f"__HELLCAT_SENTINEL_{uuid.uuid4().hex[:12]}__"

        try:
            # Write command followed by an echo of the sentinel
            self._proc.stdin.write(f"{cmd}\n")  # type: ignore[union-attr]
            self._proc.stdin.write(f"echo {sentinel}\n")  # type: ignore[union-attr]
            self._proc.stdin.flush()  # type: ignore[union-attr]
        except OSError as exc:
            return MsfCommandResult(
                command=cmd, output="", success=False,
                error=f"Failed to write to msfconsole: {exc}",
            )

        output = self._read_until_sentinel(
            self._proc.stdout, sentinel, timeout,  # type: ignore[arg-type]
        )

        timed_out = output is None
        captured = output or ""

        return MsfCommandResult(
            command=cmd,
            output=captured,
            success=not timed_out,
            timed_out=timed_out,
        )

    @staticmethod
    def _read_until_sentinel(
        stream: IO[str] | None,
        sentinel: str,
        timeout: int,
    ) -> str | None:
        """Read lines from *stream* until *sentinel* appears or timeout.

        Returns the accumulated output (excluding the sentinel line), or
        ``None`` on timeout.
        """
        if stream is None:
            return None

        lines: list[str] = []
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([stream], [], [], min(remaining, 1.0))
            if not ready:
                continue
            line = stream.readline()
            if not line:
                break
            if sentinel in line:
                return "".join(lines)
            lines.append(line)

        return None  # timed out

    @staticmethod
    def _read_until_prompt(
        stream: IO[str] | None,
        timeout: int = 30,
    ) -> str:
        """Read from *stream* until an ``msf`` prompt or timeout."""
        if stream is None:
            return ""

        lines: list[str] = []
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([stream], [], [], min(remaining, 1.0))
            if not ready:
                continue
            line = stream.readline()
            if not line:
                break
            lines.append(line)
            stripped = line.strip()
            if stripped.endswith(">") and "msf" in stripped:
                break

        return "".join(lines)
