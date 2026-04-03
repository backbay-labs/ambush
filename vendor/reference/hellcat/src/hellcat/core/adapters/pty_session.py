"""
PTY session manager for interactive Claude Code execution.

Manages a persistent PTY-based Claude Code process, enabling interactive
sessions with Agent Teams support.  Uses ``pexpect`` to drive stdin/stdout
and detects turn boundaries via prompt-pattern matching + output quiescence.

All public methods are async; blocking pexpect calls are dispatched to a
thread-pool executor so the event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import signal
import time
from pathlib import Path
from typing import IO, Any

import structlog

from hellcat.core.adapters.pty_output_parser import PTYOutputParser, TurnResult

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# ANSI escape code stripping
# ---------------------------------------------------------------------------

# Matches all common ANSI escape sequences:
#  - CSI sequences  (ESC [ ... final byte)
#  - OSC sequences  (ESC ] ... ST)
#  - Single-char escapes (ESC followed by one char in @-~)
#  - Common control characters emitted by terminals (BEL, BS, etc.)
_ANSI_ESCAPE_RE = re.compile(
    r"""
    \x1b              # ESC character
    (?:
        \[            # CSI - Control Sequence Introducer
        [0-9;?]*      # parameter bytes
        [A-Za-z~]     # final byte
    |
        \]            # OSC - Operating System Command
        .*?           # payload
        (?:\x07|\x1b\\)  # terminated by BEL or ST
    |
        [()][AB012]   # Character set selection
    |
        [@-Z\\-_]     # Two-character escape sequence (Fe)
    )
    |
    \r                # Carriage return (often paired with newline in PTY)
    |
    \x07              # BEL
    |
    \x08              # Backspace
    """,
    re.VERBOSE | re.DOTALL,
)

# Spinner / progress characters that pollute output
_SPINNER_RE = re.compile(r"[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏◐◓◑◒⣾⣽⣻⢿⡿⣟⣯⣷⠁⠂⠄⡀⢀⠠⠐⠈]+")

# Claude Code prompt patterns that indicate the agent is waiting for input.
#
# Split into two groups:
#  - _LAST_LINE_PROMPT_PATTERNS: Only checked against the very last non-empty
#    line to avoid false positives on markdown blockquotes ("> ").
#  - _TAIL_PROMPT_PATTERNS: Checked against the last 5 lines for descriptive
#    prompts that are unambiguous.
_LAST_LINE_PROMPT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^>\s*$"),
    re.compile(r"^\$\s*$"),
    re.compile(r"^claude>\s*$", re.IGNORECASE),
]

_TAIL_PROMPT_PATTERNS: list[re.Pattern[str]] = [
    # "What would you like to do?" style prompts
    re.compile(r"(?:What would you like|How can I help)", re.IGNORECASE),
]

# Default terminal dimensions for the PTY
_DEFAULT_COLS = 200
_DEFAULT_ROWS = 50

# Chunk size for writing large prompts to avoid PTY buffer overflow
_WRITE_CHUNK_SIZE = 512


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes, spinners, and control characters from *text*."""
    cleaned = _ANSI_ESCAPE_RE.sub("", text)
    cleaned = _SPINNER_RE.sub("", cleaned)
    # Collapse runs of blank lines to at most two
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned


class PTYSession:
    """
    Manages an interactive Claude Code PTY session.

    Typical usage::

        async with PTYSession(executable="claude", cwd=workcell, ...) as session:
            result = await session.send_prompt("Implement feature X ...")
            # result is a TurnResult
    """

    def __init__(
        self,
        executable: str = "claude",
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        model: str = "opus",
        timeout: int = 3600,
        log_path: Path | None = None,
        quiescence_seconds: float = 10.0,
        max_turn_seconds: int = 1800,
        skip_permissions: bool = True,
    ) -> None:
        self.executable = executable
        self.cwd = cwd or Path.cwd()
        self.env = env or {}
        self.model = model
        self.timeout = timeout
        self.log_path = log_path
        self.quiescence_seconds = quiescence_seconds
        # Cap per-turn duration to overall session timeout
        self.max_turn_seconds = min(max_turn_seconds, timeout)
        self.skip_permissions = skip_permissions

        # Internal state
        self._child: Any | None = None  # pexpect.spawn instance
        self._log_file: IO[str] | None = None
        self._parser = PTYOutputParser()
        self._started = False
        self._turn_count = 0

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> PTYSession:
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.shutdown()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Spawn ``claude`` in interactive mode with teams enabled."""
        if self._started:
            return

        import pexpect

        # Build the command arguments (no --print flag!)
        args = ["--model", self.model]
        if self.skip_permissions:
            args.append("--dangerously-skip-permissions")

        # Build environment
        child_env = os.environ.copy()
        child_env.update(self.env)

        # Open raw log file if requested
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = open(self.log_path, "w", encoding="utf-8", errors="replace")  # noqa: SIM115

        logger.info(
            "Starting PTY session",
            executable=self.executable,
            model=self.model,
            cwd=str(self.cwd),
        )

        loop = asyncio.get_running_loop()

        def _spawn() -> Any:
            child = pexpect.spawn(
                self.executable,
                args=args,
                cwd=str(self.cwd),
                env=child_env,
                encoding="utf-8",
                timeout=self.timeout,
                dimensions=(_DEFAULT_ROWS, _DEFAULT_COLS),
                codec_errors="replace",
                # Isolate the child in its own session/process group so that
                # os.killpg during shutdown cannot accidentally kill the kernel.
                preexec_fn=os.setsid,
            )
            if self._log_file:
                child.logfile_read = self._log_file
            return child

        self._child = await loop.run_in_executor(None, _spawn)
        self._started = True

        logger.info(
            "PTY session started",
            pid=self._child.pid if self._child else None,
        )

    async def send_prompt(self, prompt: str) -> TurnResult:
        """
        Send a prompt and wait for Claude to complete its turn.

        Large prompts are chunked to avoid PTY buffer overflow.

        Returns:
            Parsed TurnResult with file changes and status.
        """
        if not self._started or self._child is None:
            raise RuntimeError("PTY session not started; call start() first")

        self._turn_count += 1
        start_time = time.monotonic()

        loop = asyncio.get_running_loop()

        # Write prompt in chunks to avoid buffer overflow
        def _write_prompt() -> None:
            assert self._child is not None
            for i in range(0, len(prompt), _WRITE_CHUNK_SIZE):
                chunk = prompt[i : i + _WRITE_CHUNK_SIZE]
                self._child.send(chunk)
                # Small pause between chunks to let the terminal process
                time.sleep(0.01)
            # Send newline to submit
            self._child.sendline("")

        await loop.run_in_executor(None, _write_prompt)

        logger.debug(
            "Prompt sent to PTY",
            turn=self._turn_count,
            prompt_len=len(prompt),
        )

        # Wait for completion
        result = await self.wait_for_completion()

        duration_ms = int((time.monotonic() - start_time) * 1000)
        result.duration_ms = duration_ms

        return result

    async def wait_for_completion(self) -> TurnResult:
        """
        Wait for Claude to finish its current turn.

        Uses multi-signal detection:
        1. Prompt pattern matching (Claude is waiting for input)
        2. Output quiescence (no new output for N seconds)
        3. EOF / process exit

        Returns:
            Parsed TurnResult with extracted file changes and status.
        """
        if not self._started or self._child is None:
            raise RuntimeError("PTY session not started")

        import pexpect

        loop = asyncio.get_running_loop()
        start_time = time.monotonic()

        def _read_until_turn_complete() -> str:
            """Blocking read loop dispatched to executor.

            Only exits on:
            1. Prompt pattern detected (turn complete)
            2. EOF (process exited)
            3. Hard timeout (max_turn_seconds exceeded)

            Quiescence alone is NOT enough — Claude may be running a long
            silent tool (e.g. Bash build, test suite). Breaking early would
            kill the PTY and lose in-flight work.
            """
            assert self._child is not None
            buffer = ""
            last_output_time = time.monotonic()

            while True:
                elapsed = time.monotonic() - start_time
                if elapsed > self.max_turn_seconds:
                    logger.warning(
                        "PTY turn exceeded max duration",
                        elapsed_s=int(elapsed),
                        max_s=self.max_turn_seconds,
                    )
                    break

                try:
                    # Read with a short timeout to check for prompt patterns
                    chunk = self._child.read_nonblocking(
                        size=4096,
                        timeout=min(self.quiescence_seconds, 2.0),
                    )
                    if chunk:
                        buffer += chunk
                        last_output_time = time.monotonic()
                except pexpect.TIMEOUT:
                    # Check if Claude is waiting for input (prompt detected)
                    idle_seconds = time.monotonic() - last_output_time
                    if buffer.strip() and idle_seconds >= self.quiescence_seconds:
                        clean = strip_ansi(buffer)
                        if self._detect_turn_boundary(clean):
                            logger.debug("Turn boundary detected via prompt pattern")
                            break
                        # No prompt pattern — log but keep waiting for
                        # prompt/EOF/timeout rather than breaking early.
                        logger.debug(
                            "Quiescent but no prompt detected, continuing",
                            idle_s=round(idle_seconds, 1),
                        )
                    continue
                except pexpect.EOF:
                    logger.info("PTY process exited (EOF)")
                    break

            return buffer

        raw_output = await loop.run_in_executor(None, _read_until_turn_complete)

        duration_ms = int((time.monotonic() - start_time) * 1000)

        clean_output = strip_ansi(raw_output)
        result = self._parser.parse_turn(
            raw=raw_output,
            clean=clean_output,
            duration_ms=duration_ms,
        )

        # Override status to timeout if we hit the max
        elapsed = time.monotonic() - start_time
        if elapsed >= self.max_turn_seconds:
            result.status = "timeout"
            result.error = f"Turn exceeded max duration of {self.max_turn_seconds}s"

        # Check exit status when the process has exited (EOF).  A non-zero
        # exit or death-by-signal indicates a CLI-level failure (auth error,
        # crash, OOM kill, etc.) that the regex-based _ERROR_PATTERNS may miss.
        elif not self._child.isalive():
            exit_code = self._child.exitstatus
            signal_code = self._child.signalstatus
            if signal_code is not None:
                result.status = "error"
                result.error = (
                    result.error or f"Process killed by signal {signal_code}"
                )
            elif exit_code is not None and exit_code != 0:
                result.status = "error"
                result.error = (
                    result.error or f"Process exited with code {exit_code}"
                )

        logger.info(
            "PTY turn completed",
            turn=self._turn_count,
            status=result.status,
            duration_ms=duration_ms,
            files_modified=len(result.files_modified),
            tool_calls=len(result.tool_calls),
        )

        return result

    async def shutdown(self, timeout: int = 30) -> None:
        """
        Gracefully shut down the session.

        Sends ``/exit``, waits for graceful termination, escalates to
        SIGTERM then SIGKILL if needed.
        """
        if not self._started or self._child is None:
            return

        import pexpect

        loop = asyncio.get_running_loop()
        pid = self._child.pid

        logger.info("Shutting down PTY session", pid=pid)

        def _graceful_shutdown() -> None:
            assert self._child is not None
            try:
                if self._child.isalive():
                    # Try sending /exit command
                    try:
                        self._child.sendline("/exit")
                        self._child.expect(pexpect.EOF, timeout=min(timeout, 10))
                    except (pexpect.TIMEOUT, pexpect.EOF, OSError):
                        pass

                if self._child.isalive():
                    # Escalate to SIGTERM
                    logger.debug("Sending SIGTERM to PTY process", pid=pid)
                    self._child.kill(signal.SIGTERM)
                    with contextlib.suppress(pexpect.TIMEOUT, pexpect.EOF, OSError):
                        self._child.expect(pexpect.EOF, timeout=5)

                if self._child.isalive():
                    # Final escalation: SIGKILL the process group to avoid zombies
                    logger.warning("Sending SIGKILL to PTY process group", pid=pid)
                    try:
                        pgid = os.getpgid(pid)
                        os.killpg(pgid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError, OSError):
                        # Fallback to direct kill
                        self._child.kill(signal.SIGKILL)
                    with contextlib.suppress(pexpect.TIMEOUT, pexpect.EOF, OSError):
                        self._child.expect(pexpect.EOF, timeout=3)

                self._child.close(force=True)
            except Exception:
                logger.debug("Error during PTY shutdown", exc_info=True)

        await loop.run_in_executor(None, _graceful_shutdown)

        # Close log file
        if self._log_file:
            with contextlib.suppress(Exception):
                self._log_file.close()
            self._log_file = None

        self._started = False
        self._child = None
        logger.info("PTY session shut down", pid=pid)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _detect_turn_boundary(self, text: str) -> bool:
        """
        Detect when Claude has finished its turn and is waiting for input.

        Simple prompt characters (``>``, ``$``) are only checked on the very
        last non-empty line to avoid false positives on markdown blockquotes.
        Descriptive prompts (``What would you like...``) are checked against
        the last 5 lines.
        """
        lines = text.rstrip().split("\n")

        # Check simple prompt patterns against the last non-empty line only
        last_line = ""
        for line in reversed(lines):
            stripped = line.strip()
            if stripped:
                last_line = stripped
                break

        for pattern in _LAST_LINE_PROMPT_PATTERNS:
            if pattern.match(last_line):
                return True

        # Check descriptive patterns against the tail (last 5 lines)
        tail = "\n".join(lines[-5:]) if len(lines) >= 5 else text
        return any(pattern.search(tail) for pattern in _TAIL_PROMPT_PATTERNS)

    @property
    def is_alive(self) -> bool:
        """Return True if the underlying PTY process is still running."""
        return bool(self._child and self._child.isalive())

    @property
    def pid(self) -> int | None:
        """Return the PID of the PTY process, or None if not running."""
        if self._child:
            return self._child.pid
        return None

    @property
    def turn_count(self) -> int:
        """Number of prompts sent during this session."""
        return self._turn_count
