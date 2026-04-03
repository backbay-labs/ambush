"""
Output parser for interactive Claude Code PTY sessions.

Extracts structured data (file modifications, tool calls, team activity,
errors) from raw PTY output that has been ANSI-stripped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Patterns for detecting tool calls in Claude Code interactive output
# ---------------------------------------------------------------------------

# File write/edit patterns emitted by Claude Code
_FILE_WRITE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:Created|Wrote to|Updated)\s+(?:file\s+)?[`'\"]?([^\s`'\"]+)[`'\"]?"),
    re.compile(r"Write\s*\(\s*file_path:\s*[\"']([^\"']+)[\"']"),
    re.compile(r"Edit\s*\(\s*file_path:\s*[\"']([^\"']+)[\"']"),
]

# Specific known tool invocation patterns from Claude Code output
_KNOWN_TOOL_PATTERNS: dict[str, re.Pattern[str]] = {
    "Read": re.compile(r"Read\s*\(\s*file_path:\s*[\"']([^\"']+)[\"']"),
    "Write": re.compile(r"Write\s*\(\s*file_path:\s*[\"']([^\"']+)[\"']"),
    "Edit": re.compile(r"Edit\s*\(\s*file_path:\s*[\"']([^\"']+)[\"']"),
    "Bash": re.compile(r"Bash\s*\(\s*command:\s*[\"'](.+?)[\"']"),
    "Glob": re.compile(r"Glob\s*\(\s*pattern:\s*[\"']([^\"']+)[\"']"),
    "Grep": re.compile(r"Grep\s*\(\s*pattern:\s*[\"']([^\"']+)[\"']"),
    "Task": re.compile(r"Task\s*\(\s*(?:description|prompt):\s*[\"'](.+?)[\"']"),
}

# Team activity patterns
_TEAM_PATTERNS: dict[str, re.Pattern[str]] = {
    "teammate_spawned": re.compile(
        r"(?:Spawning|Creating|Starting)\s+teammate\s+[\"']?(\w[\w-]*)[\"']?"
    ),
    "message_sent": re.compile(
        r"(?:Sent|Sending)\s+message\s+to\s+[\"']?(\w[\w-]*)[\"']?"
    ),
    "message_received": re.compile(
        r"(?:Message|Received)\s+from\s+[\"']?(\w[\w-]*)[\"']?"
    ),
    "teammate_completed": re.compile(
        r"[Tt]eammate\s+[\"']?(\w[\w-]*)[\"']?\s+(?:completed|finished|done)"
    ),
}

# Error state patterns - scoped to Claude Code's own errors, not tool output.
# Avoid matching errors in test/lint output that Claude is actively fixing.
_ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:CRASH|FATAL|panic):\s*(.+)", re.MULTILINE),
    re.compile(r"Claude Code exited with error:\s*(.+)", re.MULTILINE),
    re.compile(r"Session terminated unexpectedly:\s*(.+)", re.MULTILINE),
    re.compile(r"Failed to connect to Claude API:\s*(.+)", re.MULTILINE),
]


@dataclass
class TurnResult:
    """Parsed result from one interactive turn."""

    raw_output: str
    clean_output: str  # ANSI stripped
    files_modified: list[str] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    status: str = "completed"  # "completed" | "waiting" | "error" | "timeout"
    error: str | None = None
    duration_ms: int = 0
    teams_activity: dict[str, Any] | None = None


class PTYOutputParser:
    """Parse interactive Claude Code output into structured data."""

    def parse_turn(self, raw: str, clean: str | None = None, duration_ms: int = 0) -> TurnResult:
        """
        Parse a single turn's output.

        Args:
            raw: Raw PTY output (may contain ANSI codes).
            clean: Pre-stripped clean text. If None, ``raw`` is used as-is.
            duration_ms: Wall-clock duration of the turn in milliseconds.

        Returns:
            TurnResult with extracted structured data.
        """
        text = clean if clean is not None else raw

        files_modified = self._extract_files_modified(text)
        tool_calls = self._extract_tool_calls(text)
        teams_activity = self._extract_teams_activity(text)
        error = self._detect_error(text)
        status = "error" if error else "completed"

        return TurnResult(
            raw_output=raw,
            clean_output=text,
            files_modified=files_modified,
            tool_calls=tool_calls,
            status=status,
            error=error,
            duration_ms=duration_ms,
            teams_activity=teams_activity if teams_activity else None,
        )

    # ----- extraction helpers ------------------------------------------------

    def _extract_files_modified(self, text: str) -> list[str]:
        """Detect file write/edit operations from output text."""
        seen: set[str] = set()
        files: list[str] = []
        for pattern in _FILE_WRITE_PATTERNS:
            for match in pattern.finditer(text):
                path = match.group(1)
                if path and path not in seen:
                    seen.add(path)
                    files.append(path)
        return files

    def _extract_tool_calls(self, text: str) -> list[dict[str, Any]]:
        """Extract structured tool call records from output text."""
        calls: list[dict[str, Any]] = []
        seen_indices: set[int] = set()

        for tool_name, pattern in _KNOWN_TOOL_PATTERNS.items():
            for match in pattern.finditer(text):
                idx = match.start()
                if idx in seen_indices:
                    continue
                seen_indices.add(idx)
                calls.append({
                    "tool": tool_name,
                    "arg": match.group(1),
                    "offset": idx,
                })

        # Sort by position in text to preserve ordering
        calls.sort(key=lambda c: c.get("offset", 0))
        # Remove offset from output
        for call in calls:
            call.pop("offset", None)
        return calls

    def _extract_teams_activity(self, text: str) -> dict[str, Any]:
        """Detect team-related activity (teammate spawning, messages)."""
        activity: dict[str, Any] = {}

        for event_type, pattern in _TEAM_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                activity[event_type] = matches

        return activity

    def _detect_error(self, text: str) -> str | None:
        """Detect error states in output. Returns first error found or None."""
        for pattern in _ERROR_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group(0).strip()
        return None
