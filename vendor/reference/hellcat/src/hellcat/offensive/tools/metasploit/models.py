"""
Data models for Metasploit integration.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MsfSession:
    """A Metasploit session (meterpreter, shell, etc.)."""

    session_id: str
    session_type: str  # "meterpreter", "shell", "vnc", etc.
    target_host: str = ""
    target_port: str = ""
    via_exploit: str = ""
    info: str = ""


@dataclass
class MsfCommandResult:
    """Result of a single msfconsole command execution."""

    command: str
    output: str
    success: bool
    timed_out: bool = False
    error: str = ""
