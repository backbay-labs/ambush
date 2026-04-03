"""
MetasploitParser - Parse msfconsole output into structured data.

Handles the tabular output formats from ``search``, ``sessions -l``,
and exploit result messages.
"""

from __future__ import annotations

import re

from hellcat.offensive.tools.metasploit.models import MsfSession


class MetasploitParser:
    """Static methods that convert raw msfconsole text into dicts/dataclasses."""

    # Regex for "session N opened (addr -> addr)" messages
    _SESSION_OPENED_RE = re.compile(
        r"session\s+(\d+)\s+opened\s+\(([^)]*)\)",
        re.IGNORECASE,
    )

    @staticmethod
    def parse_search(output: str) -> list[dict[str, str]]:
        """Parse ``msf6> search ...`` tabular output.

        Expected format::

            Matching Modules
            ================

               #  Name                           Disclosure Date  Rank       Check  Description
               -  ----                           ---------------  ----       -----  -----------
               0  exploit/windows/smb/ms17_010   2017-03-14       great      Yes    MS17-010 ...

        Returns a list of dicts with keys: name, disclosure_date, rank, check,
        description.
        """
        results: list[dict[str, str]] = []
        lines = output.splitlines()

        # Find the header row to determine column positions
        header_idx: int | None = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#") and "Name" in stripped:
                header_idx = i
                break

        if header_idx is None:
            return results

        # Skip the separator line (dashes)
        data_start = header_idx + 2

        for line in lines[data_start:]:
            stripped = line.strip()
            if not stripped or stripped.startswith("Interact"):
                break

            # Split on 2+ whitespace to handle columns
            parts = re.split(r"\s{2,}", stripped)
            if len(parts) < 4:
                continue

            # parts[0] is the index number
            entry: dict[str, str] = {"name": parts[1]}
            if len(parts) >= 3:
                entry["disclosure_date"] = parts[2]
            if len(parts) >= 4:
                entry["rank"] = parts[3]
            if len(parts) >= 5:
                entry["check"] = parts[4]
            if len(parts) >= 6:
                entry["description"] = parts[5]

            results.append(entry)

        return results

    @staticmethod
    def parse_sessions(output: str) -> dict[str, MsfSession]:
        """Parse ``sessions -l`` output into MsfSession objects.

        Expected format::

            Active sessions
            ===============

              Id  Name  Type          Info          Connection
              --  ----  ----          ----          ----------
              1         meterpreter   user@target   10.0.0.1:4444 -> 10.0.0.2:49876

        Returns a dict mapping session-id string to MsfSession.
        """
        sessions: dict[str, MsfSession] = {}
        lines = output.splitlines()

        header_idx: int | None = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("Id") and "Type" in stripped:
                header_idx = i
                break

        if header_idx is None:
            return sessions

        data_start = header_idx + 2

        for line in lines[data_start:]:
            stripped = line.strip()
            if not stripped:
                break

            parts = re.split(r"\s{2,}", stripped)
            if len(parts) < 3:
                continue

            sid = parts[0].strip()
            # parts[1] might be Name (often empty), parts[2] is Type
            # Detect whether Name column is populated
            if len(parts) >= 5:
                sess_type = parts[2]
                info = parts[3]
                connection = parts[4]
            elif len(parts) >= 4:
                sess_type = parts[1]
                info = parts[2]
                connection = parts[3]
            else:
                sess_type = parts[1]
                info = parts[2] if len(parts) > 2 else ""
                connection = ""

            target_host = ""
            target_port = ""
            if "->" in connection:
                remote = connection.split("->")[-1].strip()
                if ":" in remote:
                    target_host, target_port = remote.rsplit(":", 1)

            sessions[sid] = MsfSession(
                session_id=sid,
                session_type=sess_type,
                target_host=target_host,
                target_port=target_port,
                info=info,
            )

        return sessions

    @classmethod
    def parse_exploit_result(cls, output: str) -> dict[str, object]:
        """Detect whether an exploit succeeded from its output.

        Looks for "session N opened" patterns and common success/failure
        indicators.

        Returns a dict with keys:
        - success: bool
        - sessions_opened: list[str]  (session IDs)
        - raw: str  (the full output)
        """
        sessions_opened: list[str] = []
        for match in cls._SESSION_OPENED_RE.finditer(output):
            sessions_opened.append(match.group(1))

        success = len(sessions_opened) > 0

        # Also check for common success strings if no session detected
        if not success:
            lower = output.lower()
            if "command shell session" in lower or "meterpreter session" in lower:
                success = True

        return {
            "success": success,
            "sessions_opened": sessions_opened,
            "raw": output,
        }
