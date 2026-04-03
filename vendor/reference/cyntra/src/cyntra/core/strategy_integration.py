"""
Strategy Integration Layer.

Bridges strategy profiling with the kernel lifecycle:
- Extracts strategy profiles from agent responses
- Parses tool usage for heuristic extraction
- Stores profiles in TransitionDB for routing optimization
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from cyntra.core.adapters.telemetry import read_telemetry_events
from cyntra.cognition.dynamics.transition_db import TransitionDB
from cyntra.eval.strategy import extract_profile

if TYPE_CHECKING:
    from cyntra.core.adapters.base import PatchProof
    from cyntra.core.state.models import Issue

logger = structlog.get_logger()


class StrategyIntegration:
    """
    Integrates strategy profiling with kernel lifecycle.

    Extracts and stores strategy profiles after workcell completion
    to build a dataset for routing optimization.

    Usage:
        integration = StrategyIntegration(transition_db)

        # After dispatch completes
        integration.extract_and_store(
            workcell_id=workcell_id,
            workcell_path=workcell_path,
            issue=issue,
            proof=proof,
            toolchain=toolchain,
            outcome="success",
        )
    """

    def __init__(self, transition_db: TransitionDB):
        """
        Initialize strategy integration.

        Args:
            transition_db: TransitionDB instance for storing profiles
        """
        self.transition_db = transition_db

    def extract_and_store(
        self,
        workcell_id: str,
        workcell_path: Path,
        issue: Issue,
        proof: PatchProof | None,
        toolchain: str,
        outcome: str,
    ) -> str | None:
        """
        Extract strategy profile and store in TransitionDB.

        Args:
            workcell_id: Unique workcell identifier
            workcell_path: Path to workcell directory
            issue: Issue being worked on
            proof: Execution proof (may be None on failure)
            toolchain: Toolchain used for execution
            outcome: Execution outcome ("success", "failed", etc.)

        Returns:
            Profile ID if extraction succeeded, None otherwise
        """
        # Extract agent response text from telemetry
        response_text = self._get_response_text(workcell_path)

        # Extract commands for heuristic analysis
        commands = self._get_commands(workcell_path, proof)

        # Model info from proof or toolchain
        model = None
        if proof and proof.metadata:
            model = proof.metadata.get("model")

        # Extract profile using combined extraction
        profile = extract_profile(
            response_text=response_text,
            commands=commands,
            workcell_id=workcell_id,
            issue_id=str(issue.id),
            model=model,
            toolchain=toolchain,
        )

        if profile is None:
            logger.debug(
                "No strategy profile extracted",
                workcell_id=workcell_id,
                issue_id=issue.id,
                has_response=response_text is not None,
                has_commands=commands is not None,
            )
            return None

        # Best-effort: persist compact profile artifact alongside proof/manifest.
        self._write_profile_artifact(workcell_path, profile)

        # Store in TransitionDB
        try:
            profile_id = self.transition_db.insert_profile(
                profile=profile,
                outcome=outcome,
            )
            self.transition_db.conn.commit()

            logger.info(
                "Strategy profile stored",
                profile_id=profile_id,
                workcell_id=workcell_id,
                issue_id=issue.id,
                extraction_method=profile.extraction_method,
                dimension_count=len(profile.dimensions),
                outcome=outcome,
            )

            return profile_id

        except Exception as e:
            logger.warning(
                "Failed to store strategy profile",
                workcell_id=workcell_id,
                issue_id=issue.id,
                error=str(e),
            )
            return None

    def _get_response_text(self, workcell_path: Path) -> str | None:
        """
        Extract agent response text from telemetry.

        Looks for 'response_complete' events and concatenates content.
        """
        telemetry_path = workcell_path / "telemetry.jsonl"
        if not telemetry_path.exists():
            return None

        events = read_telemetry_events(telemetry_path)

        # Prefer response_complete (if present), otherwise fall back to streamed chunks.
        completed_parts: list[str] = []
        chunk_parts: list[str] = []

        for event in events:
            event_type = event.get("type")
            content = event.get("content", "")
            if not isinstance(content, str) or not content.strip():
                continue

            if event_type == "response_complete":
                completed_parts.append(content)
            elif event_type == "response_chunk":
                chunk_parts.append(content)

        parts = completed_parts or chunk_parts
        if not parts:
            return None

        # Concatenate all responses (agent may have multiple turns).
        return "\n".join(parts)

    def _write_profile_artifact(self, workcell_path: Path, profile: Any) -> None:
        """Write `strategy_profile.json` to the workcell root (best-effort)."""
        try:
            path = workcell_path / "strategy_profile.json"
            path.write_text(profile.to_json(indent=2))
        except Exception as exc:
            logger.debug(
                "Failed to write strategy profile artifact",
                workcell_id=workcell_path.name,
                error=str(exc),
            )

    def _get_commands(
        self,
        workcell_path: Path,
        proof: PatchProof | None,
    ) -> list[dict[str, Any]] | None:
        """
        Extract command list for heuristic analysis.

        Prefers proof.commands_executed if available,
        falls back to parsing telemetry.
        """
        # Try proof.commands_executed first
        if proof and proof.commands_executed:
            return proof.commands_executed

        # Fall back to telemetry parsing
        telemetry_path = workcell_path / "telemetry.jsonl"
        if not telemetry_path.exists():
            return None

        events = read_telemetry_events(telemetry_path)

        commands: list[dict[str, Any]] = []

        for event in events:
            event_type = event.get("type")

            if event_type == "tool_call":
                tool = event.get("tool", "")
                args = event.get("args", {})
                commands.append({
                    "tool": tool,
                    "content": args.get("content", "") or args.get("path", ""),
                    "new_string": args.get("new_string", ""),
                    "command_class": self._classify_tool(tool),
                })

            elif event_type == "bash_command":
                command_str = event.get("command", "")
                commands.append({
                    "tool": "Bash",
                    "content": command_str,
                    "command_class": "bash",
                })

            elif event_type == "file_read":
                commands.append({
                    "tool": "Read",
                    "content": event.get("path", ""),
                    "command_class": "read",
                })

            elif event_type == "file_write":
                commands.append({
                    "tool": "Write",
                    "content": event.get("path", ""),
                    "command_class": "write",
                })

        return commands if commands else None

    def _classify_tool(self, tool: str) -> str:
        """Classify a tool into a command class."""
        tool_lower = tool.lower()

        if "read" in tool_lower or "cat" in tool_lower:
            return "read"
        elif "write" in tool_lower or "edit" in tool_lower:
            return "write"
        elif "grep" in tool_lower or "search" in tool_lower or "glob" in tool_lower:
            return "search"
        elif "bash" in tool_lower:
            return "bash"
        else:
            return "other"

    def get_optimal_strategy(
        self,
        toolchain: str | None = None,
        outcome: str = "success",
        min_confidence: float = 0.5,
    ) -> dict[str, str]:
        """
        Get optimal strategy patterns based on historical data.

        Args:
            toolchain: Optional toolchain filter
            outcome: Outcome to filter by (default: "success")
            min_confidence: Minimum confidence threshold

        Returns:
            Dict mapping dimension IDs to recommended patterns
        """
        return self.transition_db.get_optimal_strategy_for(
            toolchain=toolchain,
            outcome=outcome,
            min_confidence=min_confidence,
        )

    def get_dimension_distribution(
        self,
        dimension_id: str,
        toolchain: str | None = None,
        outcome: str | None = None,
    ) -> dict[str, int]:
        """
        Get distribution of pattern values for a dimension.

        Args:
            dimension_id: Dimension to analyze
            toolchain: Optional toolchain filter
            outcome: Optional outcome filter

        Returns:
            Dict mapping pattern values to counts
        """
        return self.transition_db.get_dimension_distribution(
            dimension_id=dimension_id,
            toolchain=toolchain,
            outcome=outcome,
        )

    def profile_count(self) -> int:
        """Get total number of stored profiles."""
        return self.transition_db.profile_count()
