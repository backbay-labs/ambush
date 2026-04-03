"""
Memory Lifecycle Hooks

Following claude-mem's 5 lifecycle hooks pattern, adapted for Cyntra workcells:

1. WorkcellStart (SessionStart) - Inject context, create session
2. ToolUse (PostToolUse) - Capture tool executions
3. GateResult - Capture quality gate outcomes (Cyntra extension)
4. Summary - Generate compressed summary
5. WorkcellEnd (SessionEnd) - Close session, trigger consolidation
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from cyntra.cognition.memory.database import MemoryDB
from cyntra.cognition.memory.observations import (
    Observation,
    ObservationType,
)

logger = structlog.get_logger()


def _generate_session_id(workcell_id: str) -> str:
    """Generate session ID from workcell ID."""
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    return f"sess_{workcell_id}_{timestamp}"


def _generate_summary_id(session_id: str) -> str:
    """Generate summary ID."""
    hash_val = hashlib.sha256(session_id.encode()).hexdigest()[:8]
    return f"sum_{hash_val}"


class MemoryHooks:
    """
    Lifecycle hooks for Cyntra memory system.

    Usage:
        hooks = MemoryHooks(db_path=".cyntra/memory/cyntra-mem.db")

        # At workcell start
        context = hooks.workcell_start(
            workcell_id="wc-42-20251220",
            issue_id="42",
            domain="code"
        )

        # After each tool use
        hooks.tool_use(
            tool_name="Edit",
            tool_args={"file": "main.py"},
            result="File edited successfully"
        )

        # After gate runs
        hooks.gate_result(
            gate_name="pytest",
            passed=True,
            details={"tests": 42, "passed": 42}
        )

        # At workcell end
        hooks.workcell_end(status="success")
    """

    def __init__(
        self,
        db_path: Path | str | None = None,
        max_context_observations: int = 50,
        max_context_tokens: int = 2000,
    ):
        self.db = MemoryDB(db_path)
        self.max_context_observations = max_context_observations
        self.max_context_tokens = max_context_tokens

        self._session_id: str | None = None
        self._workcell_id: str | None = None
        self._domain: str | None = None
        self._observations: list[Observation] = []

    # Hook 1: WorkcellStart (SessionStart)

    def workcell_start(
        self,
        workcell_id: str,
        issue_id: str | None = None,
        domain: str | None = None,
        job_type: str | None = None,
        toolchain: str | None = None,
    ) -> dict[str, Any]:
        """
        Called at workcell creation.

        Creates session and returns context for injection.

        Returns:
            Context dict with summaries and observation index
            for injection into agent prompt.
        """
        self._session_id = _generate_session_id(workcell_id)
        self._workcell_id = workcell_id
        self._domain = domain
        self._observations = []

        # Create session in database
        self.db.create_session(
            session_id=self._session_id,
            workcell_id=workcell_id,
            issue_id=issue_id,
            domain=domain,
            job_type=job_type,
            toolchain=toolchain,
        )

        logger.info(
            "Memory session started",
            session_id=self._session_id,
            workcell_id=workcell_id,
        )

        # Get context for injection (progressive disclosure Layer 1)
        context = self.db.get_context_for_injection(
            domain=domain,
            max_observations=self.max_context_observations,
            max_tokens=self.max_context_tokens,
        )

        return self._format_context_for_injection(context)

    def _format_context_for_injection(self, context: dict[str, Any]) -> dict[str, Any]:
        """Format context for prompt injection."""
        formatted = {
            "memory_available": True,
            "patterns": [],
            "warnings": [],
            "recent_learnings": [],
        }

        # Extract patterns from summaries
        for summary in context.get("summaries", []):
            patterns = summary.get("patterns")
            if patterns:
                try:
                    pattern_list = json.loads(patterns) if isinstance(patterns, str) else patterns
                    formatted["patterns"].extend(pattern_list[:3])
                except (json.JSONDecodeError, TypeError):
                    pass

            # Extract anti-patterns as warnings
            anti_patterns = summary.get("anti_patterns")
            if anti_patterns:
                try:
                    ap_list = (
                        json.loads(anti_patterns)
                        if isinstance(anti_patterns, str)
                        else anti_patterns
                    )
                    formatted["warnings"].extend(ap_list[:3])
                except (json.JSONDecodeError, TypeError):
                    pass

        # Add observation index for on-demand retrieval
        obs_index = context.get("observation_index", [])
        formatted["observation_index"] = [
            {
                "id": obs.get("id"),
                "type": obs.get("type"),
                "preview": obs.get("preview"),
                "importance": obs.get("importance"),
            }
            for obs in obs_index[:10]
        ]

        formatted["token_budget"] = context.get("token_budget", {})

        return formatted

    # Hook 2: ToolUse (PostToolUse)

    def tool_use(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        result: str | None = None,
        file_refs: list[str] | None = None,
    ) -> None:
        """
        Called after each tool execution.

        Captures tool use as observation. Only stores significant
        tool uses to avoid noise.
        """
        if not self._session_id:
            logger.warning("tool_use called without active session")
            return

        # Filter out low-value tool uses
        if tool_name in ("Read",) and not file_refs:
            return  # Skip pure reads without file context

        observation = Observation.from_tool_use(
            session_id=self._session_id,
            tool_name=tool_name,
            tool_args=tool_args or {},
            result=result or "",
            file_refs=file_refs,
        )

        self._observations.append(observation)

        # Store in database
        self.db.add_observation(
            observation_id=observation.id,
            session_id=self._session_id,
            obs_type=observation.obs_type.value,
            content=observation.content,
            concept=observation.concept.value if observation.concept else None,
            tool_name=observation.tool_name,
            tool_args=observation.tool_args,
            file_refs=observation.file_refs,
            outcome=observation.outcome,
            importance=observation.importance.value,
            token_count=observation.token_count,
        )

    # Hook 3: GateResult (Cyntra extension)

    def gate_result(
        self,
        gate_name: str,
        passed: bool,
        score: float | None = None,
        fail_codes: list[str] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Called after quality gate execution.

        Captures gate outcomes for pattern learning.
        """
        if not self._session_id:
            logger.warning("gate_result called without active session")
            return

        observation = Observation.from_gate_result(
            session_id=self._session_id,
            gate_name=gate_name,
            passed=passed,
            fail_codes=fail_codes,
            score=score,
        )

        self._observations.append(observation)

        self.db.add_observation(
            observation_id=observation.id,
            session_id=self._session_id,
            obs_type=observation.obs_type.value,
            content=observation.content,
            concept=observation.concept.value if observation.concept else None,
            outcome=observation.outcome,
            importance=observation.importance.value,
            token_count=observation.token_count,
        )

        logger.debug(
            "Gate result captured",
            gate=gate_name,
            passed=passed,
            observation_id=observation.id,
        )

    # Hook 4: Summary

    def generate_summary(self) -> dict[str, Any] | None:
        """
        Generate compressed summary of session.

        Called before workcell_end to create summary for future sessions.

        In production, this would use LLM to compress observations.
        For now, we extract patterns heuristically.
        """
        if not self._session_id or not self._observations:
            return None

        # Extract patterns from observations
        patterns = []
        anti_patterns = []
        key_decisions = []

        for obs in self._observations:
            if obs.obs_type == ObservationType.DECISION:
                key_decisions.append(obs.content[:100])

            elif obs.obs_type == ObservationType.GATE_RESULT:
                if obs.outcome == "pass":
                    patterns.append(f"Gate '{obs.gate_name}' passed")
                else:
                    anti_patterns.append(
                        f"Gate '{obs.gate_name}' failed: {', '.join(obs.fail_codes[:2])}"
                    )

            elif obs.obs_type == ObservationType.TOOL_SEQUENCE:
                if obs.success_rate and obs.success_rate > 0.7:
                    patterns.append(obs.content[:100])
                else:
                    anti_patterns.append(obs.content[:100])

        # Build summary content
        content_parts = []
        if patterns:
            content_parts.append(f"Successful patterns: {len(patterns)}")
        if anti_patterns:
            content_parts.append(f"Issues encountered: {len(anti_patterns)}")
        if key_decisions:
            content_parts.append(f"Key decisions: {len(key_decisions)}")

        content = "; ".join(content_parts) if content_parts else "Session completed"

        summary_id = _generate_summary_id(self._session_id)

        self.db.add_summary(
            summary_id=summary_id,
            session_id=self._session_id,
            summary_type="session",
            content=content,
            patterns=patterns[:5] if patterns else None,
            anti_patterns=anti_patterns[:5] if anti_patterns else None,
            key_decisions=key_decisions[:5] if key_decisions else None,
        )

        return {
            "summary_id": summary_id,
            "content": content,
            "patterns": patterns,
            "anti_patterns": anti_patterns,
            "key_decisions": key_decisions,
        }

    # Hook 5: WorkcellEnd (SessionEnd)

    def workcell_end(self, status: str = "completed") -> dict[str, Any]:
        """
        Called at workcell completion.

        Generates summary and closes session.
        """
        if not self._session_id:
            logger.warning("workcell_end called without active session")
            return {"success": False, "error": "No active session"}

        # Generate summary before closing
        summary = self.generate_summary()

        # Close session
        self.db.end_session(self._session_id, status=status)

        logger.info(
            "Memory session ended",
            session_id=self._session_id,
            status=status,
            observation_count=len(self._observations),
        )

        result = {
            "success": True,
            "session_id": self._session_id,
            "observation_count": len(self._observations),
            "summary": summary,
        }

        # Clear state
        self._session_id = None
        self._workcell_id = None
        self._observations = []

        return result

    # Utility methods

    def add_decision(
        self, decision: str, rationale: str, file_refs: list[str] | None = None
    ) -> None:
        """Record an architectural decision."""
        if not self._session_id:
            return

        observation = Observation.from_decision(
            session_id=self._session_id,
            decision=decision,
            rationale=rationale,
            file_refs=file_refs,
        )

        self._observations.append(observation)

        self.db.add_observation(
            observation_id=observation.id,
            session_id=self._session_id,
            obs_type=observation.obs_type.value,
            content=observation.content,
            concept=observation.concept.value if observation.concept else None,
            file_refs=observation.file_refs,
            importance=observation.importance.value,
            token_count=observation.token_count,
        )

    def add_discovery(self, discovery: str, context: str | None = None) -> None:
        """Record a learning or discovery."""
        if not self._session_id:
            return

        observation = Observation.from_discovery(
            session_id=self._session_id,
            discovery=discovery,
            context=context,
        )

        self._observations.append(observation)

        self.db.add_observation(
            observation_id=observation.id,
            session_id=self._session_id,
            obs_type=observation.obs_type.value,
            content=observation.content,
            concept=observation.concept.value if observation.concept else None,
            importance=observation.importance.value,
            token_count=observation.token_count,
        )

    def search(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """Search observations (progressive disclosure Layer 2)."""
        return self.db.search_observations(query, limit=limit)

    def close(self) -> None:
        """Close database connection."""
        self.db.close()
