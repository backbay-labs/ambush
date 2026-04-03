"""
Observation Types and Structures

Following claude-mem observation patterns:
- Type classification: decision, bugfix, feature, refactor, discovery, change
- Concept tags: discovery, problem-solution, pattern, anti-pattern
- Importance levels: critical, decision, info

Extended for Cyntra with:
- gate_result: quality gate outcomes
- tool_sequence: successful tool chains
- trap_warning: dynamics-detected stuck states
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class ObservationType(str, Enum):
    """
    Observation types following claude-mem conventions + Cyntra extensions.

    Claude-mem types:
    - decision: architectural or implementation decisions
    - bugfix: bug fixes and their solutions
    - feature: new feature implementations
    - refactor: code refactoring
    - discovery: learnings about codebase/tools
    - change: general changes

    Cyntra extensions:
    - gate_result: quality gate pass/fail with details
    - tool_sequence: successful tool call patterns
    - trap_warning: dynamics-detected stuck states
    - repair_strategy: fixes for specific fail codes
    """

    # Claude-mem types
    DECISION = "decision"
    BUGFIX = "bugfix"
    FEATURE = "feature"
    REFACTOR = "refactor"
    DISCOVERY = "discovery"
    CHANGE = "change"

    # Cyntra extensions
    GATE_RESULT = "gate_result"
    TOOL_SEQUENCE = "tool_sequence"
    TRAP_WARNING = "trap_warning"
    REPAIR_STRATEGY = "repair_strategy"


class Concept(str, Enum):
    """Concept tags for semantic categorization."""

    DISCOVERY = "discovery"
    PROBLEM_SOLUTION = "problem-solution"
    PATTERN = "pattern"
    ANTI_PATTERN = "anti-pattern"
    WORKFLOW = "workflow"
    CONFIGURATION = "configuration"


class Importance(str, Enum):
    """Importance levels with visual indicators (claude-mem style)."""

    CRITICAL = "critical"  # Must not forget
    DECISION = "decision"  # Key decision made
    INFO = "info"  # General information


@dataclass
class Observation:
    """
    A single observation captured during workcell execution.

    Follows claude-mem structure with Cyntra extensions.
    """

    session_id: str
    obs_type: ObservationType
    content: str
    concept: Concept | None = None
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    file_refs: list[str] = field(default_factory=list)
    outcome: str | None = None
    importance: Importance = Importance.INFO
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Cyntra-specific fields
    gate_name: str | None = None
    fail_codes: list[str] = field(default_factory=list)
    success_rate: float | None = None

    def __post_init__(self):
        """Generate observation ID."""
        self.id = self._generate_id()
        self.token_count = self._estimate_tokens()

    def _generate_id(self) -> str:
        """Generate deterministic observation ID."""
        payload = f"{self.session_id}:{self.obs_type.value}:{self.content[:100]}"
        hash_val = hashlib.sha256(payload.encode()).hexdigest()[:12]
        return f"obs_{hash_val}"

    def _estimate_tokens(self) -> int:
        """Rough token estimation (4 chars per token)."""
        text = self.content
        if self.tool_args:
            text += json.dumps(self.tool_args)
        return len(text) // 4

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "type": self.obs_type.value,
            "concept": self.concept.value if self.concept else None,
            "content": self.content,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "file_refs": self.file_refs,
            "outcome": self.outcome,
            "importance": self.importance.value,
            "token_count": self.token_count,
            "created_at": self.created_at.isoformat(),
            # Cyntra extensions
            "gate_name": self.gate_name,
            "fail_codes": self.fail_codes,
            "success_rate": self.success_rate,
        }

    @classmethod
    def from_tool_use(
        cls,
        session_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        result: str,
        file_refs: list[str] | None = None,
    ) -> Observation:
        """Create observation from tool use."""
        # Determine concept based on tool
        concept = None
        if tool_name in ("Write", "Edit"):
            concept = Concept.WORKFLOW
        elif tool_name in ("Read", "Glob", "Grep"):
            concept = Concept.DISCOVERY

        return cls(
            session_id=session_id,
            obs_type=ObservationType.CHANGE,
            content=f"Used {tool_name}: {result[:200]}",
            concept=concept,
            tool_name=tool_name,
            tool_args=tool_args,
            file_refs=file_refs or [],
            outcome="success" if "error" not in result.lower() else "error",
        )

    @classmethod
    def from_gate_result(
        cls,
        session_id: str,
        gate_name: str,
        passed: bool,
        fail_codes: list[str] | None = None,
        score: float | None = None,
    ) -> Observation:
        """Create observation from gate result."""
        content = f"Gate '{gate_name}' {'passed' if passed else 'failed'}"
        if score is not None:
            content += f" (score: {score:.2f})"
        if fail_codes:
            content += f" - failures: {', '.join(fail_codes[:3])}"

        return cls(
            session_id=session_id,
            obs_type=ObservationType.GATE_RESULT,
            content=content,
            concept=Concept.PROBLEM_SOLUTION if not passed else None,
            outcome="pass" if passed else "fail",
            importance=Importance.CRITICAL if not passed else Importance.INFO,
            gate_name=gate_name,
            fail_codes=fail_codes or [],
            success_rate=score,
        )

    @classmethod
    def from_decision(
        cls,
        session_id: str,
        decision: str,
        rationale: str,
        file_refs: list[str] | None = None,
    ) -> Observation:
        """Create observation from architectural decision."""
        return cls(
            session_id=session_id,
            obs_type=ObservationType.DECISION,
            content=f"{decision}\n\nRationale: {rationale}",
            concept=Concept.PATTERN,
            importance=Importance.DECISION,
            file_refs=file_refs or [],
        )

    @classmethod
    def from_discovery(
        cls,
        session_id: str,
        discovery: str,
        context: str | None = None,
    ) -> Observation:
        """Create observation from learning/discovery."""
        content = discovery
        if context:
            content += f"\n\nContext: {context}"

        return cls(
            session_id=session_id,
            obs_type=ObservationType.DISCOVERY,
            content=content,
            concept=Concept.DISCOVERY,
        )

    @classmethod
    def from_tool_sequence(
        cls,
        session_id: str,
        tools: list[str],
        outcome: str,
        success_rate: float,
    ) -> Observation:
        """Create observation from successful tool sequence pattern."""
        return cls(
            session_id=session_id,
            obs_type=ObservationType.TOOL_SEQUENCE,
            content=f"Tool sequence: {' → '.join(tools)}\nOutcome: {outcome}",
            concept=Concept.PATTERN if success_rate > 0.7 else Concept.ANTI_PATTERN,
            importance=Importance.DECISION if success_rate > 0.8 else Importance.INFO,
            success_rate=success_rate,
        )

    @classmethod
    def from_trap_warning(
        cls,
        session_id: str,
        state_id: str,
        reason: str,
        recommendation: str,
    ) -> Observation:
        """Create observation from dynamics trap detection."""
        return cls(
            session_id=session_id,
            obs_type=ObservationType.TRAP_WARNING,
            content=f"Trap detected: {reason}\n\nRecommendation: {recommendation}",
            concept=Concept.ANTI_PATTERN,
            importance=Importance.CRITICAL,
        )
