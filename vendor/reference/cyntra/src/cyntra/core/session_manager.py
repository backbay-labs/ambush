"""
Ralph-style Session Manager for Cyntra Kernel.

Implements session continuity across loop iterations:
- Stores and retrieves session IDs per issue
- Tracks session lifecycle (start, pause, resume, end)
- Auto-resets sessions on circuit breaker trips
- Maintains session history for debugging
- Tracks PTY sessions for health monitoring

Inspired by: https://github.com/frankbria/ralph-claude-code
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class SessionState(Enum):
    """Session lifecycle states."""

    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    EXPIRED = "expired"
    RESET = "reset"


@dataclass
class SessionInfo:
    """Information about a single session."""

    session_id: str
    issue_id: str
    toolchain: str
    state: SessionState = SessionState.ACTIVE
    created_at: float = field(default_factory=time.time)
    last_active_at: float = field(default_factory=time.time)
    iteration_count: int = 0
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionTransition:
    """Record of a session state transition."""

    timestamp: float
    session_id: str
    issue_id: str
    from_state: SessionState | None
    to_state: SessionState
    reason: str


@dataclass
class SessionConfig:
    """Configuration for session management."""

    # Session expiration
    expiration_seconds: int = 86400  # 24 hours
    idle_timeout_seconds: int = 3600  # 1 hour of no activity

    # History limits
    max_history_entries: int = 50
    max_sessions_per_issue: int = 5

    # Auto-reset triggers
    reset_on_circuit_breaker: bool = True
    reset_on_interrupt: bool = True
    reset_on_completion: bool = True


class SessionManager:
    """
    Manages session continuity for Claude Code's --continue flag.

    Sessions allow context preservation across:
    - Retry attempts on the same issue
    - Loop iterations in watch mode
    - Interrupted and resumed work

    Auto-reset triggers:
    - Circuit breaker opens (stagnation detected)
    - Manual interrupt (Ctrl+C / SIGINT)
    - Project completion (graceful exit)
    """

    def __init__(
        self,
        config: SessionConfig | None = None,
        persist_path: Path | None = None,
    ) -> None:
        self.config = config or SessionConfig()
        self.persist_path = persist_path

        # Active sessions by issue_id
        self._sessions: dict[str, SessionInfo] = {}

        # PTY session tracking (issue_id -> session info dict)
        self._pty_sessions: dict[str, dict] = {}

        # Session history
        self._history: list[SessionTransition] = []

        # Load persisted state
        if persist_path:
            self._load_state()

    def get_session(
        self,
        issue_id: str,
        toolchain: str,
    ) -> SessionInfo | None:
        """
        Get or create a session for an issue.

        Returns None if session should not be resumed (expired, etc).
        """
        self._cleanup_expired()

        existing = self._sessions.get(issue_id)
        if existing:
            # Check if session is valid for resume
            if existing.state == SessionState.ACTIVE:
                if self._is_expired(existing):
                    self._transition(existing, SessionState.EXPIRED, "session_expired")
                    return None

                # Check toolchain match
                if existing.toolchain != toolchain:
                    self._transition(existing, SessionState.RESET, "toolchain_changed")
                    return self._create_session(issue_id, toolchain)

                # Update last active
                existing.last_active_at = time.time()
                existing.iteration_count += 1
                self._persist_state()
                return existing

            elif existing.state == SessionState.PAUSED:
                # Resume paused session
                self._transition(existing, SessionState.ACTIVE, "resumed")
                existing.last_active_at = time.time()
                existing.iteration_count += 1
                self._persist_state()
                return existing

        # No existing valid session
        return None

    def get_or_create_session(
        self,
        issue_id: str,
        toolchain: str,
    ) -> SessionInfo:
        """Get existing session or create new one."""
        existing = self.get_session(issue_id, toolchain)
        if existing:
            return existing
        return self._create_session(issue_id, toolchain)

    def should_resume(self, issue_id: str) -> bool:
        """Check if an issue has a valid session to resume."""
        session = self._sessions.get(issue_id)
        if not session:
            return False

        if session.state not in (SessionState.ACTIVE, SessionState.PAUSED):
            return False

        if self._is_expired(session):
            return False

        return True

    def pause_session(self, issue_id: str, reason: str = "paused") -> None:
        """Pause a session (e.g., when work is interrupted)."""
        session = self._sessions.get(issue_id)
        if session and session.state == SessionState.ACTIVE:
            self._transition(session, SessionState.PAUSED, reason)

    def complete_session(self, issue_id: str) -> None:
        """Mark a session as completed."""
        session = self._sessions.get(issue_id)
        if session:
            self._transition(session, SessionState.COMPLETED, "work_completed")

    def reset_session(self, issue_id: str, reason: str = "manual_reset") -> None:
        """Reset a session (clears context)."""
        session = self._sessions.get(issue_id)
        if session:
            self._transition(session, SessionState.RESET, reason)
            del self._sessions[issue_id]
            self._persist_state()

    def reset_all_sessions(self, reason: str = "global_reset") -> None:
        """Reset all active sessions."""
        for issue_id in list(self._sessions.keys()):
            self.reset_session(issue_id, reason)

    def on_circuit_breaker_open(self) -> None:
        """Handle circuit breaker opening."""
        if self.config.reset_on_circuit_breaker:
            self.reset_all_sessions("circuit_breaker_open")

    def on_interrupt(self) -> None:
        """Handle interrupt signal."""
        if self.config.reset_on_interrupt:
            for session in self._sessions.values():
                if session.state == SessionState.ACTIVE:
                    self._transition(session, SessionState.PAUSED, "interrupted")
            self._persist_state()

    def store_context(
        self,
        issue_id: str,
        key: str,
        value: Any,
    ) -> None:
        """Store context data in session."""
        session = self._sessions.get(issue_id)
        if session:
            session.context[key] = value
            self._persist_state()

    def get_context(
        self,
        issue_id: str,
        key: str,
        default: Any = None,
    ) -> Any:
        """Get context data from session."""
        session = self._sessions.get(issue_id)
        if session:
            return session.context.get(key, default)
        return default

    def get_status(self) -> dict:
        """Get current session manager status."""
        self._cleanup_expired()

        return {
            "active_sessions": len(
                [s for s in self._sessions.values() if s.state == SessionState.ACTIVE]
            ),
            "paused_sessions": len(
                [s for s in self._sessions.values() if s.state == SessionState.PAUSED]
            ),
            "sessions": {
                issue_id: {
                    "session_id": s.session_id,
                    "toolchain": s.toolchain,
                    "state": s.state.value,
                    "iterations": s.iteration_count,
                    "age_seconds": time.time() - s.created_at,
                    "idle_seconds": time.time() - s.last_active_at,
                }
                for issue_id, s in self._sessions.items()
            },
            "recent_history": [
                {
                    "timestamp": t.timestamp,
                    "session_id": t.session_id[:8],
                    "issue_id": t.issue_id,
                    "from": t.from_state.value if t.from_state else None,
                    "to": t.to_state.value,
                    "reason": t.reason,
                }
                for t in self._history[-10:]
            ],
        }

    # -----------------------------------------------------------------
    # PTY Session Tracking
    # -----------------------------------------------------------------

    def register_pty_session(self, issue_id: str, session_info: dict) -> None:
        """
        Track an active PTY session for health monitoring.

        Args:
            issue_id: The issue this PTY session is executing.
            session_info: Must contain at minimum:
                - pid (int): Process ID of the PTY child
                - start_time (float): Monotonic start time
                - workcell_path (str): Path to the workcell directory
                Optionally:
                - quiescence_timeout (float): Seconds before declaring hang
        """
        required = {"pid", "start_time", "workcell_path"}
        missing = required - set(session_info.keys())
        if missing:
            raise ValueError(f"session_info missing required keys: {missing}")

        self._pty_sessions[issue_id] = {
            **session_info,
            "registered_at": time.time(),
        }
        logger.info(
            "session.pty_registered",
            issue_id=issue_id,
            pid=session_info["pid"],
            workcell_path=session_info["workcell_path"],
        )

    def unregister_pty_session(self, issue_id: str) -> None:
        """Remove PTY session tracking on completion/cleanup."""
        removed = self._pty_sessions.pop(issue_id, None)
        if removed:
            logger.info(
                "session.pty_unregistered",
                issue_id=issue_id,
                pid=removed.get("pid"),
            )

    def check_pty_health(self, issue_id: str) -> dict:
        """
        Check if a tracked PTY session is still responsive.

        Returns:
            dict with keys:
                - healthy (bool): Overall health assessment
                - pid_alive (bool): Whether the process is still running
                - reason (str | None): Explanation if unhealthy
        """
        info = self._pty_sessions.get(issue_id)
        if info is None:
            return {
                "healthy": False,
                "pid_alive": False,
                "reason": "no_pty_session_registered",
            }

        pid = info["pid"]

        # Check if process is alive via signal 0
        pid_alive = False
        try:
            os.kill(pid, 0)
            pid_alive = True
        except (OSError, ProcessLookupError):
            pid_alive = False

        if not pid_alive:
            return {
                "healthy": False,
                "pid_alive": False,
                "reason": "process_dead",
            }

        # Check if session has exceeded a reasonable wall-clock time
        # (2x quiescence_timeout is the hang threshold per the spec)
        quiescence_timeout = info.get("quiescence_timeout", 10.0)
        registered_at = info.get("registered_at", 0.0)
        age = time.time() - registered_at

        # Only flag as unhealthy for age if it's been an absurdly long time
        # (the actual quiescence/hang detection is done by the adapter;
        #  here we just check process liveness)
        max_session_age = info.get("max_session_age", 7200)  # 2 hours default
        if age > max_session_age:
            return {
                "healthy": False,
                "pid_alive": True,
                "reason": f"session_exceeded_max_age ({int(age)}s > {max_session_age}s)",
            }

        return {
            "healthy": True,
            "pid_alive": True,
            "reason": None,
        }

    def get_pty_session_info(self, issue_id: str) -> dict | None:
        """Get stored PTY session info for an issue, or None."""
        return self._pty_sessions.get(issue_id)

    def _create_session(self, issue_id: str, toolchain: str) -> SessionInfo:
        """Create a new session."""
        import uuid

        session_id = str(uuid.uuid4())
        session = SessionInfo(
            session_id=session_id,
            issue_id=issue_id,
            toolchain=toolchain,
            iteration_count=1,
        )
        self._sessions[issue_id] = session

        self._record_transition(
            SessionTransition(
                timestamp=time.time(),
                session_id=session_id,
                issue_id=issue_id,
                from_state=None,
                to_state=SessionState.ACTIVE,
                reason="created",
            )
        )

        logger.info(
            "session.created",
            session_id=session_id[:8],
            issue_id=issue_id,
            toolchain=toolchain,
        )

        self._persist_state()
        return session

    def _transition(
        self,
        session: SessionInfo,
        new_state: SessionState,
        reason: str,
    ) -> None:
        """Transition a session to a new state."""
        self._record_transition(
            SessionTransition(
                timestamp=time.time(),
                session_id=session.session_id,
                issue_id=session.issue_id,
                from_state=session.state,
                to_state=new_state,
                reason=reason,
            )
        )

        logger.info(
            "session.transition",
            session_id=session.session_id[:8],
            issue_id=session.issue_id,
            from_state=session.state.value,
            to_state=new_state.value,
            reason=reason,
        )

        session.state = new_state

    def _record_transition(self, transition: SessionTransition) -> None:
        """Record a transition in history."""
        self._history.append(transition)
        if len(self._history) > self.config.max_history_entries:
            self._history = self._history[-self.config.max_history_entries :]

    def _is_expired(self, session: SessionInfo) -> bool:
        """Check if a session has expired."""
        now = time.time()

        # Check absolute expiration
        if now - session.created_at > self.config.expiration_seconds:
            return True

        # Check idle timeout
        if now - session.last_active_at > self.config.idle_timeout_seconds:
            return True

        return False

    def _cleanup_expired(self) -> None:
        """Clean up expired sessions."""
        for issue_id, session in list(self._sessions.items()):
            if session.state == SessionState.ACTIVE and self._is_expired(session):
                self._transition(session, SessionState.EXPIRED, "cleanup_expired")
                del self._sessions[issue_id]
        self._persist_state()

    def _persist_state(self) -> None:
        """Persist state to disk."""
        if not self.persist_path:
            return

        import json

        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.persist_path, "w") as f:
                json.dump(
                    {
                        "sessions": {
                            issue_id: {
                                "session_id": s.session_id,
                                "issue_id": s.issue_id,
                                "toolchain": s.toolchain,
                                "state": s.state.value,
                                "created_at": s.created_at,
                                "last_active_at": s.last_active_at,
                                "iteration_count": s.iteration_count,
                                "context": s.context,
                            }
                            for issue_id, s in self._sessions.items()
                        },
                        "history": [
                            {
                                "timestamp": t.timestamp,
                                "session_id": t.session_id,
                                "issue_id": t.issue_id,
                                "from_state": t.from_state.value if t.from_state else None,
                                "to_state": t.to_state.value,
                                "reason": t.reason,
                            }
                            for t in self._history
                        ],
                    },
                    f,
                    indent=2,
                )
        except Exception:
            logger.exception("Failed to persist session state")

    def _load_state(self) -> None:
        """Load persisted state from disk."""
        if not self.persist_path or not self.persist_path.exists():
            return

        import json

        try:
            with open(self.persist_path) as f:
                data = json.load(f)

            for issue_id, s_data in data.get("sessions", {}).items():
                session = SessionInfo(
                    session_id=s_data["session_id"],
                    issue_id=s_data["issue_id"],
                    toolchain=s_data["toolchain"],
                    state=SessionState(s_data["state"]),
                    created_at=s_data["created_at"],
                    last_active_at=s_data["last_active_at"],
                    iteration_count=s_data["iteration_count"],
                    context=s_data.get("context", {}),
                )
                self._sessions[issue_id] = session

            for t_data in data.get("history", []):
                self._history.append(
                    SessionTransition(
                        timestamp=t_data["timestamp"],
                        session_id=t_data["session_id"],
                        issue_id=t_data["issue_id"],
                        from_state=SessionState(t_data["from_state"])
                        if t_data["from_state"]
                        else None,
                        to_state=SessionState(t_data["to_state"]),
                        reason=t_data["reason"],
                    )
                )

            # Cleanup after load
            self._cleanup_expired()

            logger.info(
                "session.loaded",
                active_sessions=len(
                    [s for s in self._sessions.values() if s.state == SessionState.ACTIVE]
                ),
            )
        except Exception:
            logger.exception("Failed to load session state")
