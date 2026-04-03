"""
Kernel Escalation - Manual and automatic issue escalation.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import structlog

from hellcat.core.scheduler.routing import KernelConfig
from hellcat.core.state.manager import StateManager

logger = structlog.get_logger()


def manual_escalate(config_path: Path, issue_id: str, reason: str) -> None:
    """Manually escalate an issue."""
    config = KernelConfig.load(config_path)
    state_manager = StateManager(config)

    # Update status
    state_manager.update_issue_status(issue_id, "escalated")

    # Log escalation
    state_manager.add_event(
        event_type="issue.escalated",
        issue_id=issue_id,
        data={
            "reason": reason,
            "manual": True,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )

    logger.info("Issue escalated", issue_id=issue_id, reason=reason)


def auto_escalate(
    config: KernelConfig,
    state_manager: StateManager,
    issue_id: str,
    reason: str,
) -> None:
    """Automatically escalate an issue due to repeated failures."""
    state_manager.update_issue_status(issue_id, "escalated")

    state_manager.add_event(
        event_type="issue.escalated",
        issue_id=issue_id,
        data={
            "reason": reason,
            "manual": False,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )

    logger.warning("Issue auto-escalated", issue_id=issue_id, reason=reason)
