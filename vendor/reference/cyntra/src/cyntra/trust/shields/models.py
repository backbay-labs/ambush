"""Shared shield models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal


ActionType = Literal[
    "cancel",
    "isolate",
    "revoke",
    "escalate",
    "speculate_vote",
    "alert_only",
]


@dataclass
class ShieldAction:
    """Action emitted by a shield."""

    action: ActionType
    shield: str
    reason: str
    severity: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ShieldAlert:
    """Normalized shield alert."""

    alert_id: str
    shield: str
    severity: str
    summary: str
    timestamp: datetime | None = None
    run_id: str | None = None
    step_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
