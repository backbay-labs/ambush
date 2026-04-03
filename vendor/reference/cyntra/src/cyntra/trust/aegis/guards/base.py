"""Guard interface for Aegis runtime checks."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cyntra.trust.aegis.state import AegisRunState, AegisViolation
from cyntra.trust.ledger.events import LedgerEvent
from cyntra.core.manifests.schema import SecurityPolicy


class Guard(ABC):
    """Base class for Aegis guards."""

    guard_id: str

    @abstractmethod
    def evaluate(
        self,
        event: LedgerEvent,
        state: AegisRunState,
        policy: SecurityPolicy,
    ) -> list[AegisViolation]:
        """Evaluate guard against an event."""
        ...
