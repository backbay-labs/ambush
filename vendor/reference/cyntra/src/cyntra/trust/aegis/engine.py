"""Aegis engine for runtime security enforcement."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable

from cyntra.trust.aegis.guards import EgressAllowlistGuard, ForbiddenPathGuard, MCPToolGuard, SecretLeakGuard
from cyntra.trust.aegis.guards.base import Guard
from cyntra.trust.aegis.state import AegisRunState, AegisViolation
from cyntra.trust.ledger.events import LedgerEvent
from cyntra.core.manifests.schema import SecurityPolicy


ResponseHandler = Callable[[AegisViolation, LedgerEvent], Awaitable[None] | None]


class AegisEngine:
    """Evaluate guards and trigger responses for a single run."""

    def __init__(
        self,
        policy: SecurityPolicy,
        *,
        guards: list[Guard] | None = None,
        response_handler: ResponseHandler | None = None,
        state: AegisRunState | None = None,
        secret_values: list[str] | None = None,
    ) -> None:
        self.policy = policy
        self.state = state or AegisRunState()
        self.response_handler = response_handler
        self.guards = guards or self._default_guards(secret_values or [])

    async def handle_event(self, event: LedgerEvent) -> list[AegisViolation]:
        """Evaluate guards against an event and run responses."""
        self.state.update(event)

        violations: list[AegisViolation] = []
        for guard in self.guards:
            violations.extend(guard.evaluate(event, self.state, self.policy))

        if violations and self.response_handler:
            for violation in violations:
                result = self.response_handler(violation, event)
                if inspect.isawaitable(result):
                    await result

        return violations

    def _default_guards(self, secret_values: list[str]) -> list[Guard]:
        guards: list[Guard] = [
            ForbiddenPathGuard(),
            EgressAllowlistGuard(),
            MCPToolGuard(),
        ]

        if secret_values:
            guards.append(SecretLeakGuard(secret_values))

        return guards
