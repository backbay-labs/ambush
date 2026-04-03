"""Guard for forbidden path and allowed write roots."""

from __future__ import annotations

from cyntra.trust.aegis.guards.base import Guard
from cyntra.trust.aegis.state import AegisRunState, AegisViolation
from cyntra.trust.ledger.events import EventType, LedgerEvent
from cyntra.core.manifests.schema import SecurityPolicy


class ForbiddenPathGuard(Guard):
    """Detect writes to forbidden paths or outside allowed roots."""

    guard_id = "forbidden_path_guard"

    def evaluate(
        self,
        event: LedgerEvent,
        state: AegisRunState,
        policy: SecurityPolicy,
    ) -> list[AegisViolation]:
        if event.type != EventType.FILE_WRITE:
            return []

        path = event.data.get("path")
        if not isinstance(path, str) or not path:
            return []

        normalized = path.replace("\\", "/")

        if self._matches_any(normalized, policy.forbidden_paths):
            return [
                AegisViolation(
                    guard_id=self.guard_id,
                    severity="high",
                    message="Write to forbidden path",
                    action=policy.on_violation,
                    event=event,
                    metadata={"path": normalized},
                )
            ]

        if not self._is_allowed(normalized, policy.allowed_write_roots):
            return [
                AegisViolation(
                    guard_id=self.guard_id,
                    severity="high",
                    message="Write outside allowed roots",
                    action=policy.on_violation,
                    event=event,
                    metadata={"path": normalized},
                )
            ]

        return []

    def _is_allowed(self, path: str, roots: list[str]) -> bool:
        if not roots:
            return False

        for root in roots:
            if root in {".", "./"}:
                if not path.startswith("/"):
                    return True
                continue
            if self._matches_path(path, root):
                return True

        return False

    def _matches_any(self, path: str, patterns: list[str]) -> bool:
        return any(self._matches_path(path, pattern) for pattern in patterns)

    def _matches_path(self, path: str, pattern: str) -> bool:
        if pattern.endswith("/"):
            return path.startswith(pattern)
        if pattern.endswith("*"):
            return path.startswith(pattern[:-1])
        return path == pattern or path.startswith(pattern + "/")
