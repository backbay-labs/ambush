"""Abstract base classes and shared types for integration adapters."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class IntegrationDirection(StrEnum):
    EXPORT = "export"
    IMPORT = "import"


@dataclass
class AdapterResult:
    """Result returned by every adapter execution."""

    success: bool
    items_processed: int
    errors: list[str]
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class IntegrationAdapter(ABC):
    """Base class for all vendor integration adapters.

    Subclasses declare their platform name, direction, and the tenant-validation
    claim IDs that must be satisfied before execution is allowed.
    """

    platform: str
    direction: IntegrationDirection
    required_claims: list[str] = field(default_factory=list)

    @abstractmethod
    async def execute(self, context: dict[str, Any]) -> AdapterResult:
        """Run the adapter operation (export or import)."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the remote platform is reachable."""
        ...
