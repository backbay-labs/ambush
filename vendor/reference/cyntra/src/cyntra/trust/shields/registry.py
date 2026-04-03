"""Shield registry for dynamic instantiation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cyntra.core.manifests.schema import ShieldSpec
from cyntra.trust.shields.base import Shield


ShieldFactory = Callable[[ShieldSpec, Any], Shield]


class ShieldRegistry:
    """Registry mapping shield names to factories."""

    def __init__(self) -> None:
        self._factories: dict[str, ShieldFactory] = {}

    def register(self, name: str, factory: ShieldFactory) -> None:
        self._factories[name] = factory

    def create(self, spec: ShieldSpec, ctx: Any) -> Shield:
        if spec.name not in self._factories:
            raise KeyError(f"Unknown shield: {spec.name}")
        return self._factories[spec.name](spec, ctx)


_default_registry = ShieldRegistry()


def register_shield(name: str, factory: ShieldFactory) -> None:
    _default_registry.register(name, factory)


def get_registry() -> ShieldRegistry:
    return _default_registry
