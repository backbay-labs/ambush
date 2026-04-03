"""
Provider Registry - Central registry for execution providers.

Handles provider registration, lookup, and lifecycle management.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cyntra.core.providers.base import ExecutionProvider
    from cyntra.core.providers.capabilities import ExecutionCapabilities

logger = logging.getLogger(__name__)

# Global provider registry
_providers: dict[str, type[ExecutionProvider]] = {}
_instances: dict[str, ExecutionProvider] = {}


def register_provider(
    name: str,
    provider_class: type[ExecutionProvider],
    *,
    override: bool = False
) -> None:
    """
    Register a provider class.

    Args:
        name: Provider name (e.g., "local", "e2b", "modal")
        provider_class: Provider class to register
        override: If True, allow overriding existing registration

    Raises:
        ValueError: If provider already registered and override=False
    """
    if name in _providers and not override:
        raise ValueError(f"Provider '{name}' already registered")

    _providers[name] = provider_class
    logger.info(f"Registered provider: {name}")


def unregister_provider(name: str) -> None:
    """
    Unregister a provider.

    Args:
        name: Provider name to unregister
    """
    if name in _providers:
        del _providers[name]
        logger.info(f"Unregistered provider: {name}")

    # Also remove any cached instance
    if name in _instances:
        del _instances[name]


def get_provider(
    name: str,
    *,
    config: dict[str, Any] | None = None,
    cached: bool = True
) -> ExecutionProvider:
    """
    Get a provider instance by name.

    Args:
        name: Provider name
        config: Optional configuration to pass to provider
        cached: If True, return cached instance if available

    Returns:
        Provider instance

    Raises:
        KeyError: If provider not registered
    """
    if name not in _providers:
        raise KeyError(f"Provider '{name}' not registered. Available: {list(_providers.keys())}")

    # Return cached instance if requested
    if cached and name in _instances:
        return _instances[name]

    # Create new instance
    provider_class = _providers[name]
    instance = provider_class(config or {})

    # Cache if requested
    if cached:
        _instances[name] = instance

    return instance


def list_providers() -> list[str]:
    """
    List all registered provider names.

    Returns:
        List of provider names
    """
    return list(_providers.keys())


def get_provider_class(name: str) -> type[ExecutionProvider]:
    """
    Get a provider class by name (without instantiating).

    Args:
        name: Provider name

    Returns:
        Provider class

    Raises:
        KeyError: If provider not registered
    """
    if name not in _providers:
        raise KeyError(f"Provider '{name}' not registered")
    return _providers[name]


def get_providers_by_capability(
    requirements: ExecutionCapabilities
) -> list[tuple[str, type[ExecutionProvider]]]:
    """
    Get all providers that can satisfy the given requirements.

    Args:
        requirements: Required capabilities

    Returns:
        List of (name, class) tuples for matching providers
    """
    matching = []

    for name, provider_class in _providers.items():
        matches, _ = provider_class.capabilities.matches(requirements)
        if matches:
            matching.append((name, provider_class))

    return matching


def clear_registry() -> None:
    """Clear all registered providers and cached instances."""
    _providers.clear()
    _instances.clear()


def clear_instances() -> None:
    """Clear cached provider instances (but keep registrations)."""
    _instances.clear()


# Provider discovery and auto-registration

def discover_providers() -> None:
    """
    Auto-discover and register built-in providers.

    This imports and registers all providers from the providers package.
    """
    # Import built-in providers to trigger their registration
    try:
        from cyntra.core.providers.local import LocalProvider
        register_provider("local", LocalProvider, override=True)
    except ImportError as e:
        logger.debug(f"Local provider not available: {e}")

    try:
        from cyntra.core.providers.e2b import E2BProvider
        register_provider("e2b", E2BProvider, override=True)
    except ImportError as e:
        logger.debug(f"E2B provider not available: {e}")

    try:
        from cyntra.core.providers.modal import ModalProvider
        register_provider("modal", ModalProvider, override=True)
    except ImportError as e:
        logger.debug(f"Modal provider not available: {e}")

    try:
        from cyntra.core.providers.mcp import MCPProvider
        register_provider("mcp", MCPProvider, override=True)
    except ImportError as e:
        logger.debug(f"MCP provider not available: {e}")

    try:
        from cyntra.core.providers.gpu_pool import GPUPoolProvider
        register_provider("gpu-pool", GPUPoolProvider, override=True)
    except ImportError as e:
        logger.debug(f"GPU pool provider not available: {e}")

    try:
        from cyntra.core.providers.workbench import WorkbenchProvider
        register_provider("workbench", WorkbenchProvider, override=True)
    except ImportError as e:
        logger.debug(f"Workbench provider not available: {e}")

    try:
        from cyntra.core.providers.range import AttackRangeProvider
        register_provider("attack_range", AttackRangeProvider, override=True)
    except ImportError as e:
        logger.debug(f"Attack range provider not available: {e}")


class ProviderRegistry:
    """
    Object-oriented provider registry.

    Alternative to module-level functions for cases where
    multiple isolated registries are needed (e.g., testing).
    """

    def __init__(self):
        self._providers: dict[str, type[ExecutionProvider]] = {}
        self._instances: dict[str, ExecutionProvider] = {}

    def register(
        self,
        name: str,
        provider_class: type[ExecutionProvider],
        *,
        override: bool = False
    ) -> None:
        """Register a provider class."""
        if name in self._providers and not override:
            raise ValueError(f"Provider '{name}' already registered")
        self._providers[name] = provider_class

    def unregister(self, name: str) -> None:
        """Unregister a provider."""
        self._providers.pop(name, None)
        self._instances.pop(name, None)

    def get(
        self,
        name: str,
        *,
        config: dict[str, Any] | None = None,
        cached: bool = True
    ) -> ExecutionProvider:
        """Get a provider instance."""
        if name not in self._providers:
            raise KeyError(f"Provider '{name}' not registered")

        if cached and name in self._instances:
            return self._instances[name]

        instance = self._providers[name](config or {})

        if cached:
            self._instances[name] = instance

        return instance

    def list(self) -> list[str]:
        """List registered provider names."""
        return list(self._providers.keys())

    def get_by_capability(
        self,
        requirements: ExecutionCapabilities
    ) -> list[tuple[str, type[ExecutionProvider]]]:
        """Get providers matching requirements."""
        result = []
        for name, cls in self._providers.items():
            matches, _ = cls.capabilities.matches(requirements)
            if matches:
                result.append((name, cls))
        return result

    def clear(self) -> None:
        """Clear all providers and instances."""
        self._providers.clear()
        self._instances.clear()
