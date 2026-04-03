"""
Adapters - Toolchain integrations.

This module intentionally uses lazy imports so that optional / external-tool
adapters (e.g. OpenCode, Crush) cannot break importing Hellcat as a whole.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hellcat.core.adapters.base import CostEstimate, PatchProof, ToolchainAdapter
    from hellcat.core.adapters.claude import ClaudeAdapter
    from hellcat.core.adapters.codex import CodexAdapter
    from hellcat.core.adapters.crush import CrushAdapter
    from hellcat.core.adapters.opencode import OpenCodeAdapter
    from hellcat.core.adapters.router import RoutingDecision, ToolchainRouter
    from hellcat.core.adapters.test_architect import TestArchitectAdapter

__all__ = [
    # Code adapters
    "ToolchainAdapter",
    "PatchProof",
    "CostEstimate",
    "CodexAdapter",
    "ClaudeAdapter",
    "CrushAdapter",
    "OpenCodeAdapter",
    "ToolchainRouter",
    "RoutingDecision",
    # Test Architect adapter
    "TestArchitectAdapter",
    # Registry helpers
    "get_adapter",
    "get_available_adapters",
]


_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    # base
    "ToolchainAdapter": ("hellcat.core.adapters.base", "ToolchainAdapter"),
    "PatchProof": ("hellcat.core.adapters.base", "PatchProof"),
    "CostEstimate": ("hellcat.core.adapters.base", "CostEstimate"),
    # core adapters
    "CodexAdapter": ("hellcat.core.adapters.codex", "CodexAdapter"),
    "ClaudeAdapter": ("hellcat.core.adapters.claude", "ClaudeAdapter"),
    "CrushAdapter": ("hellcat.core.adapters.crush", "CrushAdapter"),
    "OpenCodeAdapter": ("hellcat.core.adapters.opencode", "OpenCodeAdapter"),
    "TestArchitectAdapter": ("hellcat.core.adapters.test_architect", "TestArchitectAdapter"),
    # router
    "ToolchainRouter": ("hellcat.core.adapters.router", "ToolchainRouter"),
    "RoutingDecision": ("hellcat.core.adapters.router", "RoutingDecision"),
}


def __getattr__(name: str):  # type: ignore[override]
    if name in _LAZY_EXPORTS:
        import importlib

        module_name, attr_name = _LAZY_EXPORTS[name]
        module = importlib.import_module(module_name)
        value = getattr(module, attr_name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def get_adapter(name: str, config: dict | None = None):  # -> ToolchainAdapter | None
    """
    Get an adapter by name.

    Args:
        name: Adapter name (codex, claude, opencode, crush)
        config: Optional adapter configuration

    Returns:
        Adapter instance or None if not found / import failed.
    """
    import importlib

    adapters: dict[str, tuple[str, str]] = {
        "codex": ("hellcat.core.adapters.codex", "CodexAdapter"),
        "claude": ("hellcat.core.adapters.claude", "ClaudeAdapter"),
        "opencode": ("hellcat.core.adapters.opencode", "OpenCodeAdapter"),
        "crush": ("hellcat.core.adapters.crush", "CrushAdapter"),
        "test-architect": ("hellcat.core.adapters.test_architect", "TestArchitectAdapter"),
    }

    key = name.lower()
    if key not in adapters:
        return None

    module_name, class_name = adapters[key]
    try:
        cls = getattr(importlib.import_module(module_name), class_name)
    except Exception:
        return None
    return cls(config)


def get_available_adapters() -> list[str]:
    """Get list of available (installed) adapters."""
    available: list[str] = []
    for name in ("codex", "claude", "crush", "opencode"):
        adapter = get_adapter(name)
        if adapter is not None and getattr(adapter, "available", False):
            available.append(name)
    return available
