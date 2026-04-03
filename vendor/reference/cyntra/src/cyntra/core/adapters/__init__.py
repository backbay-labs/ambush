"""
Adapters - Toolchain integrations.

This module intentionally uses lazy imports so that optional / external-tool
adapters (e.g. OpenCode, Crush) cannot break importing Cyntra as a whole.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cyntra.core.adapters.base import CostEstimate, PatchProof, ToolchainAdapter
    from cyntra.core.adapters.blender import (
        BlenderAgentAdapter,
        BlenderAgentConfig,
        BlenderTaskManifest,
        BlenderTaskResult,
        create_blender_adapter,
    )
    from cyntra.core.adapters.claude import ClaudeAdapter
    from cyntra.core.adapters.codex import CodexAdapter
    from cyntra.core.adapters.comfyui import ComfyUIAdapter
    from cyntra.core.adapters.crush import CrushAdapter
    from cyntra.core.adapters.fab_world import FabWorldAdapter
    from cyntra.core.adapters.opencode import OpenCodeAdapter
    from cyntra.core.adapters.youtu_agent import YoutuAgentAdapter
    from cyntra.core.adapters.outora import (
        LibraryValidationResult,
        OutoraLibraryAdapter,
        PodPlacement,
        create_outora_adapter,
    )
    from cyntra.core.adapters.router import RoutingDecision, ToolchainRouter
    from cyntra.core.adapters.test_architect import TestArchitectAdapter
    from cyntra.core.adapters.generative_art import GenerativeArtAdapter, SigilArtAdapter

__all__ = [
    # Code adapters
    "ToolchainAdapter",
    "PatchProof",
    "CostEstimate",
    "CodexAdapter",
    "ClaudeAdapter",
    "CrushAdapter",
    "OpenCodeAdapter",
    "YoutuAgentAdapter",
    "ToolchainRouter",
    "RoutingDecision",
    # Blender adapter
    "BlenderAgentAdapter",
    "BlenderAgentConfig",
    "BlenderTaskManifest",
    "BlenderTaskResult",
    "create_blender_adapter",
    # Outora adapter
    "OutoraLibraryAdapter",
    "PodPlacement",
    "LibraryValidationResult",
    "create_outora_adapter",
    # Fab World adapter
    "FabWorldAdapter",
    # ComfyUI adapter
    "ComfyUIAdapter",
    "YoutuAgentAdapter",
    # Test Architect adapter
    "TestArchitectAdapter",
    # Generative Art adapter
    "GenerativeArtAdapter",
    "SigilArtAdapter",  # Backwards compat alias
    # Registry helpers
    "get_adapter",
    "get_available_adapters",
]


_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    # base
    "ToolchainAdapter": ("cyntra.core.adapters.base", "ToolchainAdapter"),
    "PatchProof": ("cyntra.core.adapters.base", "PatchProof"),
    "CostEstimate": ("cyntra.core.adapters.base", "CostEstimate"),
    # core adapters
    "CodexAdapter": ("cyntra.core.adapters.codex", "CodexAdapter"),
    "ClaudeAdapter": ("cyntra.core.adapters.claude", "ClaudeAdapter"),
    "CrushAdapter": ("cyntra.core.adapters.crush", "CrushAdapter"),
    "OpenCodeAdapter": ("cyntra.core.adapters.opencode", "OpenCodeAdapter"),
    "YoutuAgentAdapter": ("cyntra.core.adapters.youtu_agent", "YoutuAgentAdapter"),
    "FabWorldAdapter": ("cyntra.core.adapters.fab_world", "FabWorldAdapter"),
    "ComfyUIAdapter": ("cyntra.core.adapters.comfyui", "ComfyUIAdapter"),
    "TestArchitectAdapter": ("cyntra.core.adapters.test_architect", "TestArchitectAdapter"),
    "GenerativeArtAdapter": ("cyntra.core.adapters.generative_art", "GenerativeArtAdapter"),
    "SigilArtAdapter": ("cyntra.core.adapters.generative_art", "SigilArtAdapter"),
    # router
    "ToolchainRouter": ("cyntra.core.adapters.router", "ToolchainRouter"),
    "RoutingDecision": ("cyntra.core.adapters.router", "RoutingDecision"),
    # blender adapter
    "BlenderAgentAdapter": ("cyntra.core.adapters.blender", "BlenderAgentAdapter"),
    "BlenderAgentConfig": ("cyntra.core.adapters.blender", "BlenderAgentConfig"),
    "BlenderTaskManifest": ("cyntra.core.adapters.blender", "BlenderTaskManifest"),
    "BlenderTaskResult": ("cyntra.core.adapters.blender", "BlenderTaskResult"),
    "create_blender_adapter": ("cyntra.core.adapters.blender", "create_blender_adapter"),
    # outora adapter
    "OutoraLibraryAdapter": ("cyntra.core.adapters.outora", "OutoraLibraryAdapter"),
    "PodPlacement": ("cyntra.core.adapters.outora", "PodPlacement"),
    "LibraryValidationResult": ("cyntra.core.adapters.outora", "LibraryValidationResult"),
    "create_outora_adapter": ("cyntra.core.adapters.outora", "create_outora_adapter"),
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
        name: Adapter name (codex, claude, opencode, crush, fab-world)
        config: Optional adapter configuration

    Returns:
        Adapter instance or None if not found / import failed.
    """
    import importlib

    adapters: dict[str, tuple[str, str]] = {
        "codex": ("cyntra.core.adapters.codex", "CodexAdapter"),
        "claude": ("cyntra.core.adapters.claude", "ClaudeAdapter"),
        "opencode": ("cyntra.core.adapters.opencode", "OpenCodeAdapter"),
        "crush": ("cyntra.core.adapters.crush", "CrushAdapter"),
        "fab-world": ("cyntra.core.adapters.fab_world", "FabWorldAdapter"),
    "comfyui": ("cyntra.core.adapters.comfyui", "ComfyUIAdapter"),
    "test-architect": ("cyntra.core.adapters.test_architect", "TestArchitectAdapter"),
    "youtu-agent": ("cyntra.core.adapters.youtu_agent", "YoutuAgentAdapter"),
    "generative-art": ("cyntra.core.adapters.generative_art", "GenerativeArtAdapter"),
    "sigil-art": ("cyntra.core.adapters.generative_art", "SigilArtAdapter"),
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
    for name in ("codex", "claude", "crush", "opencode", "youtu-agent"):
        adapter = get_adapter(name)
        if adapter is not None and getattr(adapter, "available", False):
            available.append(name)
    return available
