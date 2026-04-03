"""
Hellcat Execution Providers - Unified abstraction for running toolchains anywhere.

This module provides the ExecutionProvider interface and implementations for
various execution backends: local workcells, E2B sandboxes, Modal serverless,
MCP tool servers, and more.

Usage:
    from hellcat.core.providers import get_provider, route, ExecutionProvider
    from hellcat.core.providers.capabilities import ExecutionCapabilities

    # Get a specific provider
    provider = get_provider("e2b", config={"api_key": "..."})

    # Or let the router choose based on manifest requirements
    from hellcat.core.providers import route
    decision = route(manifest)
    result = await decision.provider.execute(manifest, context)

Available Providers:
    - local: Execute on local machine (default)
    - e2b: Execute in E2B cloud sandboxes
    - modal: Execute on Modal serverless (GPU support)
    - gpu-pool: Execute via shared GPU pool manager
    - mcp: Execute tools via MCP servers

See Also:
    - hellcat.providers.base: Base classes and interfaces
    - hellcat.providers.capabilities: Capability definitions
    - hellcat.providers.registry: Provider registration
    - hellcat.providers.router: Intelligent routing
"""

from hellcat.core.providers.base import (
    AgentProvider,
    ExecutionContext,
    ExecutionProvider,
    ExecutionResult,
    OrchestratorProvider,
    SandboxProvider,
    ToolServerProvider,
)
from hellcat.core.providers.capabilities import CAPABILITY_PRESETS, ExecutionCapabilities
from hellcat.core.providers.registry import (
    ProviderRegistry,
    discover_providers,
    get_provider,
    list_providers,
    register_provider,
)
from hellcat.core.providers.router import (
    ProviderRouter,
    RoutingDecision,
    RoutingStrategy,
    get_router,
    route,
    set_router,
)


# Lazy imports for concrete providers (avoid import errors if deps missing)
def _get_local_provider():
    from hellcat.core.providers.local import LocalProvider
    return LocalProvider

def _get_e2b_provider():
    from hellcat.core.providers.e2b import E2BProvider
    return E2BProvider

def _get_modal_provider():
    from hellcat.core.providers.modal import ModalProvider
    return ModalProvider

def _get_mcp_provider():
    from hellcat.core.providers.mcp import MCPProvider
    return MCPProvider


__all__ = [
    # Base classes
    "ExecutionProvider",
    "SandboxProvider",
    "OrchestratorProvider",
    "AgentProvider",
    "ToolServerProvider",
    # Data classes
    "ExecutionContext",
    "ExecutionResult",
    "ExecutionCapabilities",
    "CAPABILITY_PRESETS",
    # Registry
    "get_provider",
    "list_providers",
    "register_provider",
    "discover_providers",
    "ProviderRegistry",
    # Router
    "ProviderRouter",
    "RoutingDecision",
    "RoutingStrategy",
    "route",
    "get_router",
    "set_router",
]
