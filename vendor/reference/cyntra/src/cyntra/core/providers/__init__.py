"""
Cyntra Execution Providers - Unified abstraction for running toolchains anywhere.

This module provides the ExecutionProvider interface and implementations for
various execution backends: local workcells, E2B sandboxes, Modal serverless,
MCP tool servers, and more.

Usage:
    from cyntra.core.providers import get_provider, route, ExecutionProvider
    from cyntra.core.providers.capabilities import ExecutionCapabilities

    # Get a specific provider
    provider = get_provider("e2b", config={"api_key": "..."})

    # Or let the router choose based on manifest requirements
    from cyntra.core.providers import route
    decision = route(manifest)
    result = await decision.provider.execute(manifest, context)

Available Providers:
    - local: Execute on local machine (default)
    - e2b: Execute in E2B cloud sandboxes
    - modal: Execute on Modal serverless (GPU support)
    - gpu-pool: Execute via shared GPU pool manager
    - mcp: Execute tools via MCP servers

See Also:
    - cyntra.providers.base: Base classes and interfaces
    - cyntra.providers.capabilities: Capability definitions
    - cyntra.providers.registry: Provider registration
    - cyntra.providers.router: Intelligent routing
"""

from cyntra.core.providers.base import (
    AgentProvider,
    ExecutionContext,
    ExecutionProvider,
    ExecutionResult,
    OrchestratorProvider,
    SandboxProvider,
    ToolServerProvider,
)
from cyntra.core.providers.capabilities import CAPABILITY_PRESETS, ExecutionCapabilities
from cyntra.core.providers.registry import (
    ProviderRegistry,
    discover_providers,
    get_provider,
    list_providers,
    register_provider,
)
from cyntra.core.providers.router import (
    ProviderRouter,
    RoutingDecision,
    RoutingStrategy,
    get_router,
    route,
    set_router,
)


# Lazy imports for concrete providers (avoid import errors if deps missing)
def _get_local_provider():
    from cyntra.core.providers.local import LocalProvider
    return LocalProvider

def _get_e2b_provider():
    from cyntra.core.providers.e2b import E2BProvider
    return E2BProvider

def _get_modal_provider():
    from cyntra.core.providers.modal import ModalProvider
    return ModalProvider

def _get_mcp_provider():
    from cyntra.core.providers.mcp import MCPProvider
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
