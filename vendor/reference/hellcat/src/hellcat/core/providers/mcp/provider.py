"""
MCP Provider - Execute tools via Model Context Protocol servers.

MCP (Model Context Protocol) provides a standard way for LLMs to discover
and invoke tools across different servers. This provider handles:
- Server discovery and connection
- OAuth 2.1 authentication
- Tool enumeration and invocation
- Resource access

Implements the MCP specification for tool servers.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from hellcat.core.providers.base import (
    ExecutionContext,
    ExecutionResult,
    ToolServerProvider,
)
from hellcat.core.providers.capabilities import ExecutionCapabilities

if TYPE_CHECKING:
    from hellcat.core.manifests.schema import ToolchainManifest

logger = logging.getLogger(__name__)

# Check for HTTP client
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    httpx = None


@dataclass
class MCPServer:
    """Represents a connected MCP server."""

    name: str
    url: str
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    auth_token: str | None = None
    connected: bool = False


@dataclass
class MCPToolResult:
    """Result of an MCP tool invocation."""

    tool_name: str
    server: str
    content: list[dict[str, Any]]
    is_error: bool = False
    error_message: str | None = None


class MCPProvider(ToolServerProvider):
    """
    MCP tool server provider.

    Connects to MCP-compatible tool servers and exposes their tools
    for use in toolchain execution. Features:
    - Server discovery via well-known endpoints
    - OAuth 2.1 authentication (RFC 8414, RFC 7591)
    - Dynamic tool registration
    - Resource access (read-only)
    - Prompt templates

    This provider doesn't execute full toolchains but provides tool
    calling capabilities that can be composed with other providers.
    """

    name = "mcp"
    capabilities = ExecutionCapabilities(
        gpu=False,
        isolation_level="none",  # Tools run on remote servers
        max_runtime=timedelta(minutes=5),  # Per-tool timeout
        max_memory_gb=None,
        persistent_volume=False,
        network_egress=True,
        max_concurrent=50,
        mcp_support=True,
    )

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize the MCP provider.

        Args:
            config: Provider configuration
                - servers: List of server URLs or configs
                - timeout: Default tool timeout in seconds
                - auth: Authentication configuration per server
                - cache_tools: Whether to cache tool lists
        """
        if not HTTPX_AVAILABLE:
            raise ImportError(
                "httpx package required for MCPProvider. "
                "Install with: pip install httpx"
            )

        self.config = config or {}
        self.server_configs = self.config.get("servers", [])
        self.default_timeout = self.config.get("timeout", 30)
        self.auth_config = self.config.get("auth", {})
        self.cache_tools = self.config.get("cache_tools", True)

        # Connected servers
        self._servers: dict[str, MCPServer] = {}
        self._http_client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=self.default_timeout)
        return self._http_client

    async def execute(
        self,
        manifest: ToolchainManifest,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """
        Execute tool calls specified in manifest.

        For MCP, execution means calling the tools specified in the
        manifest's context or entrypoint.
        """
        start_time = datetime.utcnow()
        run_id = context.run_id
        context.ensure_shields()

        try:
            # Emit step started event
            if context.ledger_writer or context.shield_manager:
                from hellcat.trust.ledger.events import StepStartedEvent
                await context.emit_event(StepStartedEvent(
                    run_id=run_id,
                    step_id=context.step_id,
                    provider=self.name,
                    manifest_id=manifest.manifest_id,
                ))

            # Connect to servers
            await self._connect_servers()

            # Execute tools from manifest context
            results = []
            if manifest.context and manifest.context.extra.get("tool_calls"):
                for call in manifest.context.extra["tool_calls"]:
                    result = await self.call_tool(
                        call["server"],
                        call["tool"],
                        call.get("arguments", {}),
                        context=context,
                    )
                    results.append(result)

            # Check for any errors
            has_errors = any(r.is_error for r in results)

            return ExecutionResult(
                status="failed" if has_errors else "completed",
                exit_code=1 if has_errors else 0,
                artifacts={},
                logs={
                    "tool_results": [
                        {
                            "tool": r.tool_name,
                            "server": r.server,
                            "content": r.content,
                            "error": r.error_message,
                        }
                        for r in results
                    ],
                },
                metrics={
                    "duration_seconds": (datetime.utcnow() - start_time).total_seconds(),
                    "tools_called": len(results),
                    "tools_succeeded": sum(1 for r in results if not r.is_error),
                },
            )

        except Exception as e:
            logger.exception(f"MCP execution failed: {e}")
            return ExecutionResult(
                status="error",
                exit_code=-3,
                logs={"error": str(e)},
            )

    async def _connect_servers(self) -> None:
        """Connect to configured MCP servers."""
        for server_config in self.server_configs:
            if isinstance(server_config, str):
                url = server_config
                name = urlparse(url).netloc
            else:
                url = server_config["url"]
                name = server_config.get("name", urlparse(url).netloc)

            if name not in self._servers:
                server = await self._connect_server(name, url)
                if server:
                    self._servers[name] = server

    async def _connect_server(self, name: str, url: str) -> MCPServer | None:
        """Connect to a single MCP server."""
        client = await self._ensure_client()

        try:
            # Check for MCP capability via .well-known
            well_known_url = f"{url.rstrip('/')}/.well-known/mcp.json"

            response = await client.get(well_known_url)

            # Get MCP config or use direct endpoint (reserved for future use)
            _ = response.json() if response.status_code == 200 else {"endpoint": url}

            # Get auth token if needed
            auth_token = await self._get_auth_token(name, url)

            # Create server object
            server = MCPServer(
                name=name,
                url=url,
                auth_token=auth_token,
            )

            # Discover tools
            await self._discover_tools(server)

            server.connected = True
            logger.info(f"Connected to MCP server: {name} ({len(server.tools)} tools)")

            return server

        except Exception as e:
            logger.warning(f"Failed to connect to MCP server {name}: {e}")
            return None

    async def _get_auth_token(self, name: str, url: str) -> str | None:
        """Get OAuth token for server."""
        if name not in self.auth_config:
            return None

        auth = self.auth_config[name]

        # Support pre-configured tokens
        if "token" in auth:
            return auth["token"]

        # Support OAuth 2.1 flow
        if "client_id" in auth:
            return await self._oauth_flow(url, auth)

        return None

    async def _oauth_flow(self, url: str, auth: dict) -> str | None:
        """Execute OAuth 2.1 authorization flow."""
        client = await self._ensure_client()

        try:
            # Discover OAuth endpoints via RFC 8414
            metadata_url = f"{url.rstrip('/')}/.well-known/oauth-authorization-server"

            response = await client.get(metadata_url)

            if response.status_code != 200:
                logger.warning(f"OAuth metadata not found at {metadata_url}")
                return None

            metadata = response.json()

            # Client credentials flow
            token_endpoint = metadata.get("token_endpoint")
            if not token_endpoint:
                return None

            token_response = await client.post(
                token_endpoint,
                data={
                    "grant_type": "client_credentials",
                    "client_id": auth["client_id"],
                    "client_secret": auth.get("client_secret", ""),
                    "scope": auth.get("scope", ""),
                },
            )

            if token_response.status_code == 200:
                return token_response.json().get("access_token")

        except Exception as e:
            logger.warning(f"OAuth flow failed: {e}")

        return None

    async def _discover_tools(self, server: MCPServer) -> None:
        """Discover tools from MCP server."""
        client = await self._ensure_client()

        headers = {}
        if server.auth_token:
            headers["Authorization"] = f"Bearer {server.auth_token}"

        try:
            # MCP tools/list endpoint
            response = await client.post(
                f"{server.url.rstrip('/')}/tools/list",
                headers=headers,
                json={},
            )

            if response.status_code == 200:
                data = response.json()
                server.tools = data.get("tools", [])

        except Exception as e:
            logger.warning(f"Failed to discover tools from {server.name}: {e}")

    # ToolServerProvider implementation

    async def discover_servers(self) -> list[str]:
        """Discover available MCP servers."""
        await self._connect_servers()
        return list(self._servers.keys())

    async def list_tools(self, server: str | None = None) -> list[dict[str, Any]]:
        """List available tools."""
        await self._connect_servers()

        tools = []

        if server:
            if server in self._servers:
                tools = self._servers[server].tools
        else:
            # All tools from all servers
            for srv in self._servers.values():
                for tool in srv.tools:
                    tools.append({
                        **tool,
                        "server": srv.name,
                    })

        return tools

    async def call_tool(
        self,
        server: str,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        context: ExecutionContext | None = None,
    ) -> MCPToolResult:
        """
        Call a tool on an MCP server.

        Args:
            server: Server name
            tool_name: Tool to call
            arguments: Tool arguments

        Returns:
            Tool result
        """
        await self._connect_servers()

        if server not in self._servers:
            return MCPToolResult(
                tool_name=tool_name,
                server=server,
                content=[],
                is_error=True,
                error_message=f"Server '{server}' not found",
            )

        srv = self._servers[server]
        client = await self._ensure_client()

        headers = {}
        if srv.auth_token:
            headers["Authorization"] = f"Bearer {srv.auth_token}"

        actions = []
        if context:
            context.ensure_shields()
            from hellcat.trust.ledger.events import EventType, LedgerEvent

            args_payload = arguments
            if context.manifest and context.manifest.security.redact_in_logs:
                args_payload = {"_redacted": True, "keys": list(arguments.keys())}

            actions.extend(
                await context.emit_event(
                    LedgerEvent(
                        type=EventType.MCP_TOOL_INVOKED,
                        run_id=context.run_id,
                        step_id=context.step_id,
                        provider=self.name,
                        data={
                            "server": server,
                            "tool": tool_name,
                            "arguments": args_payload,
                        },
                    )
                )
            )

            parsed = urlparse(srv.url)
            host = parsed.hostname or parsed.netloc
            if host:
                actions.extend(
                    await context.emit_event(
                        LedgerEvent(
                            type=EventType.NET_CONNECT,
                            run_id=context.run_id,
                            step_id=context.step_id,
                            provider=self.name,
                            data={
                                "server": server,
                                "host": host,
                                "port": parsed.port,
                            },
                        )
                    )
                )

            if any(
                action.action in {"cancel", "isolate", "revoke", "speculate_vote"}
                for action in actions
            ):
                guard_list = ", ".join(
                    sorted(
                        {
                            str(a.metadata.get("guard_id"))
                            for a in actions
                            if a.metadata.get("guard_id")
                        }
                    )
                )
                return MCPToolResult(
                    tool_name=tool_name,
                    server=server,
                    content=[],
                    is_error=True,
                    error_message=f"Blocked by shield policy ({guard_list or 'unknown'})",
                )

        try:
            # MCP tools/call endpoint
            response = await client.post(
                f"{srv.url.rstrip('/')}/tools/call",
                headers=headers,
                json={
                    "name": tool_name,
                    "arguments": arguments,
                },
                timeout=self.default_timeout,
            )

            if response.status_code == 200:
                data = response.json()
                return MCPToolResult(
                    tool_name=tool_name,
                    server=server,
                    content=data.get("content", []),
                    is_error=data.get("isError", False),
                )
            else:
                return MCPToolResult(
                    tool_name=tool_name,
                    server=server,
                    content=[],
                    is_error=True,
                    error_message=f"HTTP {response.status_code}: {response.text}",
                )

        except TimeoutError:
            return MCPToolResult(
                tool_name=tool_name,
                server=server,
                content=[],
                is_error=True,
                error_message=f"Tool call timed out after {self.default_timeout}s",
            )

        except Exception as e:
            return MCPToolResult(
                tool_name=tool_name,
                server=server,
                content=[],
                is_error=True,
                error_message=str(e),
            )

    async def get_resources(self, server: str) -> list[dict[str, Any]]:
        """Get available resources from a server."""
        await self._connect_servers()

        if server not in self._servers:
            return []

        srv = self._servers[server]
        client = await self._ensure_client()

        headers = {}
        if srv.auth_token:
            headers["Authorization"] = f"Bearer {srv.auth_token}"

        try:
            response = await client.post(
                f"{srv.url.rstrip('/')}/resources/list",
                headers=headers,
                json={},
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("resources", [])

        except Exception as e:
            logger.warning(f"Failed to get resources from {server}: {e}")

        return []

    async def read_resource(self, server: str, uri: str) -> dict[str, Any] | None:
        """Read a resource from a server."""
        await self._connect_servers()

        if server not in self._servers:
            return None

        srv = self._servers[server]
        client = await self._ensure_client()

        headers = {}
        if srv.auth_token:
            headers["Authorization"] = f"Bearer {srv.auth_token}"

        try:
            response = await client.post(
                f"{srv.url.rstrip('/')}/resources/read",
                headers=headers,
                json={"uri": uri},
            )

            if response.status_code == 200:
                return response.json()

        except Exception as e:
            logger.warning(f"Failed to read resource {uri} from {server}: {e}")

        return None

    async def stream_logs(self, run_id: str) -> AsyncIterator[str]:
        """MCP doesn't support log streaming."""
        yield f"[MCP] Tool execution completed for {run_id}"

    async def cancel(self, run_id: str) -> bool:
        """MCP tool calls are atomic and can't be cancelled."""
        return False

    async def health_check(self) -> bool:
        """Check if any MCP servers are reachable."""
        await self._connect_servers()
        return any(s.connected for s in self._servers.values())

    async def close(self) -> None:
        """Close HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


class MCPToolAggregator:
    """
    Aggregates tools from multiple MCP servers.

    Provides a unified interface for discovering and calling tools
    across multiple MCP servers with automatic routing.
    """

    def __init__(self, provider: MCPProvider):
        self.provider = provider
        self._tool_map: dict[str, str] = {}  # tool_name -> server

    async def refresh(self) -> None:
        """Refresh tool registry from all servers."""
        self._tool_map.clear()

        for server in await self.provider.discover_servers():
            tools = await self.provider.list_tools(server)
            for tool in tools:
                tool_name = tool["name"]
                if tool_name not in self._tool_map:
                    self._tool_map[tool_name] = server

    async def call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> MCPToolResult:
        """
        Call a tool by name, automatically routing to the right server.

        Args:
            tool_name: Tool to call
            arguments: Tool arguments

        Returns:
            Tool result
        """
        if not self._tool_map:
            await self.refresh()

        if tool_name not in self._tool_map:
            return MCPToolResult(
                tool_name=tool_name,
                server="unknown",
                content=[],
                is_error=True,
                error_message=f"Tool '{tool_name}' not found on any server",
            )

        server = self._tool_map[tool_name]
        return await self.provider.call_tool(server, tool_name, arguments)

    def get_all_tools(self) -> list[str]:
        """Get all available tool names."""
        return list(self._tool_map.keys())
