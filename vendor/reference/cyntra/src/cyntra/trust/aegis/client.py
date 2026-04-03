"""
Aegis Daemon Client.

Python client for communicating with the aegis-daemon Rust service
over Unix socket using JSON-RPC.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

# Default socket path (matches NixOS module default)
DEFAULT_SOCKET_PATH = "/run/aegis/aegis.sock"


class EventType(str, Enum):
    """Types of execution events."""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    COMMAND_EXEC = "command_exec"
    NETWORK_EGRESS = "network_egress"
    TOOL_CALL = "tool_call"
    SECRET_ACCESS = "secret_access"
    PATCH_APPLY = "patch_apply"


class Severity(str, Enum):
    """Severity levels for violations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FileEventData:
    """Data for file read/write events."""
    path: str
    content_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"path": self.path}
        if self.content_hash:
            result["content_hash"] = self.content_hash
        return result


@dataclass
class CommandEventData:
    """Data for command execution events."""
    command: str
    args: list[str] = field(default_factory=list)
    working_dir: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"command": self.command, "args": self.args}
        if self.working_dir:
            result["working_dir"] = self.working_dir
        return result


@dataclass
class NetworkEventData:
    """Data for network egress events."""
    host: str
    port: int
    protocol: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"host": self.host, "port": self.port}
        if self.protocol:
            result["protocol"] = self.protocol
        return result


@dataclass
class ToolEventData:
    """Data for tool call events."""
    tool_name: str
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"tool_name": self.tool_name, "parameters": self.parameters}


@dataclass
class SecretEventData:
    """Data for secret access events."""
    secret_name: str
    scope: str

    def to_dict(self) -> dict[str, Any]:
        return {"secret_name": self.secret_name, "scope": self.scope}


@dataclass
class PatchEventData:
    """Data for patch apply events."""
    file_path: str
    patch_content: str
    patch_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "file_path": self.file_path,
            "patch_content": self.patch_content,
        }
        if self.patch_hash:
            result["patch_hash"] = self.patch_hash
        return result


EventData = FileEventData | CommandEventData | NetworkEventData | ToolEventData | SecretEventData | PatchEventData


@dataclass
class ExecutionEvent:
    """An execution event to be checked/recorded by Aegis."""
    event_type: EventType
    data: EventData
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    run_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat() + "Z",
            "data": self.data.to_dict(),
        }
        if self.run_id:
            result["run_id"] = self.run_id
        return result


@dataclass
class GuardResult:
    """Result from a guard check."""
    guard: str
    status: Literal["allow", "deny", "warn"]
    reason: str | None = None
    severity: Severity | None = None
    message: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GuardResult":
        result_data = data.get("result", {})
        status = result_data.get("status", "allow")
        return cls(
            guard=data.get("guard", ""),
            status=status,
            reason=result_data.get("reason"),
            severity=Severity(result_data["severity"]) if result_data.get("severity") else None,
            message=result_data.get("message"),
        )


@dataclass
class CheckResult:
    """Result of a pre-execution check."""
    allowed: bool
    results: list[GuardResult]
    violation_action: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CheckResult":
        return cls(
            allowed=data.get("allowed", True),
            results=[GuardResult.from_dict(r) for r in data.get("results", [])],
            violation_action=data.get("violation_action"),
        )


@dataclass
class RecordResult:
    """Result of recording an event."""
    event_hash: str
    violations: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RecordResult":
        return cls(
            event_hash=data.get("event_hash", ""),
            violations=data.get("violations", 0),
        )


@dataclass
class SystemAttestation:
    """System attestation data from NixOS."""
    nixos_system_hash: str | None
    nixos_config_hash: str | None
    kernel_version: str
    aegis_daemon_version: str
    boot_timestamp: datetime | None
    hardware_id: str | None
    cpu_model: str | None
    attested_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SystemAttestation":
        boot_ts = data.get("boot_timestamp")
        attested = data.get("attested_at")
        return cls(
            nixos_system_hash=data.get("nixos_system_hash"),
            nixos_config_hash=data.get("nixos_config_hash"),
            kernel_version=data.get("kernel_version", ""),
            aegis_daemon_version=data.get("aegis_daemon_version", ""),
            boot_timestamp=datetime.fromisoformat(boot_ts.rstrip("Z")) if boot_ts else None,
            hardware_id=data.get("hardware_id"),
            cpu_model=data.get("cpu_model"),
            attested_at=datetime.fromisoformat(attested.rstrip("Z")) if attested else datetime.utcnow(),
        )

    def is_nixos(self) -> bool:
        """Check if running on NixOS."""
        return self.nixos_system_hash is not None


@dataclass
class LedgerRoot:
    """Ledger root for a completed run."""
    run_id: str
    root_hash: str
    event_count: int
    violation_count: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LedgerRoot":
        return cls(
            run_id=data.get("run_id", ""),
            root_hash=data.get("root_hash", ""),
            event_count=data.get("event_count", 0),
            violation_count=data.get("violation_count", 0),
        )


class ExecutionMode(str, Enum):
    """Execution mode for runs."""
    LOCAL = "local"
    MICROVM = "micro_vm"
    EXTERNAL = "external"


@dataclass
class SecurityPolicy:
    """Security policy for a run (matches Rust SecurityPolicy)."""
    egress_mode: str = "allowlist"
    allowed_domains: list[str] = field(default_factory=list)
    allowed_ip_cidrs: list[str] = field(default_factory=list)
    deny_domains: list[str] = field(default_factory=list)
    allowed_write_roots: list[str] = field(default_factory=list)
    forbidden_paths: list[str] = field(default_factory=list)
    deny_exec_patterns: list[str] = field(default_factory=list)
    allow_tools: list[str] = field(default_factory=list)
    secret_patterns: list[str] = field(default_factory=list)
    max_runtime_seconds: int | None = None
    max_output_bytes: int | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "egress_mode": self.egress_mode,
            "allowed_domains": self.allowed_domains,
            "allowed_ip_cidrs": self.allowed_ip_cidrs,
            "deny_domains": self.deny_domains,
            "allowed_write_roots": self.allowed_write_roots,
            "forbidden_paths": self.forbidden_paths,
            "deny_exec_patterns": self.deny_exec_patterns,
            "allow_tools": self.allow_tools,
            "secret_patterns": self.secret_patterns,
        }
        if self.max_runtime_seconds is not None:
            result["max_runtime_seconds"] = self.max_runtime_seconds
        if self.max_output_bytes is not None:
            result["max_output_bytes"] = self.max_output_bytes
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityPolicy":
        """Build a policy from a dict snapshot."""
        if not isinstance(data, dict):
            return cls()
        return cls(
            egress_mode=data.get("egress_mode", "allowlist"),
            allowed_domains=list(data.get("allowed_domains") or []),
            allowed_ip_cidrs=list(data.get("allowed_ip_cidrs") or []),
            deny_domains=list(data.get("deny_domains") or []),
            allowed_write_roots=list(data.get("allowed_write_roots") or []),
            forbidden_paths=list(data.get("forbidden_paths") or []),
            deny_exec_patterns=list(data.get("deny_exec_patterns") or []),
            allow_tools=list(data.get("allow_tools") or []),
            secret_patterns=list(data.get("secret_patterns") or []),
            max_runtime_seconds=data.get("max_runtime_seconds"),
            max_output_bytes=data.get("max_output_bytes"),
        )

    @classmethod
    def from_manifest(cls, manifest: Any) -> "SecurityPolicy":
        """Create SecurityPolicy from a ToolchainManifest."""
        if not manifest or not hasattr(manifest, 'security'):
            return cls()
        
        sec = manifest.security
        return cls(
            egress_mode=getattr(sec, 'egress_mode', 'allowlist'),
            allowed_domains=list(getattr(sec, 'allowed_domains', [])),
            allowed_ip_cidrs=list(getattr(sec, 'allowed_ip_cidrs', [])),
            deny_domains=list(getattr(sec, 'deny_domains', [])),
            allowed_write_roots=list(getattr(sec, 'allowed_write_roots', [])),
            forbidden_paths=list(getattr(sec, 'forbidden_paths', [])),
            deny_exec_patterns=list(getattr(sec, 'deny_exec_patterns', [])),
            allow_tools=list(getattr(sec, 'allow_tools', [])),
            secret_patterns=list(getattr(sec, 'secret_patterns', [])),
            max_runtime_seconds=getattr(sec, 'max_runtime_seconds', None),
            max_output_bytes=getattr(sec, 'max_output_bytes', None),
        )


@dataclass
class ExecutionHandle:
    """Handle returned by create_run for executing a run."""
    run_id: str
    mode: ExecutionMode
    scope_name: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    exec_prefix: list[str] = field(default_factory=list)
    microvm_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExecutionHandle":
        mode_str = data.get("mode", "local")
        mode = ExecutionMode(mode_str)
        return cls(
            run_id=data.get("run_id", ""),
            mode=mode,
            scope_name=data.get("scope_name"),
            env=data.get("env", {}),
            exec_prefix=data.get("exec_prefix", []),
            microvm_id=data.get("microvm_id"),
        )

    def wrap_command(self, command: list[str]) -> list[str]:
        """Wrap a command with the exec_prefix for sandboxed execution."""
        if self.exec_prefix:
            return self.exec_prefix + command
        return command


class AegisClientError(Exception):
    """Error from the Aegis client."""
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"Aegis error {code}: {message}")


class AegisClient:
    """
    Client for the Aegis security daemon.
    
    Communicates with aegis-daemon over Unix socket using JSON-RPC.
    Falls back to local checks if daemon is not available.
    """

    def __init__(
        self,
        socket_path: str | None = None,
        timeout: float = 5.0,
        fallback_to_local: bool = True,
    ):
        """
        Initialize the Aegis client.
        
        Args:
            socket_path: Path to the Unix socket. Defaults to AEGIS_SOCKET env var
                        or /run/aegis/aegis.sock
            timeout: Connection timeout in seconds
            fallback_to_local: If True, fall back to local checks when daemon unavailable
        """
        self.socket_path = socket_path or os.environ.get("AEGIS_SOCKET", DEFAULT_SOCKET_PATH)
        self.timeout = timeout
        self.fallback_to_local = fallback_to_local
        self._request_id = 0

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    async def _send_request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send a JSON-RPC request to the daemon."""
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._next_id(),
        }
        request_json = json.dumps(request) + "\n"

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.socket_path),
                timeout=self.timeout,
            )

            writer.write(request_json.encode())
            await writer.drain()

            response_line = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout,
            )

            writer.close()
            await writer.wait_closed()

            response = json.loads(response_line.decode())

            if "error" in response and response["error"]:
                error = response["error"]
                raise AegisClientError(error.get("code", -1), error.get("message", "Unknown error"))

            return response.get("result", {})

        except (FileNotFoundError, ConnectionRefusedError) as e:
            if self.fallback_to_local:
                raise AegisClientError(-32000, f"Daemon unavailable: {e}")
            raise

    def is_daemon_available(self) -> bool:
        """Check if the daemon socket exists."""
        return Path(self.socket_path).exists()

    async def health(self) -> dict[str, Any]:
        """Check daemon health."""
        return await self._send_request("aegis.health", {})

    async def check_execution(self, event: ExecutionEvent) -> CheckResult:
        """
        Pre-flight check before executing an action.
        
        Args:
            event: The execution event to check
            
        Returns:
            CheckResult with allowed status and guard results
        """
        result = await self._send_request("aegis.check_execution", {"event": event.to_dict()})
        return CheckResult.from_dict(result)

    async def record_event(self, event: ExecutionEvent) -> RecordResult:
        """
        Record an execution event to the ledger.
        
        Args:
            event: The execution event to record
            
        Returns:
            RecordResult with event hash and violation count
        """
        result = await self._send_request("aegis.record_event", {"event": event.to_dict()})
        return RecordResult.from_dict(result)

    async def get_policy(self) -> dict[str, Any]:
        """Get the current security policy."""
        return await self._send_request("aegis.get_policy", {})

    async def get_system_attestation(self) -> SystemAttestation:
        """Get NixOS system attestation for RunReceipts."""
        result = await self._send_request("aegis.get_system_attestation", {})
        return SystemAttestation.from_dict(result)

    async def start_run(self, run_id: str) -> None:
        """Start tracking a new run."""
        await self._send_request("aegis.start_run", {"run_id": run_id})

    async def complete_run(self, run_id: str, status: str = "completed") -> LedgerRoot:
        """Complete a run and get the ledger root."""
        result = await self._send_request(
            "aegis.complete_run",
            {"run_id": run_id, "status": status},
        )
        return LedgerRoot.from_dict(result)

    async def complete_run_receipt(self, run_id: str, status: str = "completed") -> dict[str, Any]:
        """
        Complete a run and return a signed run receipt (aegis.run_receipt.v1).

        This is suitable for offline verification and/or publishing to AegisNet.
        """
        return await self._send_request(
            "aegis.complete_run_receipt",
            {"run_id": run_id, "status": status},
        )

    async def get_identity(self) -> dict[str, Any]:
        """Get daemon identity (node_id, public key, optional TPM quote)."""
        return await self._send_request("aegis.get_identity", {})

    async def verify_integrity(self, run_id: str | None = None) -> dict[str, Any]:
        """Verify ledger integrity for a run or globally."""
        return await self._send_request(
            "aegis.verify_integrity",
            {"run_id": run_id},
        )

    # === Per-Run Policy Methods (Kernel Enforcement) ===

    async def create_run(
        self,
        run_id: str,
        policy: SecurityPolicy | None = None,
        mode: ExecutionMode = ExecutionMode.LOCAL,
        workdir: str | None = None,
    ) -> ExecutionHandle:
        """
        Create a new run with security policy and get execution handle.
        
        The returned ExecutionHandle contains the exec_prefix that should
        be used to wrap command execution for kernel-level sandboxing.
        
        Args:
            run_id: Unique run identifier
            policy: Security policy for the run (optional, uses defaults if not provided)
            mode: Execution mode (local, microvm, external)
            workdir: Working directory for the run
            
        Returns:
            ExecutionHandle with sandboxing configuration
        """
        params: dict[str, Any] = {
            "run_id": run_id,
            "mode": mode.value,
        }
        if policy is not None:
            params["policy"] = policy.to_dict()
        if workdir is not None:
            params["workdir"] = workdir
        
        result = await self._send_request("aegis.create_run", params)
        return ExecutionHandle.from_dict(result)

    async def set_run_policy(self, run_id: str, policy: SecurityPolicy) -> dict[str, Any]:
        """
        Update the security policy for an existing run.
        
        Args:
            run_id: Run identifier
            policy: New security policy
            
        Returns:
            Compiled policy info
        """
        return await self._send_request(
            "aegis.set_run_policy",
            {"run_id": run_id, "policy": policy.to_dict()},
        )

    async def get_run_policy(self, run_id: str) -> dict[str, Any] | None:
        """Get the current policy for a run."""
        result = await self._send_request("aegis.get_run_policy", {"run_id": run_id})
        return result.get("policy")

    async def cancel_run(self, run_id: str) -> None:
        """Cancel a running run."""
        await self._send_request("aegis.cancel_run", {"run_id": run_id})

    async def isolate_run(self, run_id: str) -> None:
        """Isolate a run (drop network connectivity)."""
        await self._send_request("aegis.isolate_run", {"run_id": run_id})

    async def close_run(self, run_id: str) -> dict[str, Any]:
        """
        Close a run and clean up resources.
        
        This removes the run from active tracking and unregisters
        any proxy mappings.
        
        Args:
            run_id: Run identifier
            
        Returns:
            Final run state
        """
        return await self._send_request("aegis.close_run", {"run_id": run_id})

    async def list_runs(self) -> list[dict[str, Any]]:
        """List all active runs."""
        result = await self._send_request("aegis.list_runs", {})
        return result.get("runs", [])

    async def revoke_run_secrets(self, run_id: str) -> dict[str, Any]:
        """
        Revoke secrets for a run (spec §9.2).
        
        This invalidates any secrets that were provisioned for the run,
        preventing further use even if they were exfiltrated.
        
        Args:
            run_id: Run identifier
            
        Returns:
            Status of the revocation
        """
        return await self._send_request("aegis.revoke_run_secrets", {"run_id": run_id})

    async def get_stats(self) -> dict[str, Any]:
        """
        Get daemon statistics (spec §9.3).
        
        Returns:
            Dict with daemon version, kernel loader status, run counts, proxy stats
        """
        return await self._send_request("aegis.stats", {})

    async def get_proxy_health(self) -> dict[str, Any]:
        """
        Get proxy health status (spec §12.3).
        
        Returns:
            Dict with proxy health status, requests handled/blocked
        """
        return await self._send_request("aegis.proxy_health", {})

    # === Convenience methods for common event types ===

    async def check_file_read(self, path: str, run_id: str | None = None) -> CheckResult:
        """Check if a file read is allowed."""
        event = ExecutionEvent(
            event_type=EventType.FILE_READ,
            data=FileEventData(path=path),
            run_id=run_id,
        )
        return await self.check_execution(event)

    async def check_file_write(self, path: str, run_id: str | None = None) -> CheckResult:
        """Check if a file write is allowed."""
        event = ExecutionEvent(
            event_type=EventType.FILE_WRITE,
            data=FileEventData(path=path),
            run_id=run_id,
        )
        return await self.check_execution(event)

    async def check_command(
        self,
        command: str,
        args: list[str] | None = None,
        run_id: str | None = None,
    ) -> CheckResult:
        """Check if a command execution is allowed."""
        event = ExecutionEvent(
            event_type=EventType.COMMAND_EXEC,
            data=CommandEventData(command=command, args=args or []),
            run_id=run_id,
        )
        return await self.check_execution(event)

    async def check_network(
        self,
        host: str,
        port: int = 443,
        run_id: str | None = None,
    ) -> CheckResult:
        """Check if a network connection is allowed."""
        event = ExecutionEvent(
            event_type=EventType.NETWORK_EGRESS,
            data=NetworkEventData(host=host, port=port),
            run_id=run_id,
        )
        return await self.check_execution(event)

    async def check_tool(
        self,
        tool_name: str,
        parameters: dict[str, Any] | None = None,
        run_id: str | None = None,
    ) -> CheckResult:
        """Check if a tool call is allowed."""
        event = ExecutionEvent(
            event_type=EventType.TOOL_CALL,
            data=ToolEventData(tool_name=tool_name, parameters=parameters or {}),
            run_id=run_id,
        )
        return await self.check_execution(event)

    async def check_patch(
        self,
        file_path: str,
        patch_content: str,
        run_id: str | None = None,
    ) -> CheckResult:
        """Check if a patch is safe to apply."""
        event = ExecutionEvent(
            event_type=EventType.PATCH_APPLY,
            data=PatchEventData(file_path=file_path, patch_content=patch_content),
            run_id=run_id,
        )
        return await self.check_execution(event)


# Global client instance for convenience
_default_client: AegisClient | None = None


def get_client() -> AegisClient:
    """Get the default Aegis client instance."""
    global _default_client
    if _default_client is None:
        _default_client = AegisClient()
    return _default_client


async def check_execution(event: ExecutionEvent) -> CheckResult:
    """Convenience function to check an execution event."""
    return await get_client().check_execution(event)


async def record_event(event: ExecutionEvent) -> RecordResult:
    """Convenience function to record an execution event."""
    return await get_client().record_event(event)


async def get_system_attestation() -> SystemAttestation:
    """Convenience function to get system attestation."""
    return await get_client().get_system_attestation()
