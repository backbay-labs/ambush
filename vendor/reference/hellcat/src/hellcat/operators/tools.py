"""Tool definitions and handlers for Claude agent execution.

Provides the tool schemas (Anthropic ``tools`` format) and dispatch
logic used by :class:`~hellcat.operators.executor.AgentExecutor`.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Command allowlist (from ToolRegistry + common networking utilities)
# ---------------------------------------------------------------------------

COMMAND_ALLOWLIST: set[str] = {
    "nmap", "subfinder", "sqlmap", "ffuf", "nuclei", "nikto",
    "masscan", "hydra", "enum4linux", "ghidra_headless",
    "strings", "readelf", "objdump", "cloudfox", "pmapper",
    "httpx", "metasploit", "katana", "amass", "sliver",
    "curl", "dig", "whois", "host", "traceroute", "ping",
}

# Shell metacharacters that indicate injection attempts
_SHELL_METACHARS = re.compile(r"[;|&`$><\n\r]")

# ---------------------------------------------------------------------------
# Tool context
# ---------------------------------------------------------------------------


@dataclass
class ToolContext:
    """Shared state available to all tool handlers."""

    workspace_dir: Path
    artifacts_dir: Path
    allowed_hosts: list[str] = field(default_factory=list)
    http_client: httpx.Client | None = None
    # Remaining seconds in the execution budget (updated by executor each turn)
    remaining_budget_seconds: float | None = None
    # Safety / control-plane
    disabled_tools: list[str] = field(default_factory=list)
    global_disable: bool = False

    def get_http_client(self) -> httpx.Client:
        if self.http_client is None:
            self.http_client = httpx.Client(timeout=30.0, follow_redirects=True)
        return self.http_client

    def close(self) -> None:
        if self.http_client is not None:
            self.http_client.close()


# ---------------------------------------------------------------------------
# Tool schemas (Anthropic tools format)
# ---------------------------------------------------------------------------

HTTP_REQUEST_TOOL: dict[str, Any] = {
    "name": "http_request",
    "description": (
        "Send an HTTP request. Supports GET, POST, PUT, DELETE. "
        "Returns status code, headers, and body (truncated to 50k chars)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
                "description": "HTTP method.",
            },
            "url": {
                "type": "string",
                "description": "Full URL to request.",
            },
            "headers": {
                "type": "object",
                "description": "Request headers as key-value pairs.",
                "additionalProperties": {"type": "string"},
            },
            "body": {
                "type": "string",
                "description": "Request body (for POST/PUT/PATCH).",
            },
            "timeout": {
                "type": "number",
                "description": "Timeout in seconds (default 30).",
            },
        },
        "required": ["method", "url"],
    },
}

READ_FILE_TOOL: dict[str, Any] = {
    "name": "read_file",
    "description": "Read a file from the workspace directory. Path must be relative to workspace.",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Relative path within the workspace.",
            },
        },
        "required": ["path"],
    },
}

WRITE_FILE_TOOL: dict[str, Any] = {
    "name": "write_file",
    "description": "Write content to a file in the workspace directory.",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Relative path within the workspace.",
            },
            "content": {
                "type": "string",
                "description": "File content to write.",
            },
        },
        "required": ["path", "content"],
    },
}

RUN_COMMAND_TOOL: dict[str, Any] = {
    "name": "run_command",
    "description": (
        "Execute a shell command in the workspace directory. "
        "Returns stdout, stderr, and exit code. Timeout 120s."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Shell command to execute.",
            },
            "timeout": {
                "type": "number",
                "description": "Timeout in seconds (default 120).",
            },
        },
        "required": ["command"],
    },
}

LIST_DIRECTORY_TOOL: dict[str, Any] = {
    "name": "list_directory",
    "description": "List files and directories in a workspace path.",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Relative path within workspace (default: root).",
            },
        },
    },
}

SAVE_DELIVERABLE_TOOL: dict[str, Any] = {
    "name": "save_deliverable",
    "description": (
        "Save a named deliverable file. Writes to both deliverables/ and "
        "artifacts/ directories. Use type to select filename convention."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "deliverable_type": {
                "type": "string",
                "enum": [
                    "RECON",
                    "INJECTION_ANALYSIS",
                    "INJECTION_QUEUE",
                    "INJECTION_EVIDENCE",
                    "XSS_ANALYSIS",
                    "XSS_QUEUE",
                    "XSS_EVIDENCE",
                    "AUTH_ANALYSIS",
                    "AUTH_EVIDENCE",
                    "AUTHZ_ANALYSIS",
                    "AUTHZ_EVIDENCE",
                    "SSRF_ANALYSIS",
                    "SSRF_EVIDENCE",
                    "REPORT",
                    "NETWORK_RECON",
                    "SERVICE_EVIDENCE",
                    "CLOUD_CONFIG",
                    "BINARY_ANALYSIS",
                    "BINARY_EXPLOITATION_QUEUE",
                    "METASPLOIT_EVIDENCE",
                    "METASPLOIT_FINDINGS",
                    "IDENTITY_FINDINGS",
                    "CLOUD_FINDINGS",
                    "SLIVER_EVIDENCE",
                    "PHISHING_RESULTS",
                ],
                "description": "Deliverable type controlling filename.",
            },
            "content": {
                "type": "string",
                "description": "Content to save.",
            },
        },
        "required": ["deliverable_type", "content"],
    },
}


# Mapping from deliverable type to filename
_DELIVERABLE_FILENAMES: dict[str, str] = {
    "RECON": "recon_deliverable.md",
    "INJECTION_ANALYSIS": "injection_analysis_deliverable.md",
    "INJECTION_QUEUE": "injection_exploitation_queue.json",
    "INJECTION_EVIDENCE": "injection_exploitation_evidence.md",
    "XSS_ANALYSIS": "xss_analysis_deliverable.md",
    "XSS_QUEUE": "xss_exploitation_queue.json",
    "XSS_EVIDENCE": "xss_exploitation_evidence.md",
    "AUTH_ANALYSIS": "auth_analysis_deliverable.md",
    "AUTH_EVIDENCE": "auth_exploitation_evidence.md",
    "AUTHZ_ANALYSIS": "authz_analysis_deliverable.md",
    "AUTHZ_EVIDENCE": "authz_exploitation_evidence.md",
    "SSRF_ANALYSIS": "ssrf_analysis_deliverable.md",
    "SSRF_EVIDENCE": "ssrf_exploitation_evidence.md",
    "REPORT": "executive_report.md",
    "NETWORK_RECON": "network_recon_deliverable.md",
    "SERVICE_EVIDENCE": "service_exploitation_evidence.md",
    "CLOUD_CONFIG": "cloud_config_deliverable.md",
    "BINARY_ANALYSIS": "binary_analysis_deliverable.md",
    "BINARY_EXPLOITATION_QUEUE": "binary_exploitation_queue.json",
    "METASPLOIT_EVIDENCE": "metasploit_exploitation_evidence.md",
    "METASPLOIT_FINDINGS": "metasploit_findings.json",
    "IDENTITY_FINDINGS": "identity_findings.json",
    "CLOUD_FINDINGS": "cloud_findings.json",
    "SLIVER_EVIDENCE": "sliver_evidence.md",
    "PHISHING_RESULTS": "phishing_results.json",
}


def validate_deliverable_type(dtype: str) -> bool:
    """Check whether a deliverable type string is in the enum."""
    return dtype in _DELIVERABLE_FILENAMES


# ---------------------------------------------------------------------------
# Tool sets per operator type
# ---------------------------------------------------------------------------

ALL_TOOLS: list[dict[str, Any]] = [
    HTTP_REQUEST_TOOL,
    READ_FILE_TOOL,
    WRITE_FILE_TOOL,
    RUN_COMMAND_TOOL,
    LIST_DIRECTORY_TOOL,
    SAVE_DELIVERABLE_TOOL,
]

RECON_TOOLS: list[dict[str, Any]] = ALL_TOOLS

VULN_TOOLS: list[dict[str, Any]] = ALL_TOOLS

EXPLOIT_TOOLS: list[dict[str, Any]] = ALL_TOOLS

REPORTING_TOOLS: list[dict[str, Any]] = [
    HTTP_REQUEST_TOOL,
    READ_FILE_TOOL,
    WRITE_FILE_TOOL,
    LIST_DIRECTORY_TOOL,
    SAVE_DELIVERABLE_TOOL,
]

_TOOL_SETS: dict[str, list[dict[str, Any]]] = {
    "recon": RECON_TOOLS,
    "vuln_analysis": VULN_TOOLS,
    "exploitation": EXPLOIT_TOOLS,
    "reporting": REPORTING_TOOLS,
}


def get_tools_for_operator(operator_type: str) -> list[dict[str, Any]]:
    """Return tool schemas appropriate for an operator type."""
    return _TOOL_SETS.get(operator_type, ALL_TOOLS)


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

_BODY_TRUNCATE = 50_000


# ---------------------------------------------------------------------------
# Scope enforcement helpers
# ---------------------------------------------------------------------------


def is_host_allowed(
    host: str,
    port: int | None,
    allowed_hosts: list[str],
) -> bool:
    """Check if a host(:port) is allowed by the scope list.

    Supports:
    - Exact domain match: ``example.com``
    - Subdomain wildcard: ``*.example.com``
    - CIDR notation: ``10.0.0.0/8``
    - Explicit host:port: ``example.com:8080``

    Returns False if *allowed_hosts* is empty (fail-closed).
    """
    if not allowed_hosts:
        return False

    for entry in allowed_hosts:
        # URL-style entry (e.g. http://localhost:3000/*)
        if "://" in entry:
            try:
                parsed_entry = urlparse(entry)
                e_host = parsed_entry.hostname or ""
                e_port = parsed_entry.port
                if host == e_host and (e_port is None or port == e_port):
                    return True
            except Exception:
                pass
            continue

        # CIDR match (checked before host:port so IPv6 ranges work)
        if "/" in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if ipaddress.ip_address(host) in network:
                    return True
            except ValueError:
                pass
            continue

        # host:port exact match — only when exactly one colon (not bare IPv6)
        # Bare IPv6 addresses always have 2+ colons; host:port has exactly 1.
        # Bracketed IPv6+port like [::1]:8080 starts with '['.
        if (
            ":" in entry
            and not entry.startswith("*")
            and (entry.startswith("[") or entry.count(":") == 1)
        ):
                try:
                    if entry.startswith("["):
                        bracket_end = entry.index("]")
                        e_host = entry[1:bracket_end]
                        e_port_s = entry[bracket_end + 2:]  # skip "]:"
                        e_port = int(e_port_s)
                    else:
                        e_host, e_port_s = entry.rsplit(":", 1)
                        e_port = int(e_port_s)
                    if host == e_host and port == e_port:
                        return True
                except (ValueError, IndexError):
                    pass
                continue

        # Wildcard subdomain: *.example.com
        if entry.startswith("*."):
            suffix = entry[1:]  # e.g. ".example.com"
            if host == entry[2:] or host.endswith(suffix):
                return True
            continue

        # Exact domain/IP match (includes bare IPv6 like 2001:db8::1)
        if host == entry:
            return True

    return False


def _validate_command(
    command: str,
    disabled_tools: list[str],
    global_disable: bool,
) -> str | None:
    """Validate a shell command against the allowlist.

    Returns None if the command is allowed, or an error message string
    if the command should be rejected.
    """
    if global_disable:
        return "All commands blocked: global_disable is set"

    # Reject shell metacharacters
    if _SHELL_METACHARS.search(command):
        return (
            "Command rejected: shell metacharacters detected "
            "(possible injection)"
        )

    # Extract base executable name
    try:
        parts = shlex.split(command)
    except ValueError:
        return "Command rejected: could not parse command"

    if not parts:
        return "Command rejected: empty command"

    base_cmd = Path(parts[0]).name

    # Check against disabled_tools
    if base_cmd in disabled_tools:
        return f"Command rejected: '{base_cmd}' is in disabled_tools"

    # Check against allowlist
    if base_cmd not in COMMAND_ALLOWLIST:
        return (
            f"Command rejected: '{base_cmd}' is not in the "
            f"command allowlist"
        )

    return None


def _safe_resolve(ctx: ToolContext, rel_path: str) -> Path | None:
    """Resolve a relative path within the workspace, blocking traversal."""
    resolved = (ctx.workspace_dir / rel_path).resolve()
    if not str(resolved).startswith(str(ctx.workspace_dir.resolve())):
        return None
    return resolved


def handle_http_request(ctx: ToolContext, input_data: dict[str, Any]) -> str:
    method = input_data["method"]
    url = input_data["url"]
    headers = input_data.get("headers") or {}
    body = input_data.get("body")
    timeout = input_data.get("timeout", 30)

    # Scope enforcement: parse host/port and check against allowed_hosts
    try:
        parsed = urlparse(url)
        req_host = parsed.hostname or ""
        req_port = parsed.port
        # Normalize default ports so scope entries like "example.com:443" match
        if req_port is None:
            if parsed.scheme == "https":
                req_port = 443
            elif parsed.scheme == "http":
                req_port = 80
    except Exception:
        req_host = ""
        req_port = None

    if not is_host_allowed(req_host, req_port, ctx.allowed_hosts):
        logger.warning(
            "tool.http_request_denied",
            url=url,
            host=req_host,
            port=req_port,
            reason="host not in allowed_hosts scope",
        )
        return json.dumps({
            "error": "HTTP request denied: host not in scope",
            "host": req_host,
            "port": req_port,
            "allowed_hosts": ctx.allowed_hosts,
        })

    client = ctx.get_http_client()
    try:
        resp = client.request(
            method=method,
            url=url,
            headers=headers,
            content=body.encode() if body else None,
            timeout=timeout,
        )
        body_text = resp.text[:_BODY_TRUNCATE]
        if len(resp.text) > _BODY_TRUNCATE:
            body_text += f"\n\n[TRUNCATED: {len(resp.text)} total chars]"

        resp_headers = dict(resp.headers)
        return json.dumps({
            "status_code": resp.status_code,
            "headers": resp_headers,
            "body": body_text,
            "url": str(resp.url),
        })
    except httpx.TimeoutException:
        return json.dumps({"error": f"Request timed out after {timeout}s"})
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def handle_read_file(ctx: ToolContext, input_data: dict[str, Any]) -> str:
    rel_path = input_data["path"]
    resolved = _safe_resolve(ctx, rel_path)
    if resolved is None:
        return json.dumps({"error": "Path traversal blocked."})
    if not resolved.exists():
        return json.dumps({"error": f"File not found: {rel_path}"})
    if not resolved.is_file():
        return json.dumps({"error": f"Not a file: {rel_path}"})
    try:
        content = resolved.read_text(errors="replace")
        if len(content) > _BODY_TRUNCATE:
            content = content[:_BODY_TRUNCATE] + f"\n[TRUNCATED: {len(content)} total chars]"
        return content
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def handle_write_file(ctx: ToolContext, input_data: dict[str, Any]) -> str:
    rel_path = input_data["path"]
    content = input_data["content"]
    resolved = _safe_resolve(ctx, rel_path)
    if resolved is None:
        return json.dumps({"error": "Path traversal blocked."})
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content)
        return json.dumps({"status": "ok", "path": rel_path, "bytes": len(content)})
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def handle_run_command(ctx: ToolContext, input_data: dict[str, Any]) -> str:
    command = input_data["command"]
    timeout = input_data.get("timeout", 120)

    # Command validation gate
    rejection = _validate_command(
        command, ctx.disabled_tools, ctx.global_disable,
    )
    if rejection is not None:
        logger.warning(
            "tool.run_command_denied",
            command=command,
            reason=rejection,
        )
        return json.dumps({"error": rejection})

    # Cap command timeout to remaining execution budget
    if ctx.remaining_budget_seconds is not None:
        timeout = min(timeout, max(ctx.remaining_budget_seconds - 5, 5))
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=str(ctx.workspace_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = proc.stdout[:_BODY_TRUNCATE] if proc.stdout else ""
        stderr = proc.stderr[:_BODY_TRUNCATE] if proc.stderr else ""
        return json.dumps({
            "exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
        })
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Command timed out after {timeout}s"})
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def handle_list_directory(ctx: ToolContext, input_data: dict[str, Any]) -> str:
    rel_path = input_data.get("path", ".")
    resolved = _safe_resolve(ctx, rel_path)
    if resolved is None:
        return json.dumps({"error": "Path traversal blocked."})
    if not resolved.exists():
        return json.dumps({"error": f"Directory not found: {rel_path}"})
    if not resolved.is_dir():
        return json.dumps({"error": f"Not a directory: {rel_path}"})
    try:
        entries = []
        for child in sorted(resolved.iterdir()):
            entries.append({
                "name": child.name,
                "type": "dir" if child.is_dir() else "file",
                "size": child.stat().st_size if child.is_file() else None,
            })
        return json.dumps(entries)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def handle_save_deliverable(ctx: ToolContext, input_data: dict[str, Any]) -> str:
    deliverable_type = input_data["deliverable_type"]
    content = input_data["content"]

    filename = _DELIVERABLE_FILENAMES.get(deliverable_type)
    if filename is None:
        return json.dumps({"error": f"Unknown deliverable type: {deliverable_type}"})

    # Write to deliverables/ in workspace
    deliverables_dir = ctx.workspace_dir / "deliverables"
    deliverables_dir.mkdir(parents=True, exist_ok=True)
    deliverable_path = deliverables_dir / filename
    deliverable_path.write_text(content)

    # Also copy to artifacts/
    artifacts_path = ctx.artifacts_dir / filename
    ctx.artifacts_dir.mkdir(parents=True, exist_ok=True)
    artifacts_path.write_text(content)

    return json.dumps({
        "status": "success",
        "filepath": str(deliverable_path),
        "artifacts_copy": str(artifacts_path),
    })


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_HANDLERS: dict[str, Any] = {
    "http_request": handle_http_request,
    "read_file": handle_read_file,
    "write_file": handle_write_file,
    "run_command": handle_run_command,
    "list_directory": handle_list_directory,
    "save_deliverable": handle_save_deliverable,
}


def dispatch_tool(
    ctx: ToolContext,
    tool_name: str,
    input_data: dict[str, Any],
) -> str:
    """Dispatch a tool call to the appropriate handler.

    Returns:
        JSON-serialised result string (always safe to include in messages).
    """
    # Pre-dispatch gate: global kill-switch
    if ctx.global_disable:
        logger.warning(
            "tool.global_disable",
            tool=tool_name,
            reason="global_disable is set",
        )
        return json.dumps({
            "error": f"Tool '{tool_name}' blocked: global_disable is set",
        })

    # Pre-dispatch gate: per-tool disable list
    if tool_name in ctx.disabled_tools:
        logger.warning(
            "tool.disabled",
            tool=tool_name,
            reason="tool is in disabled_tools",
        )
        return json.dumps({
            "error": f"Tool '{tool_name}' is disabled",
        })

    handler = _HANDLERS.get(tool_name)
    if handler is None:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})

    start = time.monotonic()
    try:
        result = handler(ctx, input_data)
    except Exception as exc:
        logger.error("tool.handler_error", tool=tool_name, error=str(exc))
        result = json.dumps({"error": f"Tool handler crashed: {exc}"})

    elapsed = time.monotonic() - start
    logger.debug(
        "tool.dispatched",
        tool=tool_name,
        elapsed_ms=int(elapsed * 1000),
    )
    return result
