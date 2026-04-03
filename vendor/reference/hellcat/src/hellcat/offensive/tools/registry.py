"""ToolRegistry - Manages external security tools available in StrikeCells."""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass

import structlog

logger = structlog.get_logger()

# Regex for safe argument values: alphanumeric, dots, hyphens, slashes,
# colons (ports), equals, commas, underscores. No shell metacharacters.
_SAFE_ARG_RE = re.compile(r"^[a-zA-Z0-9._/:\-=,@~]+$")

# Allowlisted flags per tool (maps tool name -> set of allowed flag prefixes)
_ALLOWED_FLAGS: dict[str, set[str]] = {
    "nmap": {
        "-sV", "-sC", "-sS", "-sT", "-sU", "-sn", "-Pn", "-O",
        "-p", "-T", "-oX", "-oN", "-oG", "--top-ports", "--script",
        "-A", "-F", "--open", "--min-rate", "--max-rate",
    },
    "subfinder": {
        "-d", "-o", "-oJ", "-silent", "-t", "-timeout",
        "-nW", "-all", "-recursive",
    },
    "whatweb": {
        "-a", "-v", "--log-json", "--no-errors", "-t",
    },
    "sqlmap": {
        "-u", "--url", "--data", "--cookie", "--batch", "--level",
        "--risk", "--technique", "--threads", "--output-dir",
        "--forms", "--crawl", "--random-agent", "--tamper",
        "--dump", "--dbs", "--tables", "--columns",
    },
    "ffuf": {
        "-u", "-w", "-mc", "-fc", "-fs", "-fw", "-o", "-of",
        "-t", "-rate", "-H", "-X", "-d", "-recursion",
    },
    "nuclei": {
        "-u", "-l", "-t", "-tags", "-severity", "-o", "-j",
        "-silent", "-rate-limit", "-bulk-size", "-c",
    },
    "nikto": {
        "-h", "-host", "-p", "-port", "-output", "-Format",
        "-Tuning", "-timeout", "-ssl", "-nossl",
    },
    "masscan": {
        "-p", "--ports", "--rate", "--banners", "-oJ", "-oX", "-oL",
        "--open", "--source-port", "--wait", "--retries",
        "--excludefile", "--includefile",
    },
    "hydra": {
        "-l", "-L", "-p", "-P", "-C", "-t", "-w", "-s", "-o",
        "-f", "-F", "-e", "-u", "-M", "-V", "-I",
    },
    "enum4linux": {
        "-a", "-U", "-S", "-P", "-G", "-M", "-N", "-d", "-u", "-p",
        "-w", "-o", "-v",
    },
    "ghidra_headless": {
        "-import", "-process", "-postScript", "-scriptPath",
        "-deleteProject", "-noanalysis", "-readOnly",
    },
    "ghidra_scripts": {
        "-import", "-process", "-postScript", "-scriptPath",
        "-deleteProject", "-readOnly",
    },
    "strings": {
        "-a", "-n", "-t", "-e", "-f",
    },
    "readelf": {
        "-a", "-h", "-l", "-S", "-s", "-d", "-r", "-n", "-W",
        "--dyn-syms", "--sections", "--headers", "--symbols",
        "--relocs", "--dynamic",
    },
    "objdump": {
        "-d", "-D", "-t", "-T", "-x", "-s", "-j", "-C", "-M",
        "--disassemble", "--full-contents", "--headers",
        "--syms", "--dynamic-syms",
    },
    "cloudfox": {
        "--profile", "--output-format", "--verbosity", "-o",
        "inventory", "permissions", "access-keys", "iam-simulator",
        "endpoints", "env-vars", "secrets", "route-tables",
    },
    "pmapper": {
        "graph", "query", "create", "--profile", "--account",
        "privesc", "--principal", "-o", "--format",
    },
    "httpx": {
        "-u", "-l", "-j", "-silent", "-td", "-sc", "-server",
        "-ct", "-title", "-cdn", "-t", "-rl", "-o",
    },
    "metasploit": {
        "-q", "-x", "-r", "-e", "-o",
    },
    "katana": {
        "-u", "-list", "-d", "-jc", "-headless", "-js-crawl", "-timeout",
        "-o", "-j", "-silent", "-rl", "-c", "-depth",
    },
    "amass": {
        "-d", "-o", "-json", "-passive", "-timeout", "-src", "-ip",
        "-brute", "-w", "-rf", "-bl",
    },
    "sliver": {
        "sessions", "beacons", "implants", "generate", "beacon",
        "use", "execute", "--mtls", "--wg", "--dns", "--http", "--https",
        "--os", "--arch", "-f", "-j", "-o", "--save", "--name",
        "--timeout", "--skip-symbols",
    },
}


@dataclass
class SecurityTool:
    """Definition of an external security tool."""

    name: str
    command: str
    phase: str  # "recon" | "vuln_analysis" | "exploitation"
    required: bool = False
    version_cmd: str = ""
    available: bool = False
    description: str = ""


# Default tool definitions
_DEFAULT_TOOLS: dict[str, SecurityTool] = {
    "nmap": SecurityTool(
        name="nmap",
        command="nmap",
        phase="recon",
        required=True,
        version_cmd="nmap --version",
        description="Port scanning and service detection",
    ),
    "subfinder": SecurityTool(
        name="subfinder",
        command="subfinder",
        phase="recon",
        version_cmd="subfinder -version",
        description="Subdomain enumeration",
    ),
    "whatweb": SecurityTool(
        name="whatweb",
        command="whatweb",
        phase="recon",
        version_cmd="whatweb --version",
        description="Web technology fingerprinting",
    ),
    "ffuf": SecurityTool(
        name="ffuf",
        command="ffuf",
        phase="recon",
        version_cmd="ffuf -V",
        description="Directory and parameter fuzzing",
    ),
    "nikto": SecurityTool(
        name="nikto",
        command="nikto",
        phase="recon",
        version_cmd="nikto -Version",
        description="Web server vulnerability scanner",
    ),
    "nuclei": SecurityTool(
        name="nuclei",
        command="nuclei",
        phase="vuln_analysis",
        version_cmd="nuclei -version",
        description="Template-based vulnerability scanning",
    ),
    "sqlmap": SecurityTool(
        name="sqlmap",
        command="sqlmap",
        phase="exploitation",
        version_cmd="sqlmap --version",
        description="SQL injection detection and exploitation",
    ),
    "masscan": SecurityTool(
        name="masscan",
        command="masscan",
        phase="recon",
        version_cmd="masscan --version",
        description="Fast port scanner for large-scale network discovery",
    ),
    "hydra": SecurityTool(
        name="hydra",
        command="hydra",
        phase="exploitation",
        version_cmd="hydra -h",
        description="Credential brute-forcing against network services",
    ),
    "enum4linux": SecurityTool(
        name="enum4linux",
        command="enum4linux",
        phase="recon",
        version_cmd="enum4linux -h",
        description="SMB and Active Directory enumeration",
    ),
    "ghidra_headless": SecurityTool(
        name="ghidra_headless",
        command="analyzeHeadless",
        phase="vuln_analysis",
        version_cmd="analyzeHeadless --help",
        description="Ghidra headless analyzer for automated binary analysis",
    ),
    "ghidra_scripts": SecurityTool(
        name="ghidra_scripts",
        command="analyzeHeadless",
        phase="vuln_analysis",
        version_cmd="analyzeHeadless --help",
        description="Run custom Ghidra scripts (Jython/Java) for binary analysis",
    ),
    "strings": SecurityTool(
        name="strings",
        command="strings",
        phase="vuln_analysis",
        version_cmd="strings --version",
        description="Extract printable strings from binary files",
    ),
    "readelf": SecurityTool(
        name="readelf",
        command="readelf",
        phase="vuln_analysis",
        version_cmd="readelf --version",
        description="ELF header, section, and symbol analysis",
    ),
    "objdump": SecurityTool(
        name="objdump",
        command="objdump",
        phase="vuln_analysis",
        version_cmd="objdump --version",
        description="Disassembly and symbol extraction from binaries",
    ),
    "cloudfox": SecurityTool(
        name="cloudfox",
        command="cloudfox",
        phase="vuln_analysis",
        version_cmd="cloudfox --version",
        description="Cloud offensive security - AWS/GCP inventory and attack paths",
    ),
    "pmapper": SecurityTool(
        name="pmapper",
        command="pmapper",
        phase="vuln_analysis",
        version_cmd="pmapper --version",
        description="AWS IAM privilege escalation path analysis",
    ),
    "httpx": SecurityTool(
        name="httpx",
        command="httpx",
        phase="recon",
        version_cmd="httpx -version",
        description="HTTP probing and technology detection",
    ),
    "metasploit": SecurityTool(
        name="metasploit",
        command="msfconsole",
        phase="exploitation",
        version_cmd="msfconsole --version",
        description="Metasploit Framework exploitation via msfconsole",
    ),
    "katana": SecurityTool(
        name="katana",
        command="katana",
        phase="recon",
        version_cmd="katana -version",
        description="Next-generation headless web crawling",
    ),
    "amass": SecurityTool(
        name="amass",
        command="amass",
        phase="recon",
        version_cmd="amass -version",
        description="Attack surface mapping and asset discovery",
    ),
    "sliver": SecurityTool(
        name="sliver",
        command="sliver-client",
        phase="exploitation",
        version_cmd="sliver-client version",
        description="Sliver C2 framework for adversary emulation",
    ),
}


class ToolRegistry:
    """
    Registry of external security tools available for StrikeCell operators.

    Validates tool availability, builds safe command lines, and executes
    tools with timeout and output capture.
    """

    def __init__(
        self,
        tools: dict[str, SecurityTool] | None = None,
        allowed_tools: list[str] | None = None,
    ) -> None:
        self._tools = {k: SecurityTool(**v.__dict__) for k, v in (tools or _DEFAULT_TOOLS).items()}
        # Filter to allowed_tools if specified
        if allowed_tools is not None:
            self._tools = {k: v for k, v in self._tools.items() if k in allowed_tools}

    def check_availability(self) -> dict[str, bool]:
        """
        Check which registered tools are installed and reachable.

        Runs each tool's version command and marks available=True if it
        exits successfully.
        """
        results: dict[str, bool] = {}
        for name, tool in self._tools.items():
            if not tool.version_cmd:
                tool.available = False
                results[name] = False
                continue
            try:
                proc = subprocess.run(
                    shlex.split(tool.version_cmd),
                    capture_output=True,
                    timeout=10,
                )
                tool.available = proc.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                tool.available = False

            results[name] = tool.available
            logger.debug(
                "tools.availability_check",
                tool=name,
                available=tool.available,
            )

        return results

    def get_tools_for_phase(self, phase: str) -> list[SecurityTool]:
        """Return available tools for a given engagement phase."""
        return [t for t in self._tools.values() if t.phase == phase and t.available]

    def get_tool(self, name: str) -> SecurityTool | None:
        """Look up a tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[SecurityTool]:
        """Return all registered tools."""
        return list(self._tools.values())

    def get_tool_command(
        self,
        name: str,
        args: dict[str, str],
        target: str | None = None,
    ) -> list[str]:
        """
        Build a safe command line for a tool invocation.

        Validates all arguments against the tool's flag allowlist and
        sanitizes values to prevent command injection.

        Raises:
            ValueError: If the tool is unknown, unavailable, or arguments
                        contain disallowed flags/values.
        """
        tool = self._tools.get(name)
        if tool is None:
            raise ValueError(f"Unknown tool: {name}")

        allowed_flags = _ALLOWED_FLAGS.get(name, set())
        cmd = [tool.command]

        for flag, value in args.items():
            # Validate flag is in allowlist
            if not self._flag_allowed(flag, allowed_flags):
                raise ValueError(
                    f"Flag {flag!r} not allowed for tool {name!r}. "
                    f"Allowed: {sorted(allowed_flags)}"
                )

            # Validate value is safe
            if value and not _SAFE_ARG_RE.match(value):
                raise ValueError(
                    f"Unsafe argument value for {flag}: {value!r}"
                )

            cmd.append(flag)
            if value:
                cmd.append(value)

        # Append target at the end if provided
        if target:
            if not _SAFE_ARG_RE.match(target):
                raise ValueError(f"Unsafe target value: {target!r}")
            cmd.append(target)

        return cmd

    def run_tool(
        self,
        name: str,
        args: dict[str, str],
        target: str | None = None,
        timeout: int = 300,
    ) -> tuple[int, str, str]:
        """
        Execute a tool and capture its output.

        Returns (exit_code, stdout, stderr).

        Raises:
            ValueError: If the tool is unknown or unavailable.
            subprocess.TimeoutExpired: If the tool exceeds the timeout.
        """
        tool = self._tools.get(name)
        if tool is None:
            raise ValueError(f"Unknown tool: {name}")
        if not tool.available:
            raise ValueError(f"Tool {name!r} is not available on this system")

        cmd = self.get_tool_command(name, args, target=target)

        logger.info(
            "tools.executing",
            tool=name,
            cmd_preview=" ".join(shlex.quote(c) for c in cmd[:5]),
            timeout=timeout,
        )

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        logger.info(
            "tools.completed",
            tool=name,
            exit_code=proc.returncode,
            stdout_len=len(proc.stdout),
            stderr_len=len(proc.stderr),
        )

        return proc.returncode, proc.stdout, proc.stderr

    @staticmethod
    def _flag_allowed(flag: str, allowed: set[str]) -> bool:
        """Check if a flag matches any entry in the allowlist."""
        if flag in allowed:
            return True
        # Check prefix match (e.g., "--script" allows "--script=vuln")
        return any(flag.startswith(allowed_flag + "=") for allowed_flag in allowed)
