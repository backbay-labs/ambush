"""
Output parsers for external security tools.

Each parser converts tool-specific output formats into dicts compatible
with TargetGraph.add_vulnerability() / add_target().

Supported parsers:
  NmapParser           - Parses nmap XML output (-oX)
  SubfinderParser      - Parses subfinder line-based / JSON output
  SqlmapParser         - Parses sqlmap log output
  NucleiParser         - Parses nuclei JSON output (-j)
  GhidraHeadlessParser - Parses analyzeHeadless stdout/log output
  GhidraScriptParser   - Parses structured JSON from Ghidra scripts
  ReadelfParser        - Parses readelf output (sections, symbols, dynamic)
  ObjdumpParser        - Parses objdump disassembly output
"""

from __future__ import annotations

import contextlib
import json
import xml.etree.ElementTree as ET
from typing import Any

import structlog

logger = structlog.get_logger()


class NmapParser:
    """Parse nmap XML output into target/port/service nodes."""

    @staticmethod
    def parse(xml_content: str) -> list[dict[str, Any]]:
        """
        Parse nmap XML output.

        Returns a list of dicts with keys:
          - type: "target" | "port" | "service"
          - host: IP address or hostname
          - port: port number (for port/service entries)
          - protocol: "tcp" | "udp"
          - state: "open" | "closed" | "filtered"
          - service_name: detected service name
          - service_version: detected version string
          - metadata: additional nmap data
        """
        results: list[dict[str, Any]] = []

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as exc:
            logger.warning("parsers.nmap_xml_error", error=str(exc))
            return results

        for host_elem in root.findall(".//host"):
            # Extract address
            addr_elem = host_elem.find("address")
            if addr_elem is None:
                continue
            host_addr = addr_elem.get("addr", "")

            # Host-level entry
            status_elem = host_elem.find("status")
            host_state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

            hostname = ""
            hostname_elem = host_elem.find(".//hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name", "")

            results.append({
                "type": "target",
                "host": host_addr,
                "hostname": hostname,
                "state": host_state,
                "metadata": {"addr_type": addr_elem.get("addrtype", "")},
            })

            # Port entries
            for port_elem in host_elem.findall(".//port"):
                port_id = port_elem.get("portid", "")
                protocol = port_elem.get("protocol", "tcp")

                state_elem = port_elem.find("state")
                port_state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                service_elem = port_elem.find("service")
                service_name = ""
                service_version = ""
                service_product = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    service_version = service_elem.get("version", "")
                    service_product = service_elem.get("product", "")

                results.append({
                    "type": "port",
                    "host": host_addr,
                    "port": int(port_id) if port_id.isdigit() else 0,
                    "protocol": protocol,
                    "state": port_state,
                    "service_name": service_name,
                    "service_version": service_version,
                    "metadata": {
                        "product": service_product,
                        "hostname": hostname,
                    },
                })

        logger.debug("parsers.nmap_parsed", result_count=len(results))
        return results


class SubfinderParser:
    """Parse subfinder output into subdomain/endpoint nodes."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """
        Parse subfinder output (one subdomain per line or JSON).

        Returns a list of dicts with keys:
          - type: "subdomain"
          - host: the discovered subdomain
          - source: discovery source (if JSON mode)
        """
        results: list[dict[str, Any]] = []

        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # Try JSON line first
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    results.append({
                        "type": "subdomain",
                        "host": data.get("host", data.get("subdomain", "")),
                        "source": data.get("source", ""),
                        "metadata": {k: v for k, v in data.items() if k not in ("host", "subdomain", "source")},
                    })
                    continue
                except json.JSONDecodeError:
                    pass

            # Plain text: one subdomain per line
            results.append({
                "type": "subdomain",
                "host": line,
                "source": "",
                "metadata": {},
            })

        logger.debug("parsers.subfinder_parsed", result_count=len(results))
        return results


class SqlmapParser:
    """Parse sqlmap log/output for injection findings."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """
        Parse sqlmap text output for injection points and findings.

        Returns a list of dicts with keys:
          - type: "vulnerability"
          - vuln_type: "sqli"
          - parameter: the injectable parameter
          - injection_type: type of injection (e.g., "boolean-based blind")
          - endpoint: URL or endpoint
          - severity: "high" | "critical"
          - description: human-readable description
        """
        results: list[dict[str, Any]] = []
        current_url = ""

        for line in output.splitlines():
            stripped = line.strip()

            # Track target URL
            if stripped.startswith("[*] testing URL"):
                current_url = stripped.split("URL")[-1].strip().strip("'\"")
            elif "URL:" in stripped and "target" in stripped.lower():
                parts = stripped.split("URL:")
                if len(parts) > 1:
                    current_url = parts[1].strip().strip("'\"")

            # Detect injectable parameters
            if "is vulnerable" in stripped.lower() or "injectable" in stripped.lower():
                # Extract parameter name if possible
                param = _extract_between(stripped, "parameter '", "'")
                if not param:
                    param = _extract_between(stripped, 'parameter "', '"')
                if not param:
                    param = "unknown"

                results.append({
                    "type": "vulnerability",
                    "vuln_type": "sqli",
                    "parameter": param,
                    "injection_type": _extract_injection_type(stripped),
                    "endpoint": current_url,
                    "severity": "high",
                    "description": stripped,
                })

            # Detect retrieved databases
            if stripped.startswith("[*] ") and "database" in stripped.lower():
                results.append({
                    "type": "discovery",
                    "vuln_type": "sqli",
                    "discovery_type": "database",
                    "value": stripped.lstrip("[*] ").strip(),
                    "endpoint": current_url,
                    "metadata": {},
                })

        logger.debug("parsers.sqlmap_parsed", result_count=len(results))
        return results


class NucleiParser:
    """Parse nuclei JSON output into vulnerability nodes."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """
        Parse nuclei JSON output (one JSON object per line with -j flag).

        Returns a list of dicts with keys:
          - type: "vulnerability"
          - vuln_type: from template tags
          - template_id: nuclei template ID
          - severity: "info" | "low" | "medium" | "high" | "critical"
          - endpoint: matched URL
          - description: template info name
          - matched_at: specific matched location
          - metadata: template info, tags, etc.
        """
        results: list[dict[str, Any]] = []

        for line in output.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info", {})
            severity = info.get("severity", "info").lower()
            tags = info.get("tags", [])

            # Determine vuln_type from tags
            vuln_type = "unknown"
            tag_priority = ["sqli", "xss", "ssrf", "rce", "lfi", "xxe", "auth-bypass"]
            for tag in tag_priority:
                if tag in tags:
                    vuln_type = tag
                    break

            results.append({
                "type": "vulnerability",
                "vuln_type": vuln_type,
                "template_id": data.get("template-id", data.get("templateID", "")),
                "severity": severity,
                "endpoint": data.get("host", data.get("url", "")),
                "matched_at": data.get("matched-at", data.get("matched", "")),
                "description": info.get("name", ""),
                "metadata": {
                    "tags": tags,
                    "reference": info.get("reference", []),
                    "matcher_name": data.get("matcher-name", ""),
                    "template_url": data.get("template-url", ""),
                },
            })

        logger.debug("parsers.nuclei_parsed", result_count=len(results))
        return results


class MasscanParser:
    """Parse masscan JSON output into host/port nodes."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """
        Parse masscan JSON output (-oJ flag).

        Returns a list of dicts with keys:
          - type: "port"
          - host: IP address
          - port: port number
          - protocol: "tcp" | "udp"
          - state: "open"
          - service_name: "" (masscan does not do service detection)
          - metadata: additional masscan data (timestamp, ttl)
        """
        results: list[dict[str, Any]] = []

        # masscan -oJ produces a JSON array (with possible trailing comma)
        content = output.strip()
        if content.endswith(","):
            content = content[:-1]
        if not content.startswith("["):
            content = "[" + content + "]"

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Fallback: try parsing line-by-line JSON
            for line in output.strip().splitlines():
                line = line.strip().rstrip(",")
                if not line or not line.startswith("{"):
                    continue
                try:
                    entry = json.loads(line)
                    for port_info in entry.get("ports", []):
                        results.append({
                            "type": "port",
                            "host": entry.get("ip", ""),
                            "port": port_info.get("port", 0),
                            "protocol": port_info.get("proto", "tcp"),
                            "state": port_info.get("status", "open"),
                            "service_name": "",
                            "metadata": {
                                "timestamp": entry.get("timestamp", ""),
                                "ttl": port_info.get("ttl", 0),
                            },
                        })
                except json.JSONDecodeError:
                    continue
            logger.debug("parsers.masscan_parsed_linewise", result_count=len(results))
            return results

        for entry in data:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip", "")
            for port_info in entry.get("ports", []):
                results.append({
                    "type": "port",
                    "host": ip,
                    "port": port_info.get("port", 0),
                    "protocol": port_info.get("proto", "tcp"),
                    "state": port_info.get("status", "open"),
                    "service_name": "",
                    "metadata": {
                        "timestamp": entry.get("timestamp", ""),
                        "ttl": port_info.get("ttl", 0),
                    },
                })

        logger.debug("parsers.masscan_parsed", result_count=len(results))
        return results


class HydraParser:
    """Parse hydra output for discovered credentials."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """
        Parse hydra text output for successful login attempts.

        Returns a list of dicts with keys:
          - type: "credential"
          - host: target host
          - port: target port
          - service: service name (ssh, ftp, smb, etc.)
          - username: discovered username
          - password: discovered password
          - metadata: additional hydra data
        """
        results: list[dict[str, Any]] = []

        for line in output.splitlines():
            stripped = line.strip()

            # Hydra success lines look like:
            # [22][ssh] host: 10.0.0.1   login: admin   password: secret
            if stripped.startswith("[") and ("login:" in stripped or "password:" in stripped):
                port = _extract_between(stripped, "[", "]")
                # Second bracket has the service
                remainder = stripped[stripped.index("]") + 1:]
                service = ""
                if remainder.startswith("["):
                    service = _extract_between(remainder, "[", "]")

                host = ""
                username = ""
                password = ""

                parts = stripped.split()
                for i, part in enumerate(parts):
                    if part == "host:" and i + 1 < len(parts):
                        host = parts[i + 1]
                    elif part == "login:" and i + 1 < len(parts):
                        username = parts[i + 1]
                    elif part == "password:" and i + 1 < len(parts):
                        password = parts[i + 1]

                if username or password:
                    results.append({
                        "type": "credential",
                        "host": host,
                        "port": int(port) if port.isdigit() else 0,
                        "service": service,
                        "username": username,
                        "password": password,
                        "metadata": {"raw_line": stripped},
                    })

        logger.debug("parsers.hydra_parsed", result_count=len(results))
        return results


class Enum4linuxParser:
    """Parse enum4linux output for SMB/AD enumeration results."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """
        Parse enum4linux text output for shares, users, and groups.

        Returns a list of dicts with keys:
          - type: "share" | "user" | "group" | "info"
          - name: share/user/group name
          - host: target host
          - description: additional details
          - metadata: raw section data
        """
        results: list[dict[str, Any]] = []
        current_section = ""
        host = ""

        for line in output.splitlines():
            stripped = line.strip()

            # Track target host
            if "Target Information" in stripped or "target:" in stripped.lower():
                parts = stripped.split(":")
                if len(parts) > 1:
                    host = parts[-1].strip()

            # Track sections
            if stripped.startswith("========"):
                continue
            if stripped.startswith("[+]") or stripped.startswith("[*]"):
                section_text = stripped.lstrip("[+*] ").strip()
                if "share" in section_text.lower():
                    current_section = "shares"
                elif "user" in section_text.lower():
                    current_section = "users"
                elif "group" in section_text.lower():
                    current_section = "groups"
                elif "password policy" in section_text.lower():
                    current_section = "password_policy"
                elif "os information" in section_text.lower():
                    current_section = "os_info"
                continue

            if not stripped:
                continue

            # Parse share entries (typically: //HOST/SHARE  Mapping: OK  Type: ...)
            if current_section == "shares" and "//" in stripped:
                share_parts = stripped.split()
                if share_parts:
                    share_path = share_parts[0]
                    share_name = share_path.rstrip("/").split("/")[-1] if "/" in share_path else share_path
                    results.append({
                        "type": "share",
                        "name": share_name,
                        "host": host,
                        "description": stripped,
                        "metadata": {"path": share_path},
                    })

            # Parse user entries
            elif current_section == "users" and stripped and not stripped.startswith("["):
                # User lines vary but often contain username in the output
                results.append({
                    "type": "user",
                    "name": stripped.split()[0] if stripped.split() else stripped,
                    "host": host,
                    "description": stripped,
                    "metadata": {},
                })

            # Parse group entries
            elif current_section == "groups" and stripped and not stripped.startswith("["):
                results.append({
                    "type": "group",
                    "name": stripped.split()[0] if stripped.split() else stripped,
                    "host": host,
                    "description": stripped,
                    "metadata": {},
                })

            # Password policy info
            elif current_section == "password_policy" and ":" in stripped:
                results.append({
                    "type": "info",
                    "name": "password_policy",
                    "host": host,
                    "description": stripped,
                    "metadata": {"section": "password_policy"},
                })

        logger.debug("parsers.enum4linux_parsed", result_count=len(results))
        return results


def _extract_between(text: str, start: str, end: str) -> str:
    """Extract text between two markers."""
    try:
        s = text.index(start) + len(start)
        e = text.index(end, s)
        return text[s:e]
    except ValueError:
        return ""


def _extract_injection_type(text: str) -> str:
    """Extract injection type from sqlmap output line."""
    types = [
        "boolean-based blind",
        "time-based blind",
        "error-based",
        "UNION query",
        "stacked queries",
    ]
    lower = text.lower()
    for t in types:
        if t.lower() in lower:
            return t
    return "unknown"


class HttpxParser:
    """Parse httpx JSON output into service/technology nodes."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """
        Parse httpx JSON output (one JSON object per line with -j flag).

        Returns a list of dicts with keys:
          - type: "service"
          - url: the probed URL
          - status_code: HTTP status
          - server: Server header value
          - content_type: Content-Type header
          - technologies: list of detected technologies (with -td flag)
          - port: port number
          - metadata: additional httpx data (title, cdn, tls info)
        """
        results: list[dict[str, Any]] = []

        for line in output.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract port from URL or field
            port = data.get("port", 0)
            url = data.get("url", data.get("input", ""))
            if not port and ":" in url:
                # Try to extract port from URL
                parts = url.rsplit(":", 1)
                port_str = parts[-1].split("/")[0] if len(parts) > 1 else ""
                if port_str.isdigit():
                    port = int(port_str)

            techs = data.get("tech", data.get("technologies", []))

            results.append({
                "type": "service",
                "url": url,
                "status_code": data.get("status_code", data.get("status-code", 0)),
                "server": data.get("webserver", data.get("server", "")),
                "content_type": data.get("content_type", data.get("content-type", "")),
                "technologies": techs,
                "port": port,
                "metadata": {
                    "title": data.get("title", ""),
                    "cdn": data.get("cdn", False),
                    "tls": data.get("tls", {}),
                    "method": data.get("method", ""),
                    "host": data.get("host", ""),
                },
            })

        logger.debug("parsers.httpx_parsed", result_count=len(results))
        return results


class GhidraHeadlessParser:
    """Parse Ghidra analyzeHeadless stdout/log output."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """
        Parse analyzeHeadless stdout for analysis summary information.

        Returns a list of dicts with keys:
          - type: "analysis_summary" | "script_output" | "error"
          - functions_found: number of functions (for summary)
          - analysis_time: elapsed time string
          - script_name: name of post-script (if applicable)
          - output: raw output text
          - metadata: additional data
        """
        results: list[dict[str, Any]] = []
        functions_found = 0
        analysis_time = ""
        scripts_run: list[str] = []
        errors: list[str] = []
        script_output_lines: list[str] = []
        in_script_output = False

        for line in output.splitlines():
            stripped = line.strip()

            # Track function count
            if "functions" in stripped.lower() and (
                "found" in stripped.lower()
                or "defined" in stripped.lower()
                or "analyzed" in stripped.lower()
            ):
                for word in stripped.split():
                    if word.isdigit():
                        functions_found = max(functions_found, int(word))
                        break

            # Track analysis time
            if "elapsed" in stripped.lower() or "analysis time" in stripped.lower():
                analysis_time = stripped

            # Track scripts
            if "running script" in stripped.lower() or "postscript" in stripped.lower():
                # Extract script name
                parts = stripped.split()
                for part in parts:
                    if part.endswith(".py") or part.endswith(".java"):
                        scripts_run.append(part)
                        break

            # Track script output (lines starting with ">>" or "SCRIPT>")
            if stripped.startswith(">>") or stripped.startswith("SCRIPT>"):
                in_script_output = True
                script_output_lines.append(stripped.lstrip("> ").lstrip("SCRIPT>").strip())
            elif in_script_output and stripped and not stripped.startswith("INFO"):
                # Continue capturing script output until we hit an INFO line
                if stripped.startswith("[") or "Ghidra" in stripped:
                    in_script_output = False
                else:
                    script_output_lines.append(stripped)

            # Track errors
            if "ERROR" in stripped or "SEVERE" in stripped:
                errors.append(stripped)

        # Emit analysis summary
        results.append({
            "type": "analysis_summary",
            "functions_found": functions_found,
            "analysis_time": analysis_time,
            "scripts_run": scripts_run,
            "metadata": {},
        })

        # Emit script output if any
        if script_output_lines:
            results.append({
                "type": "script_output",
                "output": "\n".join(script_output_lines),
                "scripts_run": scripts_run,
                "metadata": {},
            })

        # Emit errors if any
        for err in errors:
            results.append({
                "type": "error",
                "output": err,
                "metadata": {},
            })

        logger.debug("parsers.ghidra_headless_parsed", result_count=len(results))
        return results


class GhidraScriptParser:
    """Parse structured JSON output from custom Ghidra scripts."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """
        Parse JSON output from Ghidra analysis scripts.

        Expects either a single JSON object or one JSON object per line.
        Scripts typically output findings as JSON with keys like
        "functions", "strings", "vulnerabilities", "imports", "exports".

        Returns a list of dicts with keys:
          - type: "function" | "string" | "vulnerability" | "import" | "export" | "finding"
          - name: symbol/function/string name
          - address: hex address in binary
          - metadata: additional data from the script
        """
        results: list[dict[str, Any]] = []

        # Try parsing as a single JSON document first
        content = output.strip()
        data = None
        if content.startswith("{"):
            with contextlib.suppress(json.JSONDecodeError):
                data = json.loads(content)

        if data is not None:
            results.extend(GhidraScriptParser._extract_from_object(data))
        else:
            # Try line-by-line JSON
            for line in output.strip().splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                    results.extend(GhidraScriptParser._extract_from_object(obj))
                except json.JSONDecodeError:
                    continue

        logger.debug("parsers.ghidra_script_parsed", result_count=len(results))
        return results

    @staticmethod
    def _extract_from_object(data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract typed entries from a Ghidra script JSON output object."""
        results: list[dict[str, Any]] = []

        # Functions list
        for fn in data.get("functions", []):
            results.append({
                "type": "function",
                "name": fn.get("name", ""),
                "address": fn.get("address", fn.get("addr", "")),
                "size": fn.get("size", 0),
                "metadata": {k: v for k, v in fn.items()
                             if k not in ("name", "address", "addr", "size")},
            })

        # Strings list
        for s in data.get("strings", []):
            if isinstance(s, str):
                results.append({
                    "type": "string",
                    "name": s,
                    "address": "",
                    "metadata": {},
                })
            elif isinstance(s, dict):
                results.append({
                    "type": "string",
                    "name": s.get("value", s.get("string", "")),
                    "address": s.get("address", s.get("addr", "")),
                    "metadata": {k: v for k, v in s.items()
                                 if k not in ("value", "string", "address", "addr")},
                })

        # Vulnerabilities
        for v in data.get("vulnerabilities", []):
            results.append({
                "type": "vulnerability",
                "name": v.get("function", v.get("name", "")),
                "address": v.get("address", v.get("addr", "")),
                "vuln_type": v.get("type", v.get("vuln_type", "unknown")),
                "severity": v.get("severity", "medium"),
                "description": v.get("description", ""),
                "metadata": {k: v_val for k, v_val in v.items()
                             if k not in ("function", "name", "address", "addr",
                                          "type", "vuln_type", "severity", "description")},
            })

        # Imports
        for imp in data.get("imports", []):
            if isinstance(imp, str):
                results.append({
                    "type": "import",
                    "name": imp,
                    "address": "",
                    "metadata": {},
                })
            elif isinstance(imp, dict):
                results.append({
                    "type": "import",
                    "name": imp.get("name", ""),
                    "address": imp.get("address", ""),
                    "metadata": {k: v for k, v in imp.items()
                                 if k not in ("name", "address")},
                })

        # Exports
        for exp in data.get("exports", []):
            if isinstance(exp, str):
                results.append({
                    "type": "export",
                    "name": exp,
                    "address": "",
                    "metadata": {},
                })
            elif isinstance(exp, dict):
                results.append({
                    "type": "export",
                    "name": exp.get("name", ""),
                    "address": exp.get("address", ""),
                    "metadata": {k: v for k, v in exp.items()
                                 if k not in ("name", "address")},
                })

        # Generic findings
        for finding in data.get("findings", []):
            results.append({
                "type": "finding",
                "name": finding.get("title", finding.get("name", "")),
                "address": finding.get("address", ""),
                "description": finding.get("description", ""),
                "metadata": {k: v for k, v in finding.items()
                             if k not in ("title", "name", "address", "description")},
            })

        return results


class ReadelfParser:
    """Parse readelf output into structured symbol/section data."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """
        Parse readelf text output for sections, symbols, and dynamic entries.

        Returns a list of dicts with keys:
          - type: "section" | "symbol" | "dynamic"
          - name: section/symbol name
          - address: hex address
          - size: size in bytes (for sections/symbols)
          - info: additional info (type, bind, visibility)
          - metadata: raw parsed data
        """
        results: list[dict[str, Any]] = []
        current_section = ""

        for line in output.splitlines():
            stripped = line.strip()

            # Detect section headers
            if "Section Headers:" in stripped or "section header" in stripped.lower():
                current_section = "sections"
                continue
            elif "Symbol table" in stripped:
                current_section = "symbols"
                continue
            elif "Dynamic section" in stripped:
                current_section = "dynamic"
                continue
            elif "Relocation section" in stripped:
                current_section = "relocations"
                continue

            if not stripped or stripped.startswith("Key to Flags"):
                continue

            # Parse section header entries
            # readelf -S outputs multi-line entries:
            #   [ 1] .text             PROGBITS         0000000000401000  00001000
            #        0000000000000500  0000000000000000  AX       0     0     16
            # Note: "[ 1]" splits into "[" and "1]" tokens.
            if current_section == "sections" and stripped.startswith("["):
                parts = stripped.split()
                # Handle "[ 1]" split into "[", "1]" or "[1]" as single token
                nr = ""
                offset = 0
                if len(parts) >= 2 and parts[0] == "[":
                    # "[ 1]" format: nr is parts[1] stripped of "]"
                    nr = parts[1].rstrip("]")
                    offset = 2
                elif parts:
                    nr = parts[0].strip("[]")
                    offset = 1

                if not nr.isdigit():
                    continue

                name = parts[offset] if len(parts) > offset else ""
                sec_type = parts[offset + 1] if len(parts) > offset + 1 else ""
                addr = parts[offset + 2] if len(parts) > offset + 2 else ""

                # Size may be on this line (compact) or the next line
                size = "0"
                if len(parts) > offset + 4:
                    size = parts[offset + 4]

                results.append({
                    "type": "section",
                    "name": name,
                    "address": addr,
                    "size": int(size, 16) if _is_hex(size) else 0,
                    "info": sec_type,
                    "metadata": {"nr": int(nr)},
                })

            # Continuation line for section: starts with hex (size field)
            elif current_section == "sections" and results and not stripped.startswith("["):
                parts = stripped.split()
                if parts and _is_hex(parts[0]) and results[-1]["type"] == "section" and results[-1]["size"] == 0:
                    results[-1]["size"] = int(parts[0], 16)

            # Parse symbol table entries
            # Format: Num: Value Size Type Bind Vis Ndx Name
            elif current_section == "symbols" and ":" in stripped:
                parts = stripped.split()
                if len(parts) >= 8:
                    num = parts[0].rstrip(":")
                    if not num.isdigit():
                        continue
                    value = parts[1]
                    size = parts[2]
                    sym_type = parts[3]
                    bind = parts[4]
                    vis = parts[5] if len(parts) > 5 else ""
                    name = parts[-1] if len(parts) > 7 else ""

                    if name and name != "0":
                        results.append({
                            "type": "symbol",
                            "name": name,
                            "address": value,
                            "size": int(size) if size.isdigit() else 0,
                            "info": f"{sym_type} {bind}",
                            "metadata": {
                                "visibility": vis,
                                "num": int(num),
                            },
                        })

            # Parse dynamic section entries
            # Format: Tag Type Name/Value
            elif current_section == "dynamic" and "0x" in stripped:
                parts = stripped.split()
                if len(parts) >= 3:
                    tag = parts[0]
                    dyn_type = parts[1].strip("()")
                    value = " ".join(parts[2:])

                    results.append({
                        "type": "dynamic",
                        "name": dyn_type,
                        "address": tag,
                        "size": 0,
                        "info": value,
                        "metadata": {},
                    })

        logger.debug("parsers.readelf_parsed", result_count=len(results))
        return results


class ObjdumpParser:
    """Parse objdump disassembly output."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """
        Parse objdump disassembly output for functions and call sites.

        Returns a list of dicts with keys:
          - type: "function" | "call" | "string_ref"
          - name: function/symbol name
          - address: hex address
          - metadata: additional context (instructions, callees)
        """
        results: list[dict[str, Any]] = []
        current_function = ""
        current_addr = ""
        seen_functions: set[str] = set()

        for line in output.splitlines():
            stripped = line.strip()

            # Function headers: "0000000000401000 <main>:"
            if stripped.endswith(">:") and "<" in stripped:
                addr_part = stripped.split()[0] if stripped.split() else ""
                name_start = stripped.index("<") + 1
                name_end = stripped.index(">")
                func_name = stripped[name_start:name_end]
                current_function = func_name
                current_addr = addr_part

                if func_name not in seen_functions:
                    seen_functions.add(func_name)
                    results.append({
                        "type": "function",
                        "name": func_name,
                        "address": addr_part,
                        "metadata": {},
                    })

            # Call instructions: "  401015: e8 xx xx xx xx  call   401050 <strcpy@plt>"
            elif "call" in stripped.lower() and "<" in stripped and ">" in stripped:
                parts = stripped.split()
                call_addr = parts[0].rstrip(":") if parts else ""
                # Extract callee name
                if "<" in stripped and ">" in stripped:
                    callee_start = stripped.index("<") + 1
                    callee_end = stripped.index(">")
                    callee = stripped[callee_start:callee_end]

                    results.append({
                        "type": "call",
                        "name": callee,
                        "address": call_addr,
                        "metadata": {
                            "caller": current_function,
                            "caller_address": current_addr,
                        },
                    })

        logger.debug("parsers.objdump_parsed", result_count=len(results))
        return results


class KatanaParser:
    """Parse katana JSON lines output into endpoint dicts."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """Parse katana JSON lines output.

        Each line is a JSON object with endpoint, method, body, tag, source fields.

        Returns:
            List of dicts with url, method, parameters, content_type, tag keys.
        """
        results: list[dict[str, Any]] = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            url = record.get("endpoint", record.get("url", ""))
            if not url:
                continue

            results.append({
                "type": "endpoint",
                "url": url,
                "method": record.get("method", "GET"),
                "parameters": record.get("body", ""),
                "content_type": record.get("content_type", ""),
                "tag": record.get("tag", ""),
                "source": record.get("source", ""),
                "metadata": {
                    "timestamp": record.get("timestamp", ""),
                },
            })
        return results


class AmassParser:
    """Parse Amass JSON lines output into subdomain/host dicts."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """Parse Amass JSON lines output.

        Each line is a JSON object with name, domain, addresses, tag, sources fields.

        Returns:
            List of dicts with hostname, domain, addresses, source, tag keys.
        """
        results: list[dict[str, Any]] = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            hostname = record.get("name", "")
            if not hostname:
                continue

            # Extract IP addresses from addresses array
            addresses: list[str] = []
            for addr in record.get("addresses", []):
                if isinstance(addr, dict):
                    ip = addr.get("ip", "")
                    if ip:
                        addresses.append(ip)
                elif isinstance(addr, str):
                    addresses.append(addr)

            sources = record.get("sources", [])
            source_str = ",".join(sources) if isinstance(sources, list) else str(sources)

            results.append({
                "type": "subdomain",
                "hostname": hostname,
                "domain": record.get("domain", ""),
                "addresses": addresses,
                "source": source_str,
                "tag": record.get("tag", ""),
                "metadata": {},
            })
        return results


def _is_hex(s: str) -> bool:
    """Check if a string is a valid hexadecimal number."""
    try:
        int(s, 16)
        return True
    except ValueError:
        return False
