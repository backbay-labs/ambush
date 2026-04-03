"""Shared helpers for the reporting package."""
from __future__ import annotations

import json
from typing import Any

_REMEDIATION_MAP: dict[str, str] = {
    "sqli": "Use parameterized queries / prepared statements. Validate and sanitize all user input.",
    "xss": "Encode output contextually (HTML, JS, URL). Use Content-Security-Policy headers.",
    "xss_reflected": "Encode output contextually. Use Content-Security-Policy headers.",
    "xss_stored": "Sanitize input on storage and encode on output. Use CSP headers.",
    "ssrf": "Validate and allowlist URLs. Block internal/private IP ranges.",
    "rce": "Never pass user input to system commands. Use safe APIs instead of exec/eval.",
    "auth_bypass": (
        "Implement proper authentication checks on all endpoints. Use framework auth middleware."
    ),
    "idor": "Implement proper authorization checks. Use indirect object references.",
    "lfi": (
        "Validate file paths. Use allowlists for accessible files."
        " Avoid user input in file operations."
    ),
    "xxe": "Disable external entity processing in XML parsers.",
    "credential_spray": "Implement account lockout. Use multi-factor authentication.",
    "privesc": "Apply principle of least privilege. Validate authorization at every access level.",
    "csrf": "Use anti-CSRF tokens. Validate Origin/Referer headers.",
    "cloud-misconfiguration": "Review and remediate cloud configuration per CIS benchmarks.",
}


def _parse_meta(finding: dict[str, Any]) -> dict[str, Any]:
    """Parse metadata_json from a finding dict."""
    raw = finding.get("metadata_json", "{}")
    try:
        return json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError):
        return {}


def _suggest_remediation(vuln_type: str) -> str:
    """Suggest remediation based on vulnerability type."""
    if vuln_type in _REMEDIATION_MAP:
        return _REMEDIATION_MAP[vuln_type]
    for key, val in _REMEDIATION_MAP.items():
        if key in vuln_type or vuln_type in key:
            return val
    return "Review and fix the identified vulnerability following OWASP guidelines."
