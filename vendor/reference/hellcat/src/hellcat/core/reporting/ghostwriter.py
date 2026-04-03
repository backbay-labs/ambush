"""GhostwriterFormatter - Export findings in Ghostwriter JSON format.

Ghostwriter (https://github.com/GhostManager/Ghostwriter) is an engagement
management platform. This formatter produces JSON compatible with
Ghostwriter's finding import API.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from hellcat.core.reporting._helpers import _REMEDIATION_MAP, _parse_meta

if TYPE_CHECKING:
    from hellcat.core.reporting.generator import ReportBundle

logger = structlog.get_logger()

# Map Hellcat severity to Ghostwriter severity scale
_SEVERITY_MAP: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}


@dataclass
class GhostwriterFinding:
    """A single finding in Ghostwriter format."""

    title: str
    severity: str
    description: str
    impact: str
    mitigation: str
    affected_entities: list[str]
    evidence: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    finding_type: str = ""
    references: list[str] | None = None


class GhostwriterFormatter:
    """Format Hellcat findings for Ghostwriter API import.

    Produces a JSON file compatible with Ghostwriter's finding import
    endpoint. Each finding maps Hellcat severity to Ghostwriter's scale
    and includes affected systems, evidence, and remediation guidance.
    """

    def format(
        self,
        bundle: ReportBundle,
        engagement_id: str = "",
        output_dir: Path | None = None,
    ) -> list[Path]:
        """Format ReportBundle findings for Ghostwriter.

        Args:
            bundle: The ReportBundle from ReportGenerator.
            engagement_id: Optional Ghostwriter engagement ID.
            output_dir: Directory to write output files.

        Returns:
            List of output file paths.
        """
        gw_findings = self._map_findings(bundle.findings)

        payload = {
            "engagement_id": engagement_id,
            "findings_count": len(gw_findings),
            "findings": [self._finding_to_dict(f) for f in gw_findings],
        }

        output_files: list[Path] = []

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            findings_path = output_dir / "ghostwriter_findings.json"
            findings_path.write_text(
                json.dumps(payload, indent=2, default=str),
                encoding="utf-8",
            )
            output_files.append(findings_path)
            logger.info(
                "ghostwriter.export_complete",
                path=str(findings_path),
                findings=len(gw_findings),
            )

        return output_files

    def _map_findings(
        self, findings: list[dict[str, Any]],
    ) -> list[GhostwriterFinding]:
        """Map Hellcat findings to GhostwriterFinding objects."""
        gw_findings: list[GhostwriterFinding] = []

        for finding in findings:
            severity = finding.get("severity", "info")
            vuln_type = finding.get("vuln_type", "unknown")

            meta = _parse_meta(finding)

            title = self._build_title(vuln_type, finding)
            gw_severity = _SEVERITY_MAP.get(severity, "Informational")
            description = finding.get("description", "")
            impact = meta.get("impact_description", self._default_impact(severity))
            mitigation = self._suggest_mitigation(vuln_type)

            affected: list[str] = []
            source_loc = finding.get("source_location", "")
            if source_loc:
                affected.append(source_loc)

            evidence = ""
            witness = finding.get("witness_payload", "")
            if witness:
                evidence = f"Proof payload:\n{witness}"

            cvss_score = finding.get("cvss")
            if isinstance(cvss_score, str):
                try:
                    cvss_score = float(cvss_score)
                except ValueError:
                    cvss_score = None

            gw_findings.append(GhostwriterFinding(
                title=title,
                severity=gw_severity,
                description=description,
                impact=impact,
                mitigation=mitigation,
                affected_entities=affected,
                evidence=evidence,
                cvss_score=cvss_score,
                finding_type=vuln_type,
            ))

        return gw_findings

    def _finding_to_dict(self, finding: GhostwriterFinding) -> dict[str, Any]:
        """Convert GhostwriterFinding to API-compatible dict."""
        result: dict[str, Any] = {
            "title": finding.title,
            "severity": finding.severity,
            "description": finding.description,
            "impact": finding.impact,
            "mitigation": finding.mitigation,
            "affected_entities": finding.affected_entities,
            "finding_type": finding.finding_type,
        }
        if finding.evidence:
            result["evidence"] = finding.evidence
        if finding.cvss_score is not None:
            result["cvss_score"] = finding.cvss_score
        if finding.cvss_vector:
            result["cvss_vector"] = finding.cvss_vector
        if finding.references:
            result["references"] = finding.references
        return result

    def _build_title(
        self, vuln_type: str, finding: dict[str, Any],
    ) -> str:
        """Build a descriptive finding title."""
        type_names: dict[str, str] = {
            "sqli": "SQL Injection",
            "xss": "Cross-Site Scripting (XSS)",
            "xss_reflected": "Reflected Cross-Site Scripting",
            "xss_stored": "Stored Cross-Site Scripting",
            "ssrf": "Server-Side Request Forgery (SSRF)",
            "rce": "Remote Code Execution",
            "auth_bypass": "Authentication Bypass",
            "idor": "Insecure Direct Object Reference (IDOR)",
            "lfi": "Local File Inclusion (LFI)",
            "xxe": "XML External Entity Injection (XXE)",
            "credential_spray": "Credential Spraying",
            "privesc": "Privilege Escalation",
            "csrf": "Cross-Site Request Forgery (CSRF)",
            "cve": "Known Vulnerability (CVE)",
        }
        base = type_names.get(vuln_type, vuln_type.replace("_", " ").title())

        location = finding.get("source_location", "")
        if location:
            return f"{base} in {location}"
        return base

    def _suggest_mitigation(self, vuln_type: str) -> str:
        """Suggest remediation for a vulnerability type."""
        if vuln_type in _REMEDIATION_MAP:
            return _REMEDIATION_MAP[vuln_type]
        for key, val in _REMEDIATION_MAP.items():
            if key in vuln_type or vuln_type in key:
                return val
        return "Review and remediate following OWASP guidelines."

    def _default_impact(self, severity: str) -> str:
        """Provide default impact text based on severity."""
        impacts: dict[str, str] = {
            "critical": (
                "Complete system compromise possible. Immediate remediation required."
            ),
            "high": "Significant security impact. High-priority remediation recommended.",
            "medium": "Moderate security impact. Remediation should be planned.",
            "low": "Minor security impact. Address during regular maintenance.",
            "info": "Informational finding for awareness.",
        }
        return impacts.get(severity, "Security impact assessment needed.")

    @staticmethod
    def push_to_ghostwriter(
        url: str,
        api_key: str,
        findings_path: Path,
        timeout: int = 30,
    ) -> bool:
        """Push findings JSON to Ghostwriter API.

        Args:
            url: Ghostwriter instance URL.
            api_key: API authentication key.
            findings_path: Path to ghostwriter_findings.json.
            timeout: Request timeout in seconds.

        Returns:
            True if upload succeeded.
        """
        import urllib.error
        import urllib.request

        if not findings_path.exists():
            logger.warning("ghostwriter.push_no_file", path=str(findings_path))
            return False

        body = findings_path.read_bytes()
        endpoint = f"{url.rstrip('/')}/api/v1/findings/import/"

        try:
            req = urllib.request.Request(endpoint, data=body, method="POST")
            req.add_header("Authorization", f"Bearer {api_key}")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
            logger.info("ghostwriter.push_success", status=status)
            return status < 400
        except urllib.error.HTTPError as exc:
            logger.warning("ghostwriter.push_http_error", status=exc.code)
            return False
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            logger.warning("ghostwriter.push_error", error=str(exc))
            return False
