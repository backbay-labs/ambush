"""Pentera import adapter — ingest run/report exports into graph findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from hellcat.core.integrations.base import (
    AdapterResult,
    IntegrationAdapter,
    IntegrationDirection,
)

logger = structlog.get_logger()

_PENTERA_SEVERITY_MAP: dict[str, str] = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
    "Info": "info",
}


def _normalize_achievement(item: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Pentera achievement/vulnerability into a graph finding."""
    raw_severity = item.get("severity", item.get("risk", "info"))
    severity = _PENTERA_SEVERITY_MAP.get(str(raw_severity), "info")

    cve_ids: list[str] = []
    for cve in item.get("cves", item.get("cve_ids", [])):
        if isinstance(cve, str) and cve.startswith("CVE-"):
            cve_ids.append(cve)

    affected_hosts: list[str] = []
    for host in item.get("affected_hosts", item.get("hosts", [])):
        if isinstance(host, str):
            affected_hosts.append(host)
        elif isinstance(host, dict):
            affected_hosts.append(host.get("ip", host.get("hostname", "")))

    return {
        "vuln_type": item.get("name", item.get("technique", "unknown")),
        "severity": severity,
        "description": item.get("description", ""),
        "cve_ids": cve_ids,
        "affected_hosts": affected_hosts,
        "source": "pentera",
        "raw_id": item.get("id", ""),
        "category": item.get("category", ""),
    }


def _parse_pentera_payload(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract findings from a Pentera export payload."""
    findings: list[dict[str, Any]] = []

    for key in ("achievements", "vulnerabilities", "findings"):
        items = data.get(key, [])
        if isinstance(items, list):
            for item in items:
                finding = _normalize_achievement(item)
                if finding["vuln_type"] != "unknown":
                    findings.append(finding)

    # Top-level assets for host context
    assets = data.get("assets", [])
    if isinstance(assets, list) and assets and not findings:
        for asset in assets:
            vulns = asset.get("vulnerabilities", [])
            if isinstance(vulns, list):
                for vuln in vulns:
                    finding = _normalize_achievement(vuln)
                    host = asset.get("ip", asset.get("hostname", ""))
                    if host and host not in finding["affected_hosts"]:
                        finding["affected_hosts"].append(host)
                    if finding["vuln_type"] != "unknown":
                        findings.append(finding)

    return findings


@dataclass
class PenteraImportAdapter(IntegrationAdapter):
    """Import findings from a Pentera run/report export."""

    platform: str = "pentera"
    direction: IntegrationDirection = IntegrationDirection.IMPORT
    required_claims: list[str] = field(
        default_factory=lambda: ["PEN-001", "PEN-002", "PEN-003"],
    )

    base_url: str = ""
    api_token: str = ""
    timeout: int = 30

    async def execute(self, context: dict[str, Any]) -> AdapterResult:
        """Import findings from context['payload'] (dict) or fetch from API."""
        payload: dict[str, Any] | None = context.get("payload")

        if payload is None:
            # Fetch from API
            base_url = context.get("base_url", self.base_url).rstrip("/")
            api_token = context.get("api_token", self.api_token)
            task_run_id = context.get("task_run_id", "")

            if not base_url or not api_token or not task_run_id:
                return AdapterResult(
                    success=False,
                    items_processed=0,
                    errors=["Missing base_url, api_token, or task_run_id."],
                )

            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    url = (
                        f"{base_url}/pentera/api/v1/task_run"
                        f"/{task_run_id}/achievements"
                    )
                    resp = await client.get(
                        url,
                        headers={"Authorization": f"Bearer {api_token}"},
                    )
                    if resp.status_code >= 400:
                        return AdapterResult(
                            success=False,
                            items_processed=0,
                            errors=[f"HTTP {resp.status_code} from Pentera API"],
                        )
                    payload = resp.json()
            except httpx.HTTPError as exc:
                return AdapterResult(
                    success=False,
                    items_processed=0,
                    errors=[f"Pentera API error: {exc}"],
                )

        findings = _parse_pentera_payload(payload or {})
        logger.info(
            "pentera.import_complete",
            findings=len(findings),
        )
        return AdapterResult(
            success=True,
            items_processed=len(findings),
            errors=[],
            details={"findings": findings},
        )

    async def health_check(self) -> bool:
        base_url = self.base_url.rstrip("/")
        if not base_url or not self.api_token:
            return False
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{base_url}/pentera/api/v1/status",
                    headers={"Authorization": f"Bearer {self.api_token}"},
                )
                return resp.status_code < 400
        except httpx.HTTPError:
            return False
