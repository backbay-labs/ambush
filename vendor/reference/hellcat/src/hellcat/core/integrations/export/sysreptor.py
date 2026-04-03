"""SysReptor export adapter — create findings via REST API."""
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

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def _finding_to_sysreptor(
    finding: dict[str, Any],
    template_id: str | None = None,
) -> dict[str, Any]:
    """Convert a Hellcat finding to a SysReptor finding payload."""
    payload: dict[str, Any] = {
        "data": {
            "title": finding.get("vuln_type", "Unknown Vulnerability"),
            "severity": _SEVERITY_MAP.get(
                finding.get("severity", "info"), "info",
            ),
            "description": finding.get("description", ""),
            "recommendation": (
                "Review and remediate following OWASP guidelines."
            ),
        },
    }
    location = finding.get("source_location", "")
    if location:
        payload["data"]["affected_components"] = [location]
    evidence = finding.get("witness_payload", "")
    if evidence:
        payload["data"]["evidence"] = evidence
    cvss = finding.get("cvss")
    if cvss is not None:
        payload["data"]["cvss"] = str(cvss)
    if template_id:
        payload["template"] = template_id
    return payload


@dataclass
class SysReptorExportAdapter(IntegrationAdapter):
    """Export Hellcat findings to a SysReptor instance."""

    platform: str = "sysreptor"
    direction: IntegrationDirection = IntegrationDirection.EXPORT
    required_claims: list[str] = field(default_factory=list)

    base_url: str = ""
    api_token: str = ""
    project_id: str = ""
    template_id: str | None = None
    timeout: int = 30

    async def execute(self, context: dict[str, Any]) -> AdapterResult:
        findings: list[dict[str, Any]] = context.get("findings", [])
        base_url = context.get("base_url", self.base_url).rstrip("/")
        api_token = context.get("api_token", self.api_token)
        project_id = context.get("project_id", self.project_id)
        template_id = context.get("template_id", self.template_id)

        if not base_url or not api_token or not project_id:
            return AdapterResult(
                success=False,
                items_processed=0,
                errors=["Missing base_url, api_token, or project_id."],
            )

        errors: list[str] = []
        processed = 0
        finding_ids: list[str] = []

        url = f"{base_url}/api/v1/pentestprojects/{project_id}/findings"
        headers = {"Authorization": f"Bearer {api_token}"}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for finding in findings:
                payload = _finding_to_sysreptor(finding, template_id)
                try:
                    resp = await client.post(
                        url, json=payload, headers=headers,
                    )
                    if resp.status_code < 400:
                        processed += 1
                        body = resp.json()
                        fid = body.get("id")
                        if fid:
                            finding_ids.append(str(fid))
                    else:
                        errors.append(
                            f"HTTP {resp.status_code} for "
                            f"{finding.get('vuln_type')}"
                        )
                except httpx.HTTPError as exc:
                    errors.append(str(exc))

        logger.info(
            "sysreptor.export_complete",
            processed=processed,
            errors=len(errors),
        )
        return AdapterResult(
            success=len(errors) == 0,
            items_processed=processed,
            errors=errors,
            details={"finding_ids": finding_ids},
        )

    async def health_check(self) -> bool:
        base_url = self.base_url.rstrip("/")
        if not base_url or not self.api_token:
            return False
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{base_url}/api/v1/pentestprojects",
                    headers={
                        "Authorization": f"Bearer {self.api_token}",
                    },
                )
                return resp.status_code < 400
        except httpx.HTTPError:
            return False
