"""Dradis export adapter — push findings as Dradis issues via REST API."""
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
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def _finding_to_dradis_markup(finding: dict[str, Any]) -> str:
    """Convert a Hellcat finding dict to Dradis textile-style issue markup."""
    title = finding.get("vuln_type", "Unknown Vulnerability")
    severity = _SEVERITY_MAP.get(finding.get("severity", "info"), "Info")
    description = finding.get("description", "")
    location = finding.get("source_location", "")
    evidence = finding.get("witness_payload", "")
    cvss = finding.get("cvss")

    lines = [
        f"#[Title]#\n{title}",
        f"#[Severity]#\n{severity}",
    ]
    if description:
        lines.append(f"#[Description]#\n{description}")
    if location:
        lines.append(f"#[Location]#\n{location}")
    if evidence:
        lines.append(f"#[Evidence]#\n{evidence}")
    if cvss is not None:
        lines.append(f"#[CVSSv3.Score]#\n{cvss}")
    lines.append(
        "#[Recommendation]#\nReview and remediate following OWASP guidelines."
    )
    return "\n\n".join(lines)


@dataclass
class DradisExportAdapter(IntegrationAdapter):
    """Export Hellcat findings to a Dradis instance."""

    platform: str = "dradis"
    direction: IntegrationDirection = IntegrationDirection.EXPORT
    required_claims: list[str] = field(default_factory=list)

    base_url: str = ""
    api_token: str = ""
    project_id: str = ""
    timeout: int = 30

    async def execute(self, context: dict[str, Any]) -> AdapterResult:
        findings: list[dict[str, Any]] = context.get("findings", [])
        base_url = context.get("base_url", self.base_url).rstrip("/")
        api_token = context.get("api_token", self.api_token)
        project_id = context.get("project_id", self.project_id)

        if not base_url or not api_token or not project_id:
            return AdapterResult(
                success=False,
                items_processed=0,
                errors=["Missing base_url, api_token, or project_id."],
            )

        errors: list[str] = []
        processed = 0
        issue_ids: list[int] = []

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for finding in findings:
                markup = _finding_to_dradis_markup(finding)
                url = f"{base_url}/api/issues"
                headers = {
                    "Authorization": f"Token token={api_token}",
                    "Content-Type": "application/json",
                    "Dradis-Project-Id": project_id,
                }
                payload = {"issue": {"text": markup}}
                try:
                    resp = await client.post(
                        url, json=payload, headers=headers,
                    )
                    if resp.status_code < 400:
                        processed += 1
                        body = resp.json()
                        if "id" in body:
                            issue_ids.append(body["id"])
                    else:
                        errors.append(
                            f"HTTP {resp.status_code} for {finding.get('vuln_type')}"
                        )
                except httpx.HTTPError as exc:
                    errors.append(str(exc))

        logger.info(
            "dradis.export_complete",
            processed=processed,
            errors=len(errors),
        )
        return AdapterResult(
            success=len(errors) == 0,
            items_processed=processed,
            errors=errors,
            details={"issue_ids": issue_ids},
        )

    async def health_check(self) -> bool:
        base_url = self.base_url.rstrip("/")
        if not base_url or not self.api_token:
            return False
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{base_url}/api/issues",
                    headers={
                        "Authorization": f"Token token={self.api_token}",
                        "Dradis-Project-Id": self.project_id,
                    },
                )
                return resp.status_code < 400
        except httpx.HTTPError:
            return False
