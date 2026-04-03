"""PlexTrac export adapter — authenticate and push findings."""
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


def _map_risk_score(finding: dict[str, Any]) -> dict[str, Any]:
    """Map Hellcat CVSS/severity to PlexTrac risk_score fields."""
    import contextlib

    risk: dict[str, Any] = {}
    cvss = finding.get("cvss")
    if cvss is not None:
        with contextlib.suppress(ValueError, TypeError):
            risk["cvss"] = float(cvss)
    severity = finding.get("severity", "info")
    severity_map = {
        "critical": 10,
        "high": 8,
        "medium": 5,
        "low": 2,
        "info": 0,
    }
    risk["risk_score"] = severity_map.get(severity, 0)
    return risk


def _finding_to_plextrac(finding: dict[str, Any]) -> dict[str, Any]:
    """Convert a Hellcat finding to a PlexTrac flaw object."""
    risk = _map_risk_score(finding)
    flaw: dict[str, Any] = {
        "title": finding.get("vuln_type", "Unknown"),
        "severity": finding.get("severity", "info"),
        "description": finding.get("description", ""),
        "recommendations": "Review and remediate following OWASP guidelines.",
        "risk_score": risk.get("risk_score", 0),
        "status": "Open",
        "subStatus": "Confirmed",
    }
    if "cvss" in risk:
        flaw["cvss"] = risk["cvss"]
    location = finding.get("source_location", "")
    if location:
        flaw["affected_assets"] = [location]
    evidence = finding.get("witness_payload", "")
    if evidence:
        flaw["evidence"] = evidence
    custom = finding.get("custom_fields")
    if custom:
        flaw["custom_fields"] = custom
    return flaw


@dataclass
class PlexTracExportAdapter(IntegrationAdapter):
    """Export Hellcat findings to a PlexTrac instance."""

    platform: str = "plextrac"
    direction: IntegrationDirection = IntegrationDirection.EXPORT
    required_claims: list[str] = field(default_factory=lambda: ["PT-001", "PT-002"])

    base_url: str = ""
    username: str = ""
    password: str = ""
    client_id: str = ""
    report_id: str = ""
    timeout: int = 30

    async def _authenticate(self, client: httpx.AsyncClient) -> str | None:
        """Authenticate and return bearer token, or None on failure."""
        url = f"{self.base_url.rstrip('/')}/api/v1/authenticate"
        payload = {"username": self.username, "password": self.password}
        try:
            resp = await client.post(url, json=payload)
            if resp.status_code < 400:
                data = resp.json()
                return data.get("token") or data.get("access_token")
        except httpx.HTTPError as exc:
            logger.warning("plextrac.auth_failed", error=str(exc))
        return None

    async def execute(self, context: dict[str, Any]) -> AdapterResult:
        findings: list[dict[str, Any]] = context.get("findings", [])
        base_url = context.get("base_url", self.base_url).rstrip("/")
        client_id = context.get("client_id", self.client_id)
        report_id = context.get("report_id", self.report_id)

        if not base_url or not client_id or not report_id:
            return AdapterResult(
                success=False,
                items_processed=0,
                errors=["Missing base_url, client_id, or report_id."],
            )

        self.base_url = base_url
        errors: list[str] = []
        processed = 0
        flaw_ids: list[str] = []

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            token = await self._authenticate(client)
            if not token:
                return AdapterResult(
                    success=False,
                    items_processed=0,
                    errors=["Authentication failed."],
                )

            headers = {"Authorization": f"Bearer {token}"}
            flaw_url = (
                f"{base_url}/api/v1/client/{client_id}"
                f"/report/{report_id}/flaw"
            )

            for finding in findings:
                flaw = _finding_to_plextrac(finding)
                try:
                    resp = await client.post(
                        flaw_url, json=flaw, headers=headers,
                    )
                    if resp.status_code < 400:
                        processed += 1
                        body = resp.json()
                        fid = body.get("flaw_id") or body.get("id")
                        if fid:
                            flaw_ids.append(str(fid))
                    else:
                        errors.append(
                            f"HTTP {resp.status_code} for "
                            f"{finding.get('vuln_type')}"
                        )
                except httpx.HTTPError as exc:
                    errors.append(str(exc))

        logger.info(
            "plextrac.export_complete",
            processed=processed,
            errors=len(errors),
        )
        return AdapterResult(
            success=len(errors) == 0,
            items_processed=processed,
            errors=errors,
            details={"flaw_ids": flaw_ids},
        )

    async def health_check(self) -> bool:
        if not self.base_url:
            return False
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                token = await self._authenticate(client)
                return token is not None
        except httpx.HTTPError:
            return False
