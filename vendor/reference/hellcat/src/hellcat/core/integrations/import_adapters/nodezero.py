"""NodeZero import adapter — pull weaknesses and attack paths via GraphQL."""
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

_WEAKNESSES_QUERY = """\
query WeaknessesPage($page: PageInput, $filter: FilterByInput) {
  weaknesses_page(page: $page, filter: $filter) {
    items {
      id
      name
      severity
      description
      cve_ids
      affected_hosts
      category
      attack_path_id
    }
    page_info {
      has_next_page
      end_cursor
    }
  }
}
"""

_NODEZERO_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "INFORMATIONAL": "info",
}


def _normalize_weakness(item: dict[str, Any]) -> dict[str, Any]:
    """Normalize a NodeZero weakness into a graph-compatible finding."""
    raw_severity = item.get("severity", "info")
    severity = _NODEZERO_SEVERITY_MAP.get(
        str(raw_severity).upper(), "info",
    )

    cve_ids: list[str] = []
    for cve in item.get("cve_ids", []):
        if isinstance(cve, str) and cve.startswith("CVE-"):
            cve_ids.append(cve)

    affected_hosts: list[str] = []
    for host in item.get("affected_hosts", []):
        if isinstance(host, str):
            affected_hosts.append(host)

    return {
        "vuln_type": item.get("name", "unknown"),
        "severity": severity,
        "description": item.get("description", ""),
        "cve_ids": cve_ids,
        "affected_hosts": affected_hosts,
        "source": "nodezero",
        "raw_id": item.get("id", ""),
        "category": item.get("category", ""),
        "attack_path_id": item.get("attack_path_id", ""),
    }


@dataclass
class NodeZeroImportAdapter(IntegrationAdapter):
    """Import weaknesses and attack paths from NodeZero via GraphQL."""

    platform: str = "nodezero"
    direction: IntegrationDirection = IntegrationDirection.IMPORT
    required_claims: list[str] = field(
        default_factory=lambda: ["NZ-001", "NZ-002", "NZ-003", "NZ-004"],
    )

    base_url: str = ""
    api_token: str = ""
    page_size: int = 100
    timeout: int = 30

    async def execute(self, context: dict[str, Any]) -> AdapterResult:
        """Import findings from context['payload'] or fetch via GraphQL."""
        payload: dict[str, Any] | None = context.get("payload")

        if payload is not None:
            return self._process_payload(payload)

        base_url = context.get("base_url", self.base_url).rstrip("/")
        api_token = context.get("api_token", self.api_token)
        page_size = context.get("page_size", self.page_size)

        if not base_url or not api_token:
            return AdapterResult(
                success=False,
                items_processed=0,
                errors=["Missing base_url or api_token."],
            )

        all_findings: list[dict[str, Any]] = []
        errors: list[str] = []
        cursor: str | None = None

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                while True:
                    variables: dict[str, Any] = {
                        "page": {"size": page_size},
                    }
                    if cursor:
                        variables["page"]["after"] = cursor

                    gql_url = f"{base_url}/graphql"
                    resp = await client.post(
                        gql_url,
                        json={
                            "query": _WEAKNESSES_QUERY,
                            "variables": variables,
                        },
                        headers={"Authorization": f"Bearer {api_token}"},
                    )
                    if resp.status_code >= 400:
                        errors.append(f"HTTP {resp.status_code} from GraphQL")
                        break

                    body = resp.json()
                    gql_errors = body.get("errors")
                    if gql_errors:
                        errors.extend(
                            e.get("message", str(e)) for e in gql_errors
                        )
                        break

                    data = body.get("data", {})
                    page = data.get("weaknesses_page", {})
                    items = page.get("items", [])
                    for item in items:
                        all_findings.append(_normalize_weakness(item))

                    page_info = page.get("page_info", {})
                    if page_info.get("has_next_page") and page_info.get("end_cursor"):
                        cursor = page_info["end_cursor"]
                    else:
                        break

        except httpx.HTTPError as exc:
            errors.append(f"NodeZero API error: {exc}")

        logger.info(
            "nodezero.import_complete",
            findings=len(all_findings),
            errors=len(errors),
        )
        return AdapterResult(
            success=len(errors) == 0,
            items_processed=len(all_findings),
            errors=errors,
            details={"findings": all_findings},
        )

    def _process_payload(self, payload: dict[str, Any]) -> AdapterResult:
        """Process an already-fetched payload dict."""
        findings: list[dict[str, Any]] = []
        data = payload.get("data", payload)
        page = data.get("weaknesses_page", data)
        items = page.get("items", [])
        for item in items:
            findings.append(_normalize_weakness(item))
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
                resp = await client.post(
                    f"{base_url}/graphql",
                    json={"query": "{ __typename }"},
                    headers={"Authorization": f"Bearer {self.api_token}"},
                )
                return resp.status_code < 400
        except httpx.HTTPError:
            return False
