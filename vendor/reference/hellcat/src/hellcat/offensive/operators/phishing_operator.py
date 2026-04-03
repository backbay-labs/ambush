"""Phishing Operator - Social engineering via GoPhish campaigns."""
from __future__ import annotations

import os
from typing import Any

import structlog

from hellcat.core.adapters.base import CostEstimate
from hellcat.offensive.operator_base import (
    AttackManifest,
    OperatorType,
    SecurityOperator,
    VulnerabilityCategory,
)
from hellcat.core.manifests.attack_proof import (
    AttackProof,
    VulnerabilityFinding,
)
from hellcat.offensive.tools.gophish.client import GoPhishClient
from hellcat.offensive.tools.gophish.parser import GoPhishParser

logger = structlog.get_logger()


class PhishingOperator(SecurityOperator):
    """Phishing simulation operator via GoPhish.

    Configures and monitors GoPhish phishing campaigns based on
    engagement scope. Captures credentials and feeds them into
    the TargetGraph for planner credential chaining.
    """

    name = "phishing"
    prompt_templates = ["phishing.txt"]

    @property
    def operator_type(self) -> OperatorType:
        return "exploitation"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "auth"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        policy_gates: list[str] = []

        # Authorization gate: phishing requires authorization_ref
        if not manifest.authorization_ref:
            logger.warning("phishing.no_authorization_ref")
            policy_gates.append("authorization_ref:denied")
            return AttackProof(
                operator_name=self.name,
                target_id=manifest.target_id,
                status="blocked",
                evidence={
                    "error": "Phishing operations require authorization_ref in manifest",
                },
                metadata={
                    "data_source": "gophish",
                    "policy_gates": policy_gates,
                },
            )
        policy_gates.append("authorization_ref:passed")

        client = GoPhishClient()

        if not client.is_configured:
            logger.warning("phishing.gophish_not_configured")
            return AttackProof(
                operator_name=self.name,
                target_id=manifest.target_id,
                status="failed",
                evidence={"error": "GoPhish not configured"},
                metadata={
                    "data_source": "gophish",
                    "policy_gates": policy_gates,
                },
            )

        # Determine campaign mode: create new or poll existing
        campaign_id: int | None = None
        if manifest.toolchain_config:
            campaign_id = manifest.toolchain_config.get("campaign_id")

        campaign_results_data: dict[str, Any] | None = None

        if campaign_id is not None:
            # Poll existing campaign
            try:
                raw_data = client.get_raw_campaign_results(campaign_id)
                result = client.get_campaign_results(campaign_id)
                if result:
                    campaign_results_data = raw_data
                    parsed_result = result
                else:
                    logger.warning(
                        "phishing.campaign_not_found", campaign_id=campaign_id,
                    )
                    return AttackProof(
                        operator_name=self.name,
                        target_id=manifest.target_id,
                        status="failed",
                        evidence={
                            "error": f"Campaign {campaign_id} not found",
                        },
                        metadata={
                            "data_source": "gophish",
                            "policy_gates": policy_gates,
                        },
                    )
            except Exception as exc:
                logger.warning("phishing.poll_error", error=str(exc))
                return AttackProof(
                    operator_name=self.name,
                    target_id=manifest.target_id,
                    status="failed",
                    evidence={"error": f"Campaign poll failed: {exc}"},
                    metadata={
                        "data_source": "gophish",
                        "policy_gates": policy_gates,
                    },
                )
        else:
            # Create a new campaign
            campaign_data: dict[str, Any] = {}
            if manifest.toolchain_config:
                campaign_data = manifest.toolchain_config.get(
                    "campaign_data", {},
                )
            if not campaign_data.get("name"):
                campaign_data["name"] = (
                    f"hellcat-{manifest.strike_cell_id}"
                )

            try:
                campaign = client.create_campaign(campaign_data)
                if not campaign:
                    return AttackProof(
                        operator_name=self.name,
                        target_id=manifest.target_id,
                        status="failed",
                        evidence={"error": "Failed to create campaign"},
                        metadata={
                            "data_source": "gophish",
                            "policy_gates": policy_gates,
                        },
                    )

                # Immediately poll for results
                raw_data = client.get_raw_campaign_results(
                    campaign.campaign_id,
                )
                result = client.get_campaign_results(
                    campaign.campaign_id,
                )
                if result:
                    campaign_results_data = raw_data
                    parsed_result = result
                else:
                    parsed_result = None
            except Exception as exc:
                logger.warning("phishing.create_error", error=str(exc))
                return AttackProof(
                    operator_name=self.name,
                    target_id=manifest.target_id,
                    status="failed",
                    evidence={"error": f"Campaign creation failed: {exc}"},
                    metadata={
                        "data_source": "gophish",
                        "policy_gates": policy_gates,
                    },
                )

        # Build findings from results
        vulns: list[VulnerabilityFinding] = []
        credentials_harvested: list[dict[str, Any]] = []

        if parsed_result:
            if parsed_result.credentials_captured > 0:
                vulns.append(VulnerabilityFinding(
                    vuln_id="PHISH-CRED-001",
                    vuln_type="credential-phishing",
                    severity="high",
                    title=(
                        f"Credentials captured: "
                        f"{parsed_result.credentials_captured} "
                        f"in {parsed_result.campaign_name}"
                    ),
                    description=(
                        f"Phishing campaign '{parsed_result.campaign_name}' "
                        f"captured {parsed_result.credentials_captured} "
                        f"credentials from {parsed_result.targets_sent} targets"
                    ),
                    endpoint=manifest.target_url,
                    evidence_summary=(
                        f"Open rate: {parsed_result.email_open_rate:.0%}, "
                        f"Click rate: {parsed_result.click_rate:.0%}, "
                        f"Capture rate: "
                        f"{parsed_result.credential_capture_rate:.0%}"
                    ),
                    cwe_id="CWE-523",
                ))

                # Extract credentials for graph injection
                if campaign_results_data:
                    creds = GoPhishParser.extract_credentials(
                        campaign_results_data,
                    )
                    for c in creds:
                        credentials_harvested.append({
                            "username": c.username,
                            "email": c.email,
                            "campaign": c.campaign_name,
                            "captured_at": c.captured_at,
                        })

            campaign_stats = {
                "campaign_name": parsed_result.campaign_name,
                "targets_sent": parsed_result.targets_sent,
                "emails_opened": parsed_result.emails_opened,
                "links_clicked": parsed_result.links_clicked,
                "credentials_captured": parsed_result.credentials_captured,
                "reported_count": parsed_result.reported_count,
                "email_open_rate": parsed_result.email_open_rate,
                "click_rate": parsed_result.click_rate,
                "credential_capture_rate": parsed_result.credential_capture_rate,
            }
        else:
            campaign_stats = {}

        total_items = (
            (parsed_result.credentials_captured if parsed_result else 0)
            + len(vulns)
        )

        evidence: dict[str, Any] = {
            "data_source": "gophish",
            "campaign_stats": campaign_stats,
            "credentials_count": len(credentials_harvested),
        }

        status = "success" if vulns else "partial"
        confidence = (
            0.9 if credentials_harvested
            else (0.6 if parsed_result and parsed_result.targets_sent > 0 else 0.3)
        )

        logger.info(
            "phishing.completed",
            campaign=campaign_stats.get("campaign_name", "unknown"),
            credentials=len(credentials_harvested),
            vulns=len(vulns),
        )

        return AttackProof(
            operator_name=self.name,
            target_id=manifest.target_id,
            status=status,
            evidence=evidence,
            vulnerabilities_found=vulns,
            credentials_harvested=credentials_harvested,
            metadata={
                "data_source": "gophish",
                "item_count": total_items,
                "policy_gates": policy_gates,
                "campaign_stats": campaign_stats,
            },
            confidence=confidence,
        )

    async def health_check(self) -> bool:
        return bool(os.environ.get("GOPHISH_API_KEY") and os.environ.get("GOPHISH_URL"))

    def estimate_cost(self, manifest: AttackManifest) -> CostEstimate:
        return CostEstimate(
            estimated_tokens=60_000,
            estimated_cost_usd=0.90,
            model=manifest.model,
        )
