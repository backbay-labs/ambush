"""Sliver C2 Operator - Post-exploitation and lateral movement."""
from __future__ import annotations

import shutil

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
from hellcat.offensive.tools.sliver.client import SliverClient

logger = structlog.get_logger()


class SliverOperator(SecurityOperator):
    """Sliver C2 post-exploitation operator.

    Generates implants for target platforms, manages sessions,
    performs credential harvesting and lateral movement via the
    Sliver C2 framework.
    """

    name = "sliver-c2"
    prompt_templates = ["sliver-c2.txt"]

    @property
    def operator_type(self) -> OperatorType:
        return "exploitation"

    @property
    def vulnerability_category(self) -> VulnerabilityCategory:
        return "general"

    async def execute(self, manifest: AttackManifest) -> AttackProof:
        policy_gates: list[str] = []

        # Authorization gate: C2 operations require authorization_ref
        if not manifest.authorization_ref:
            logger.warning("sliver.no_authorization_ref")
            policy_gates.append("authorization_ref:denied")
            return AttackProof(
                operator_name=self.name,
                target_id=manifest.target_id,
                status="blocked",
                evidence={
                    "error": "C2 operations require authorization_ref in manifest",
                },
                metadata={
                    "data_source": "sliver",
                    "policy_gates": policy_gates,
                },
            )
        policy_gates.append("authorization_ref:passed")

        # Scope check: verify target host is in scope
        from urllib.parse import urlparse

        from hellcat.operators.tools import is_host_allowed

        parsed = urlparse(manifest.target_url)
        target_host = parsed.hostname or manifest.target_url
        target_port = parsed.port
        scope_includes = manifest.scope_includes or []

        if scope_includes:
            in_scope = is_host_allowed(target_host, target_port, scope_includes)
            if not in_scope:
                logger.warning(
                    "sliver.target_not_in_scope",
                    target=target_host,
                    scope=scope_includes,
                )
                policy_gates.append("scope_check:denied")
                return AttackProof(
                    operator_name=self.name,
                    target_id=manifest.target_id,
                    status="blocked",
                    evidence={
                        "error": f"Target {target_host} not in allowed scope",
                    },
                    metadata={
                        "data_source": "sliver",
                        "policy_gates": policy_gates,
                    },
                )
            policy_gates.append("scope_check:passed")

        client = SliverClient()

        if not client.is_available():
            logger.warning("sliver.binary_not_available")
            return AttackProof(
                operator_name=self.name,
                target_id=manifest.target_id,
                status="failed",
                evidence={"error": "sliver-client binary not available"},
                metadata={
                    "data_source": "sliver",
                    "policy_gates": policy_gates,
                },
            )

        vulns: list[VulnerabilityFinding] = []
        session_evidence: list[dict] = []
        beacon_evidence: list[dict] = []
        implant_evidence: list[dict] = []

        # Enumerate existing sessions
        try:
            sessions = client.list_sessions()
            for s in sessions:
                session_evidence.append({
                    "session_id": s.session_id,
                    "name": s.name,
                    "transport": s.transport,
                    "remote_address": s.remote_address,
                    "hostname": s.hostname,
                    "username": s.username,
                    "os": s.os,
                })
        except Exception as exc:
            logger.warning("sliver.sessions_error", error=str(exc))

        # Enumerate existing beacons
        try:
            beacons = client.list_beacons()
            for b in beacons:
                beacon_evidence.append({
                    "beacon_id": b.beacon_id,
                    "name": b.name,
                    "transport": b.transport,
                    "remote_address": b.remote_address,
                    "hostname": b.hostname,
                    "interval": b.interval,
                })
        except Exception as exc:
            logger.warning("sliver.beacons_error", error=str(exc))

        # Check if implant generation is authorized
        generate_implants = False
        if manifest.toolchain_config:
            generate_implants = manifest.toolchain_config.get(
                "generate_implants", False,
            )

        if generate_implants:
            policy_gates.append("implant_generation:authorized")
            try:
                c2_url = manifest.toolchain_config.get(  # type: ignore[union-attr]
                    "c2_url", f"mtls://{target_host}:8888",
                )
                implant = client.generate_implant(c2_url=c2_url)
                if implant:
                    implant_evidence.append({
                        "implant_id": implant.implant_id,
                        "name": implant.name,
                        "os": implant.os,
                        "arch": implant.arch,
                        "format": implant.format,
                        "c2_urls": implant.c2_urls,
                        "is_beacon": implant.is_beacon,
                    })
            except Exception as exc:
                logger.warning("sliver.generate_error", error=str(exc))

        # Build vulnerability findings from sessions
        for i, s_ev in enumerate(session_evidence):
            vulns.append(VulnerabilityFinding(
                vuln_id=f"SLIVER-SESS-{i+1:03d}",
                vuln_type="active-c2-session",
                severity="critical",
                title=f"Active session: {s_ev['name']} on {s_ev['hostname']}",
                description=(
                    f"Active Sliver session {s_ev['session_id']} on "
                    f"{s_ev['hostname']} as {s_ev['username']} "
                    f"via {s_ev['transport']}"
                ),
                endpoint=s_ev.get("remote_address", ""),
                evidence_summary=f"Transport: {s_ev['transport']}, OS: {s_ev['os']}",
            ))

        total_items = (
            len(session_evidence) + len(beacon_evidence) + len(implant_evidence)
        )

        evidence = {
            "data_source": "sliver",
            "sessions": session_evidence,
            "beacons": beacon_evidence,
            "implants": implant_evidence,
            "total_items": total_items,
        }

        status = "success" if total_items > 0 else "partial"
        confidence = 0.9 if session_evidence else (0.6 if beacon_evidence else 0.3)

        logger.info(
            "sliver.completed",
            sessions=len(session_evidence),
            beacons=len(beacon_evidence),
            implants=len(implant_evidence),
        )

        return AttackProof(
            operator_name=self.name,
            target_id=manifest.target_id,
            status=status,
            evidence=evidence,
            vulnerabilities_found=vulns,
            metadata={
                "data_source": "sliver",
                "item_count": total_items,
                "policy_gates": policy_gates,
            },
            confidence=confidence,
        )

    async def health_check(self) -> bool:
        return shutil.which("sliver-client") is not None

    def estimate_cost(self, manifest: AttackManifest) -> CostEstimate:
        return CostEstimate(
            estimated_tokens=100_000,
            estimated_cost_usd=1.50,
            model=manifest.model,
        )
