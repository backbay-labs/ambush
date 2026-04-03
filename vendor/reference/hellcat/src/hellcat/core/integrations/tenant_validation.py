"""Tenant validation registry for gating vendor integrations."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import structlog
import yaml

logger = structlog.get_logger()


class ClaimStatus(StrEnum):
    UNKNOWN = "unknown"
    IN_PROGRESS = "in_progress"
    VALIDATED = "validated"
    BLOCKED = "blocked"
    EXPIRED = "expired"


@dataclass
class TenantClaim:
    """A single tenant-validation claim record."""

    claim_id: str
    platform: str
    status: ClaimStatus
    validated_at: str | None = None
    expires_at: str | None = None
    checked_by: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class TenantValidationRegistry:
    """Registry of tenant-validation claims loaded from YAML."""

    tenant_id: str
    claims: dict[str, TenantClaim] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> TenantValidationRegistry:
        """Load a registry from a YAML file."""
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"Invalid tenant validation file: {path}")

        tenant_id = data.get("tenant_id", "unknown")
        claims: dict[str, TenantClaim] = {}

        for raw in data.get("claims", []):
            claim = TenantClaim(
                claim_id=raw["claim_id"],
                platform=raw.get("platform", ""),
                status=ClaimStatus(raw.get("status", "unknown")),
                validated_at=raw.get("validated_at"),
                expires_at=raw.get("expires_at"),
                checked_by=raw.get("checked_by"),
                evidence_refs=raw.get("evidence_refs", []),
                notes=raw.get("notes", ""),
            )
            claims[claim.claim_id] = claim

        return cls(tenant_id=tenant_id, claims=claims)

    def save(self, path: Path) -> None:
        """Persist the registry to a YAML file."""
        path.parent.mkdir(parents=True, exist_ok=True)

        records: list[dict[str, Any]] = []
        for claim in self.claims.values():
            rec: dict[str, Any] = {
                "claim_id": claim.claim_id,
                "platform": claim.platform,
                "status": str(claim.status),
            }
            if claim.validated_at:
                rec["validated_at"] = claim.validated_at
            if claim.expires_at:
                rec["expires_at"] = claim.expires_at
            if claim.checked_by:
                rec["checked_by"] = claim.checked_by
            if claim.evidence_refs:
                rec["evidence_refs"] = claim.evidence_refs
            if claim.notes:
                rec["notes"] = claim.notes
            records.append(rec)

        payload: dict[str, Any] = {
            "tenant_id": self.tenant_id,
            "claims": records,
        }
        path.write_text(yaml.dump(payload, sort_keys=False), encoding="utf-8")
        logger.info(
            "tenant_validation.saved",
            tenant_id=self.tenant_id,
            path=str(path),
            claims=len(records),
        )

    def is_claim_valid(self, claim_id: str) -> bool:
        """Return True if claim is VALIDATED and not expired."""
        claim = self.claims.get(claim_id)
        if not claim:
            return False
        if claim.status != ClaimStatus.VALIDATED:
            return False
        if claim.expires_at:
            try:
                expiry = datetime.fromisoformat(claim.expires_at)
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=UTC)
                if expiry <= datetime.now(UTC):
                    return False
            except ValueError:
                return False
        return True

    def get_missing_claims(self, required: list[str]) -> list[str]:
        """Return claim IDs that are not in VALIDATED state."""
        return [cid for cid in required if not self.is_claim_valid(cid)]

    def get_expired_claims(self, required: list[str]) -> list[str]:
        """Return claim IDs that exist and are VALIDATED but past expiry."""
        expired: list[str] = []
        for cid in required:
            claim = self.claims.get(cid)
            if not claim or claim.status != ClaimStatus.VALIDATED:
                continue
            if claim.expires_at:
                try:
                    expiry = datetime.fromisoformat(claim.expires_at)
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=UTC)
                    if expiry <= datetime.now(UTC):
                        expired.append(cid)
                except ValueError:
                    expired.append(cid)
        return expired
