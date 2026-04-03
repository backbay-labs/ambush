"""
Data Availability obligation schemas and bond tracking.

Implements:
- AvailabilityObligation: Requirements for bundle availability
- AvailabilityCheck: Multi-fetcher check results
- DABondRegistry: In-memory bond tracking with slash detection
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AvailabilityStatus(str, Enum):
    """Status of an availability obligation."""

    ACTIVE = "active"  # Within availability window
    EXPIRED = "expired"  # Window closed, bonds released
    SLASHED = "slashed"  # DA failure detected, bond forfeited
    RELEASED = "released"  # Manually released early


@dataclass
class FetcherResult:
    """Result of a single fetcher's attempt to retrieve a bundle."""

    fetcher_id: str
    success: bool
    latency_ms: float
    error: str | None = None
    storage_uri: str | None = None
    content_hash_verified: bool = False
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "fetcher_id": self.fetcher_id,
            "success": self.success,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "storage_uri": self.storage_uri,
            "content_hash_verified": self.content_hash_verified,
            "checked_at": self.checked_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FetcherResult:
        return cls(
            fetcher_id=data["fetcher_id"],
            success=data["success"],
            latency_ms=data["latency_ms"],
            error=data.get("error"),
            storage_uri=data.get("storage_uri"),
            content_hash_verified=data.get("content_hash_verified", False),
            checked_at=datetime.fromisoformat(data["checked_at"]),
        )


@dataclass
class AvailabilityObligation:
    """
    Bundle availability requirements.

    Defines the DA guarantee a bundle provider must maintain:
    - Availability window (e.g., 72 hours post-submission)
    - Minimum fetchers that must succeed (e.g., 3 independent)
    - Storage URIs where bundle is expected to be available
    - Bond amount posted as collateral for the guarantee
    """

    bundle_hash: str  # 0x-prefixed SHA-256 of bundle contents
    availability_window_hours: int  # e.g., 72 hours
    min_fetchers: int  # e.g., 3 independent fetchers must succeed
    storage_uris: list[str]  # IPFS, S3, Arweave URIs
    da_bond_wei: int  # Collateral for DA guarantee
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Computed fields
    obligation_id: str = ""

    def __post_init__(self) -> None:
        if not self.obligation_id:
            import hashlib

            unique_str = f"{self.bundle_hash}:{self.created_at.isoformat()}"
            self.obligation_id = "ob_" + hashlib.sha256(unique_str.encode()).hexdigest()[:16]

    @property
    def expires_at(self) -> datetime:
        """When the availability window closes."""
        return self.created_at + timedelta(hours=self.availability_window_hours)

    @property
    def is_expired(self) -> bool:
        """Check if the availability window has closed."""
        return datetime.now(UTC) > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "bundle_hash": self.bundle_hash,
            "availability_window_hours": self.availability_window_hours,
            "min_fetchers": self.min_fetchers,
            "storage_uris": self.storage_uris,
            "da_bond_wei": self.da_bond_wei,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AvailabilityObligation:
        return cls(
            bundle_hash=data["bundle_hash"],
            availability_window_hours=data["availability_window_hours"],
            min_fetchers=data["min_fetchers"],
            storage_uris=data["storage_uris"],
            da_bond_wei=data["da_bond_wei"],
            created_at=datetime.fromisoformat(data["created_at"]),
            obligation_id=data.get("obligation_id", ""),
        )


@dataclass
class AvailabilityCheck:
    """
    Result of multi-fetcher availability check.

    Records the outcome of checking bundle availability across
    multiple independent fetchers. Used to determine if DA
    obligations are being met.
    """

    obligation_id: str
    bundle_hash: str
    checked_at: datetime
    fetchers: list[FetcherResult]
    required_fetchers: int

    @property
    def successful_fetchers(self) -> int:
        """Count of fetchers that successfully retrieved the bundle."""
        return sum(1 for f in self.fetchers if f.success)

    @property
    def available(self) -> bool:
        """Bundle is available if min_fetchers succeeded."""
        return self.successful_fetchers >= self.required_fetchers

    @property
    def hash_verified(self) -> bool:
        """At least one fetcher verified the content hash."""
        return any(f.content_hash_verified for f in self.fetchers if f.success)

    @property
    def mean_latency_ms(self) -> float:
        """Mean latency across successful fetchers."""
        successful = [f.latency_ms for f in self.fetchers if f.success]
        if not successful:
            return 0.0
        return sum(successful) / len(successful)

    @property
    def latency_by_fetcher(self) -> dict[str, float]:
        """Latency per fetcher."""
        return {f.fetcher_id: f.latency_ms for f in self.fetchers}

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "bundle_hash": self.bundle_hash,
            "checked_at": self.checked_at.isoformat(),
            "fetchers": [f.to_dict() for f in self.fetchers],
            "required_fetchers": self.required_fetchers,
            "successful_fetchers": self.successful_fetchers,
            "available": self.available,
            "hash_verified": self.hash_verified,
            "mean_latency_ms": self.mean_latency_ms,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AvailabilityCheck:
        return cls(
            obligation_id=data["obligation_id"],
            bundle_hash=data["bundle_hash"],
            checked_at=datetime.fromisoformat(data["checked_at"]),
            fetchers=[FetcherResult.from_dict(f) for f in data["fetchers"]],
            required_fetchers=data["required_fetchers"],
        )


@dataclass
class DABondRecord:
    """Record of a DA bond."""

    obligation_id: str
    bundle_hash: str
    bond_wei: int
    provider: str  # Public key of bond poster
    status: AvailabilityStatus
    created_at: datetime
    released_at: datetime | None = None
    slashed_at: datetime | None = None
    slash_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "bundle_hash": self.bundle_hash,
            "bond_wei": self.bond_wei,
            "provider": self.provider,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "released_at": self.released_at.isoformat() if self.released_at else None,
            "slashed_at": self.slashed_at.isoformat() if self.slashed_at else None,
            "slash_reason": self.slash_reason,
        }


class DABondRegistry:
    """
    In-memory DA bond registry.

    Tracks bonds posted for availability obligations.
    Production implementation would use a database.
    """

    def __init__(self) -> None:
        self._bonds: dict[str, DABondRecord] = {}
        self._by_bundle: dict[str, list[str]] = {}  # bundle_hash -> obligation_ids

    def register_bond(
        self,
        obligation: AvailabilityObligation,
        provider: str,
    ) -> DABondRecord:
        """Register a new DA bond for an obligation."""
        record = DABondRecord(
            obligation_id=obligation.obligation_id,
            bundle_hash=obligation.bundle_hash,
            bond_wei=obligation.da_bond_wei,
            provider=provider,
            status=AvailabilityStatus.ACTIVE,
            created_at=datetime.now(UTC),
        )
        self._bonds[obligation.obligation_id] = record

        if obligation.bundle_hash not in self._by_bundle:
            self._by_bundle[obligation.bundle_hash] = []
        self._by_bundle[obligation.bundle_hash].append(obligation.obligation_id)

        logger.info(f"Registered DA bond {obligation.obligation_id}: {obligation.da_bond_wei} wei")
        return record

    def get_bond(self, obligation_id: str) -> DABondRecord | None:
        """Get bond record by obligation ID."""
        return self._bonds.get(obligation_id)

    def get_bonds_for_bundle(self, bundle_hash: str) -> list[DABondRecord]:
        """Get all bonds for a bundle."""
        obligation_ids = self._by_bundle.get(bundle_hash, [])
        return [self._bonds[oid] for oid in obligation_ids if oid in self._bonds]

    def slash_bond(
        self,
        obligation_id: str,
        reason: str,
    ) -> DABondRecord | None:
        """
        Slash a bond due to DA failure.

        Returns the slashed record, or None if not found/already slashed.
        """
        record = self._bonds.get(obligation_id)
        if not record:
            return None

        if record.status != AvailabilityStatus.ACTIVE:
            logger.warning(f"Cannot slash bond {obligation_id}: status is {record.status}")
            return None

        record.status = AvailabilityStatus.SLASHED
        record.slashed_at = datetime.now(UTC)
        record.slash_reason = reason
        logger.warning(f"Slashed DA bond {obligation_id}: {reason}")
        return record

    def release_bond(self, obligation_id: str) -> DABondRecord | None:
        """
        Release a bond after obligation window expires.

        Returns the released record, or None if not found.
        """
        record = self._bonds.get(obligation_id)
        if not record:
            return None

        if record.status != AvailabilityStatus.ACTIVE:
            logger.warning(f"Cannot release bond {obligation_id}: status is {record.status}")
            return None

        record.status = AvailabilityStatus.RELEASED
        record.released_at = datetime.now(UTC)
        logger.info(f"Released DA bond {obligation_id}")
        return record

    def expire_bond(self, obligation_id: str) -> DABondRecord | None:
        """Mark a bond as expired (window closed, no failures)."""
        record = self._bonds.get(obligation_id)
        if not record:
            return None

        if record.status != AvailabilityStatus.ACTIVE:
            return None

        record.status = AvailabilityStatus.EXPIRED
        record.released_at = datetime.now(UTC)
        return record

    @property
    def active_bonds(self) -> list[DABondRecord]:
        """All currently active bonds."""
        return [b for b in self._bonds.values() if b.status == AvailabilityStatus.ACTIVE]

    @property
    def total_bonded_wei(self) -> int:
        """Total wei currently bonded."""
        return sum(b.bond_wei for b in self.active_bonds)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bonds": {k: v.to_dict() for k, v in self._bonds.items()},
            "total_bonded_wei": self.total_bonded_wei,
            "active_count": len(self.active_bonds),
        }


# Default bond amounts by tier
DEFAULT_DA_BOND_WEI = {
    0: 10_000_000_000_000_000,  # 0.01 ETH for T0 (spot-check)
    1: 100_000_000_000_000_000,  # 0.1 ETH for T1 (full replay)
    2: 1_000_000_000_000_000_000,  # 1 ETH for T2 (multi-verifier)
}

# Default availability windows by tier
DEFAULT_AVAILABILITY_HOURS = {
    0: 24,  # 24 hours for T0
    1: 72,  # 72 hours for T1
    2: 168,  # 1 week for T2
}

# Default minimum fetchers
DEFAULT_MIN_FETCHERS = 3
