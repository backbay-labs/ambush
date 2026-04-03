"""
Tier-dependent verification work products.

Defines the deliverables required from verifiers at each tier:
- Tier 0 (Spot-check): Hash verification only
- Tier 1 (Full replay): Gate re-execution with transcript
- Tier 2 (Multi-verifier): Quorum with anti-correlation
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class GateOutcome(str, Enum):
    """Outcome of a gate replay."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class GateReplayResult:
    """Result of replaying a single gate."""

    gate_id: str
    gate_type: str
    original_outcome: GateOutcome
    replayed_outcome: GateOutcome
    match: bool
    replay_time_ms: float
    original_hash: str | None = None  # Hash of original output
    replayed_hash: str | None = None  # Hash of replayed output
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_deterministic(self) -> bool:
        """Gate produced deterministic results."""
        return self.match and self.original_hash == self.replayed_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "gate_type": self.gate_type,
            "original_outcome": self.original_outcome.value,
            "replayed_outcome": self.replayed_outcome.value,
            "match": self.match,
            "replay_time_ms": self.replay_time_ms,
            "original_hash": self.original_hash,
            "replayed_hash": self.replayed_hash,
            "error": self.error,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GateReplayResult:
        return cls(
            gate_id=data["gate_id"],
            gate_type=data["gate_type"],
            original_outcome=GateOutcome(data["original_outcome"]),
            replayed_outcome=GateOutcome(data["replayed_outcome"]),
            match=data["match"],
            replay_time_ms=data["replay_time_ms"],
            original_hash=data.get("original_hash"),
            replayed_hash=data.get("replayed_hash"),
            error=data.get("error"),
            details=data.get("details", {}),
        )


@dataclass
class Tier0WorkProduct:
    """
    Spot-check work product: hash verification only.

    Minimal verification that confirms:
    - Receipt hash matches bundle contents
    - Manifest hash matches file listing
    """

    receipt_hash_verified: bool
    manifest_hash_verified: bool
    verification_time_ms: float
    bundle_hash: str
    verifier_pubkey: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_valid(self) -> bool:
        """Work product passes T0 requirements."""
        return self.receipt_hash_verified and self.manifest_hash_verified

    def compute_commitment(self) -> str:
        """Compute commitment hash for this work product."""
        content = f"{self.bundle_hash}:{self.receipt_hash_verified}:{self.manifest_hash_verified}"
        return "0x" + hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": 0,
            "receipt_hash_verified": self.receipt_hash_verified,
            "manifest_hash_verified": self.manifest_hash_verified,
            "verification_time_ms": self.verification_time_ms,
            "bundle_hash": self.bundle_hash,
            "verifier_pubkey": self.verifier_pubkey,
            "created_at": self.created_at.isoformat(),
            "commitment": self.compute_commitment(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Tier0WorkProduct:
        return cls(
            receipt_hash_verified=data["receipt_hash_verified"],
            manifest_hash_verified=data["manifest_hash_verified"],
            verification_time_ms=data["verification_time_ms"],
            bundle_hash=data["bundle_hash"],
            verifier_pubkey=data["verifier_pubkey"],
            created_at=datetime.fromisoformat(data["created_at"]),
        )


@dataclass
class Tier1WorkProduct:
    """
    Full replay work product: gate re-execution.

    Includes T0 verification plus:
    - Full replay of all gates
    - Transcript commitment for auditability
    """

    tier0: Tier0WorkProduct
    gates_replayed: list[GateReplayResult]
    replay_transcript_hash: str
    total_replay_time_ms: float
    bundle_hash: str
    verifier_pubkey: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def gates_matched(self) -> int:
        """Count of gates with matching outcomes."""
        return sum(1 for g in self.gates_replayed if g.match)

    @property
    def gates_mismatched(self) -> int:
        """Count of gates with mismatched outcomes."""
        return len(self.gates_replayed) - self.gates_matched

    @property
    def all_gates_match(self) -> bool:
        """All replayed gates produced matching outcomes."""
        return all(g.match for g in self.gates_replayed)

    @property
    def is_valid(self) -> bool:
        """Work product passes T1 requirements."""
        return self.tier0.is_valid and self.all_gates_match

    def compute_commitment(self) -> str:
        """Compute commitment hash for this work product."""
        gate_hashes = [g.replayed_hash or "" for g in self.gates_replayed]
        content = f"{self.tier0.compute_commitment()}:{':'.join(gate_hashes)}:{self.replay_transcript_hash}"
        return "0x" + hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": 1,
            "tier0": self.tier0.to_dict(),
            "gates_replayed": [g.to_dict() for g in self.gates_replayed],
            "gates_matched": self.gates_matched,
            "gates_mismatched": self.gates_mismatched,
            "replay_transcript_hash": self.replay_transcript_hash,
            "total_replay_time_ms": self.total_replay_time_ms,
            "bundle_hash": self.bundle_hash,
            "verifier_pubkey": self.verifier_pubkey,
            "created_at": self.created_at.isoformat(),
            "commitment": self.compute_commitment(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Tier1WorkProduct:
        return cls(
            tier0=Tier0WorkProduct.from_dict(data["tier0"]),
            gates_replayed=[GateReplayResult.from_dict(g) for g in data["gates_replayed"]],
            replay_transcript_hash=data["replay_transcript_hash"],
            total_replay_time_ms=data["total_replay_time_ms"],
            bundle_hash=data["bundle_hash"],
            verifier_pubkey=data["verifier_pubkey"],
            created_at=datetime.fromisoformat(data["created_at"]),
        )


@dataclass
class Tier2WorkProduct:
    """
    Multi-verifier work product: quorum with anti-correlation.

    Aggregates T1 results from multiple independent verifiers
    with anti-correlation checks to detect collusion.
    """

    tier1_results: list[Tier1WorkProduct]
    quorum_size: int
    agreement_ratio: float
    verifier_pubkeys: list[str]
    bundle_hash: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Anti-correlation metrics
    verifier_overlap_checked: bool = False
    recent_agreement_rate: float | None = None  # Historical agreement between these verifiers

    @property
    def has_quorum(self) -> bool:
        """Sufficient verifiers participated."""
        return len(self.tier1_results) >= self.quorum_size

    @property
    def has_consensus(self) -> bool:
        """Verifiers reached consensus (high agreement)."""
        return self.agreement_ratio >= 0.67  # 2/3 agreement threshold

    @property
    def is_valid(self) -> bool:
        """Work product passes T2 requirements."""
        return self.has_quorum and self.has_consensus and all(t.is_valid for t in self.tier1_results)

    @property
    def majority_outcome_is_pass(self) -> bool:
        """Majority of verifiers voted PASS."""
        passes = sum(1 for t in self.tier1_results if t.all_gates_match)
        return passes > len(self.tier1_results) / 2

    def compute_commitment(self) -> str:
        """Compute commitment hash for this work product."""
        commitments = [t.compute_commitment() for t in self.tier1_results]
        content = f"{self.bundle_hash}:{':'.join(sorted(commitments))}:{self.agreement_ratio}"
        return "0x" + hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": 2,
            "tier1_results": [t.to_dict() for t in self.tier1_results],
            "quorum_size": self.quorum_size,
            "agreement_ratio": self.agreement_ratio,
            "verifier_pubkeys": self.verifier_pubkeys,
            "bundle_hash": self.bundle_hash,
            "created_at": self.created_at.isoformat(),
            "has_quorum": self.has_quorum,
            "has_consensus": self.has_consensus,
            "majority_outcome_is_pass": self.majority_outcome_is_pass,
            "verifier_overlap_checked": self.verifier_overlap_checked,
            "recent_agreement_rate": self.recent_agreement_rate,
            "commitment": self.compute_commitment(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Tier2WorkProduct:
        wp = cls(
            tier1_results=[Tier1WorkProduct.from_dict(t) for t in data["tier1_results"]],
            quorum_size=data["quorum_size"],
            agreement_ratio=data["agreement_ratio"],
            verifier_pubkeys=data["verifier_pubkeys"],
            bundle_hash=data["bundle_hash"],
            created_at=datetime.fromisoformat(data["created_at"]),
        )
        wp.verifier_overlap_checked = data.get("verifier_overlap_checked", False)
        wp.recent_agreement_rate = data.get("recent_agreement_rate")
        return wp


class WorkProductValidationError(Exception):
    """Work product validation failed."""

    pass


@dataclass
class ValidationResult:
    """Result of work product validation."""

    valid: bool
    tier: int
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "tier": self.tier,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class WorkProductValidator:
    """
    Validates work products against tier requirements.

    Checks:
    - Required fields are present
    - Hash commitments are valid
    - Anti-correlation constraints for T2+
    """

    def __init__(
        self,
        min_quorum_t2: int = 3,
        min_agreement_t2: float = 0.67,
        max_recent_agreement_t2: float = 0.95,  # Flag potential collusion
    ) -> None:
        self.min_quorum_t2 = min_quorum_t2
        self.min_agreement_t2 = min_agreement_t2
        self.max_recent_agreement_t2 = max_recent_agreement_t2

    def validate_t0(self, wp: Tier0WorkProduct) -> ValidationResult:
        """Validate a T0 work product."""
        errors: list[str] = []
        warnings: list[str] = []

        if not wp.receipt_hash_verified:
            errors.append("Receipt hash not verified")

        if not wp.manifest_hash_verified:
            errors.append("Manifest hash not verified")

        if wp.verification_time_ms <= 0:
            warnings.append("Invalid verification time")

        if not wp.bundle_hash:
            errors.append("Missing bundle hash")

        if not wp.verifier_pubkey:
            errors.append("Missing verifier public key")

        return ValidationResult(
            valid=len(errors) == 0,
            tier=0,
            errors=errors,
            warnings=warnings,
        )

    def validate_t1(self, wp: Tier1WorkProduct) -> ValidationResult:
        """Validate a T1 work product."""
        # First validate embedded T0
        t0_result = self.validate_t0(wp.tier0)
        errors = list(t0_result.errors)
        warnings = list(t0_result.warnings)

        if not wp.gates_replayed:
            errors.append("No gates replayed")

        for gate in wp.gates_replayed:
            if not gate.match:
                errors.append(f"Gate {gate.gate_id} outcome mismatch: {gate.original_outcome} != {gate.replayed_outcome}")
            if gate.error:
                warnings.append(f"Gate {gate.gate_id} replay error: {gate.error}")

        if not wp.replay_transcript_hash:
            errors.append("Missing replay transcript hash")

        if wp.total_replay_time_ms <= 0:
            warnings.append("Invalid total replay time")

        return ValidationResult(
            valid=len(errors) == 0,
            tier=1,
            errors=errors,
            warnings=warnings,
        )

    def validate_t2(self, wp: Tier2WorkProduct) -> ValidationResult:
        """Validate a T2 work product."""
        errors: list[str] = []
        warnings: list[str] = []

        # Check quorum
        if len(wp.tier1_results) < self.min_quorum_t2:
            errors.append(f"Insufficient quorum: {len(wp.tier1_results)} < {self.min_quorum_t2}")

        # Check agreement
        if wp.agreement_ratio < self.min_agreement_t2:
            errors.append(f"Insufficient agreement: {wp.agreement_ratio:.2f} < {self.min_agreement_t2:.2f}")

        # Validate each T1 result
        for i, t1 in enumerate(wp.tier1_results):
            t1_result = self.validate_t1(t1)
            if not t1_result.valid:
                errors.append(f"T1 result {i} invalid: {t1_result.errors}")
            warnings.extend(t1_result.warnings)

        # Check for unique verifiers
        if len(set(wp.verifier_pubkeys)) != len(wp.verifier_pubkeys):
            errors.append("Duplicate verifier public keys")

        # Anti-correlation check
        if (
            wp.recent_agreement_rate is not None
            and wp.recent_agreement_rate > self.max_recent_agreement_t2
        ):
            warnings.append(
                f"High historical agreement ({wp.recent_agreement_rate:.2f}): "
                "possible verifier collusion"
            )

        return ValidationResult(
            valid=len(errors) == 0,
            tier=2,
            errors=errors,
            warnings=warnings,
        )

    def validate(self, wp: Tier0WorkProduct | Tier1WorkProduct | Tier2WorkProduct) -> ValidationResult:
        """Validate a work product of any tier."""
        if isinstance(wp, Tier2WorkProduct):
            return self.validate_t2(wp)
        elif isinstance(wp, Tier1WorkProduct):
            return self.validate_t1(wp)
        elif isinstance(wp, Tier0WorkProduct):
            return self.validate_t0(wp)
        else:
            raise WorkProductValidationError(f"Unknown work product type: {type(wp)}")


def generate_checklist(tier: int) -> list[str]:
    """
    Generate a verification checklist for a given tier.

    Used for manual verification guidance.
    """
    base_checklist = [
        "[ ] Verify receipt.json exists and is valid JSON",
        "[ ] Compute receipt hash using CCJ v1 canonicalization",
        "[ ] Verify manifest.json lists all bundle files",
        "[ ] Compute manifest hash and compare to receipt.manifest_hash",
    ]

    if tier == 0:
        return base_checklist

    tier1_additions = [
        "[ ] For each gate in proof.json:",
        "    [ ] Re-execute gate command with bundle inputs",
        "    [ ] Compare exit code to original",
        "    [ ] Compare output hash to original (if deterministic)",
        "[ ] Record total replay time",
        "[ ] Generate replay transcript with all outputs",
        "[ ] Compute transcript commitment hash",
    ]

    if tier == 1:
        return base_checklist + tier1_additions

    tier2_additions = [
        "[ ] Collect T1 results from N independent verifiers",
        "[ ] Verify verifiers are distinct entities (pubkey check)",
        "[ ] Compute agreement ratio across verifiers",
        "[ ] Check anti-correlation: verifier pairs should not always agree",
        "[ ] Verify quorum threshold is met",
        "[ ] Generate aggregate commitment",
    ]

    return base_checklist + tier1_additions + tier2_additions


# Default configurations
DEFAULT_QUORUM_SIZE = {
    0: 1,  # T0: single verifier
    1: 1,  # T1: single verifier
    2: 3,  # T2: 3-of-5 typical
}

DEFAULT_AGREEMENT_THRESHOLD = {
    2: 0.67,  # 2/3 agreement for T2
}
