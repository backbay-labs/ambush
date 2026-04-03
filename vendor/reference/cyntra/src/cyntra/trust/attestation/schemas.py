"""
Attestation schemas backed by Rust cyntra-trust crate.

This module re-exports the Rust types when available, falling back to
pure Python implementations for compatibility and development.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional, Union

# Try to import from Rust bindings
try:
    from cyntra_trust import (
        RekorRef as _RustRekorRef,
        EasRef as _RustEasRef,
        SolanaRef as _RustSolanaRef,
        AttestationBundle as _RustAttestationBundle,
        EasReceiptData as _RustEasReceiptData,
        sha256 as _rust_sha256,
    )
    _RUST_AVAILABLE = True
except ImportError:
    _RUST_AVAILABLE = False


if TYPE_CHECKING or not _RUST_AVAILABLE:
    # Pure Python fallback implementations
    from dataclasses import dataclass, field
    from enum import Enum

    class AttestationType(str, Enum):
        """Type of attestation."""
        REKOR = "rekor"
        EAS = "eas"
        SOLANA = "solana"

    @dataclass
    class RekorRef:
        """Reference to a Rekor transparency log entry."""

        uuid: str
        log_index: int
        integrated_time: datetime
        body_hash: str  # SHA-256 hex
        inclusion_proof: Optional[str] = None
        rekor_url: str = "https://rekor.sigstore.dev"

        def to_dict(self) -> dict:
            return {
                "type": "rekor",
                "uuid": self.uuid,
                "log_index": self.log_index,
                "integrated_time": self.integrated_time.isoformat(),
                "body_hash": self.body_hash,
                "inclusion_proof": self.inclusion_proof,
                "rekor_url": self.rekor_url,
            }

        def to_json(self) -> str:
            return json.dumps(self.to_dict())

        @classmethod
        def from_dict(cls, data: dict) -> RekorRef:
            return cls(
                uuid=data["uuid"],
                log_index=data["log_index"],
                integrated_time=datetime.fromisoformat(data["integrated_time"]),
                body_hash=data["body_hash"],
                inclusion_proof=data.get("inclusion_proof"),
                rekor_url=data.get("rekor_url", "https://rekor.sigstore.dev"),
            )

        @classmethod
        def from_json(cls, json_str: str) -> RekorRef:
            return cls.from_dict(json.loads(json_str))

    @dataclass
    class EasRef:
        """Reference to an EAS attestation on Base/Ethereum."""

        uid: str
        chain_id: int
        schema_uid: str
        attester: str
        recipient: Optional[str] = None
        block_number: int = 0
        tx_hash: str = ""
        timestamp: Optional[datetime] = None

        def to_dict(self) -> dict:
            return {
                "type": "eas",
                "uid": self.uid,
                "chain_id": self.chain_id,
                "schema_uid": self.schema_uid,
                "attester": self.attester,
                "recipient": self.recipient,
                "block_number": self.block_number,
                "tx_hash": self.tx_hash,
                "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            }

        def to_json(self) -> str:
            return json.dumps(self.to_dict())

        @classmethod
        def from_dict(cls, data: dict) -> EasRef:
            ts = data.get("timestamp")
            return cls(
                uid=data["uid"],
                chain_id=data["chain_id"],
                schema_uid=data["schema_uid"],
                attester=data["attester"],
                recipient=data.get("recipient"),
                block_number=data.get("block_number", 0),
                tx_hash=data.get("tx_hash", ""),
                timestamp=datetime.fromisoformat(ts) if ts else None,
            )

        @classmethod
        def from_json(cls, json_str: str) -> EasRef:
            return cls.from_dict(json.loads(json_str))

        @property
        def chain_name(self) -> str:
            return {8453: "base", 84532: "base-sepolia", 1: "ethereum"}.get(self.chain_id, "unknown")

    @dataclass
    class SolanaRef:
        """Reference to a Solana Aegis attestation."""

        signature: str
        slot: int
        cluster: str
        program_id: str
        receipt_pda: str
        block_time: int

        def to_dict(self) -> dict:
            return {
                "type": "solana",
                "signature": self.signature,
                "slot": self.slot,
                "cluster": self.cluster,
                "program_id": self.program_id,
                "receipt_pda": self.receipt_pda,
                "block_time": self.block_time,
            }

        def to_json(self) -> str:
            return json.dumps(self.to_dict())

        @classmethod
        def from_dict(cls, data: dict) -> SolanaRef:
            return cls(
                signature=data["signature"],
                slot=data["slot"],
                cluster=data["cluster"],
                program_id=data["program_id"],
                receipt_pda=data["receipt_pda"],
                block_time=data["block_time"],
            )

        @classmethod
        def from_json(cls, json_str: str) -> SolanaRef:
            return cls.from_dict(json.loads(json_str))

    @dataclass
    class AttestationBundle:
        """Multi-chain attestation bundle."""

        receipt_hash: str
        attestations: list = field(default_factory=list)
        created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

        def add(self, attestation) -> None:
            self.attestations.append(attestation)

        def has_chain(self, chain_id: str) -> bool:
            return any(attestation_chain_id(a) == chain_id for a in self.attestations)

        def get_chain(self, chain_id: str):
            for a in self.attestations:
                if attestation_chain_id(a) == chain_id:
                    return a
            return None

        @property
        def count(self) -> int:
            return len(self.attestations)

        def __len__(self) -> int:
            return len(self.attestations)

        @property
        def chains(self) -> list[str]:
            return [attestation_chain_id(a) for a in self.attestations]

        def add_rekor(self, ref: RekorRef) -> None:
            self.attestations.append(ref)

        def add_eas(self, ref: EasRef) -> None:
            self.attestations.append(ref)

        def add_solana(self, ref: SolanaRef) -> None:
            self.attestations.append(ref)

        def to_dict(self) -> dict:
            return {
                "receipt_hash": self.receipt_hash,
                "attestations": [a.to_dict() for a in self.attestations],
                "created_at": self.created_at.isoformat(),
            }

        def to_json(self) -> str:
            return json.dumps(self.to_dict())

        @classmethod
        def from_dict(cls, data: dict) -> AttestationBundle:
            return cls(
                receipt_hash=data["receipt_hash"],
                attestations=[attestation_from_dict(a) for a in data.get("attestations", [])],
                created_at=datetime.fromisoformat(data["created_at"]),
            )

        @classmethod
        def from_json(cls, json_str: str) -> AttestationBundle:
            return cls.from_dict(json.loads(json_str))

    @dataclass
    class EasReceiptData:
        """CNP Receipt data for EAS attestation."""

        receipt_hash: str
        task_id: str
        worker: str
        passed: bool
        difficulty: int
        token_count: int
        timestamp: int

        def abi_encode(self) -> bytes:
            data = bytearray()
            data.extend(bytes.fromhex(self.receipt_hash.removeprefix("0x")).ljust(32, b'\x00')[:32])
            data.extend(bytes.fromhex(self.task_id.removeprefix("0x")).ljust(32, b'\x00')[:32])
            data.extend(b'\x00' * 12 + bytes.fromhex(self.worker.removeprefix("0x"))[:20])
            data.extend(b'\x00' * 31 + bytes([1 if self.passed else 0]))
            data.extend(self.difficulty.to_bytes(32, 'big'))
            data.extend(self.token_count.to_bytes(32, 'big'))
            data.extend(self.timestamp.to_bytes(32, 'big'))
            return bytes(data)

        def abi_encode_hex(self) -> str:
            return "0x" + self.abi_encode().hex()

        def to_dict(self) -> dict:
            return {
                "receipt_hash": self.receipt_hash,
                "task_id": self.task_id,
                "worker": self.worker,
                "passed": self.passed,
                "difficulty": self.difficulty,
                "token_count": self.token_count,
                "timestamp": self.timestamp,
            }

        def to_json(self) -> str:
            return json.dumps(self.to_dict())

else:
    # Rust-backed implementations via wrappers
    from enum import Enum

    class AttestationType(str, Enum):
        """Type of attestation."""
        REKOR = "rekor"
        EAS = "eas"
        SOLANA = "solana"

    # Re-export Rust types directly
    RekorRef = _RustRekorRef
    EasRef = _RustEasRef
    SolanaRef = _RustSolanaRef
    AttestationBundle = _RustAttestationBundle
    EasReceiptData = _RustEasReceiptData


# Union type for attestation references
AttestationRef = Union[RekorRef, EasRef, SolanaRef]


def attestation_from_dict(data: dict) -> AttestationRef:
    """Create an AttestationRef from a dictionary."""
    att_type = data.get("type")
    if att_type == "rekor":
        return RekorRef.from_json(json.dumps(data)) if _RUST_AVAILABLE else RekorRef.from_dict(data)
    elif att_type == "eas":
        return EasRef.from_json(json.dumps(data)) if _RUST_AVAILABLE else EasRef.from_dict(data)
    elif att_type == "solana":
        return SolanaRef.from_json(json.dumps(data)) if _RUST_AVAILABLE else SolanaRef.from_dict(data)
    else:
        raise ValueError(f"Unknown attestation type: {att_type}")


def attestation_chain_id(ref: AttestationRef) -> str:
    """Get the chain/log identifier for an attestation."""
    if isinstance(ref, RekorRef):
        return "rekor"
    elif isinstance(ref, EasRef):
        return ref.chain_name() if callable(getattr(ref, 'chain_name', None)) else ref.chain_name
    elif isinstance(ref, SolanaRef):
        cluster = ref.cluster
        if cluster == "mainnet-beta":
            return "solana"
        elif cluster == "devnet":
            return "solana-devnet"
        else:
            return f"solana-{cluster}"
    return "unknown"


# Helper to check if Rust backend is available
def is_rust_backend() -> bool:
    """Check if Rust cryptographic backend is available."""
    return _RUST_AVAILABLE


__all__ = [
    "AttestationType",
    "RekorRef",
    "EasRef",
    "SolanaRef",
    "AttestationBundle",
    "EasReceiptData",
    "AttestationRef",
    "attestation_from_dict",
    "attestation_chain_id",
    "is_rust_backend",
]
