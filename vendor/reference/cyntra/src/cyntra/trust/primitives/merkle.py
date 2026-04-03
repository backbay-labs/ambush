"""Merkle tree helpers for ledger event anchoring.

Uses Rust cyntra-trust backend when available for performance.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256 as _py_sha256
from typing import Iterable

from cyntra.trust.ledger.events import LedgerEvent
from cyntra.trust.primitives.canonical_json import canonicalize as canonicalize_json

# Try to import Rust backend
try:
    from cyntra_trust import (
        MerkleTree as _RustMerkleTree,
        MerkleProof as _RustMerkleProof,
        sha256 as _rust_sha256,
    )
    _RUST_AVAILABLE = True
except ImportError:
    _RUST_AVAILABLE = False


@dataclass
class MerkleProof:
    """Merkle inclusion proof for a single event."""

    leaf_hash: str
    siblings: list[str]
    path_bits: list[bool]  # True => sibling is right, False => sibling is left
    root: str

    def verify(self) -> bool:
        """Verify this proof against the stored root."""
        current = self.leaf_hash
        for sibling, sibling_right in zip(self.siblings, self.path_bits):
            if sibling_right:
                current = _hash_pair(current, sibling)
            else:
                current = _hash_pair(sibling, current)
        return current == self.root


class EventMerkleTree:
    """Build Merkle tree from LedgerEvents.
    
    Uses Rust backend when available for core hashing operations.
    """

    ANCHORED_EVENTS = {
        "RUN_STARTED",
        "RUN_COMPLETED",
        "GATE_PASSED",
        "GATE_FAILED",
        "POLICY_VIOLATION",
        "CONTAINMENT_ACTION",
        "VERDICT",
    }

    def __init__(self, events: Iterable[LedgerEvent]) -> None:
        filtered = [
            event for event in events if event.type.name in self.ANCHORED_EVENTS
        ]
        self.leaves = [self._hash_event(event) for event in filtered]
        self._layers: list[list[str]] = []
        self._rust_tree = None
        
        if _RUST_AVAILABLE and self.leaves:
            # Use Rust backend for tree construction
            leaf_bytes = [bytes.fromhex(h.removeprefix("0x")) for h in self.leaves]
            self._rust_tree = _RustMerkleTree.from_hex_leaves(
                [h.removeprefix("0x") for h in self.leaves]
            )
            self.root = self._rust_tree.root().to_hex_prefixed()
        else:
            self.root = self._build_tree()

    def _hash_event(self, event: LedgerEvent) -> str:
        """Hash an event to a leaf."""
        canonical = canonicalize_json(event.to_dict())
        if _RUST_AVAILABLE:
            h = _rust_sha256(canonical.encode("utf-8"))
            return h.to_hex_prefixed()
        return "0x" + _py_sha256(canonical.encode("utf-8")).hexdigest()

    def _build_tree(self) -> str:
        """Build tree using Python fallback."""
        if not self.leaves:
            self._layers = [[]]
            return "0x" + "0" * 64

        layers = [self.leaves]
        while len(layers[-1]) > 1:
            layer = layers[-1]
            next_layer: list[str] = []
            for idx in range(0, len(layer), 2):
                left = layer[idx]
                right = layer[idx + 1] if idx + 1 < len(layer) else left
                next_layer.append(_hash_pair(left, right))
            layers.append(next_layer)
        self._layers = layers
        return layers[-1][0]

    def get_proof(self, event_index: int) -> MerkleProof:
        """Get inclusion proof for a specific event index."""
        if not self.leaves:
            raise IndexError("No leaves available")
        if event_index < 0 or event_index >= len(self.leaves):
            raise IndexError("Event index out of range")

        if _RUST_AVAILABLE and self._rust_tree is not None:
            # Use Rust proof generation
            rust_proof = self._rust_tree.get_proof(event_index)
            # The Rust proof has a different format, we need to adapt
            # For now, verify works on the Rust side
            return _RustMerkleProofWrapper(rust_proof)

        # Python fallback
        siblings: list[str] = []
        path_bits: list[bool] = []
        idx = event_index

        for layer in self._layers[:-1]:
            if idx % 2 == 0:
                sibling_idx = idx + 1 if idx + 1 < len(layer) else idx
                siblings.append(layer[sibling_idx])
                path_bits.append(True)
            else:
                sibling_idx = idx - 1
                siblings.append(layer[sibling_idx])
                path_bits.append(False)
            idx //= 2

        return MerkleProof(
            leaf_hash=self.leaves[event_index],
            siblings=siblings,
            path_bits=path_bits,
            root=self.root,
        )

    @property
    def leaf_count(self) -> int:
        """Get number of leaves in the tree."""
        return len(self.leaves)


class _RustMerkleProofWrapper:
    """Wrapper to make Rust MerkleProof compatible with Python interface."""
    
    def __init__(self, rust_proof):
        self._rust_proof = rust_proof
        self.leaf_hash = rust_proof.leaf_hash.to_hex_prefixed()
        self.root = rust_proof.root.to_hex_prefixed()
        # Note: siblings/path_bits not directly exposed, use verify()
        self.siblings = []
        self.path_bits = []
    
    def verify(self) -> bool:
        """Verify using Rust backend."""
        return self._rust_proof.verify()


def _hash_pair(left: str, right: str) -> str:
    """Hash two nodes together."""
    left_bytes = bytes.fromhex(left.removeprefix("0x"))
    right_bytes = bytes.fromhex(right.removeprefix("0x"))
    if _RUST_AVAILABLE:
        h = _rust_sha256(left_bytes + right_bytes)
        return h.to_hex_prefixed()
    return "0x" + _py_sha256(left_bytes + right_bytes).hexdigest()


def is_rust_backend() -> bool:
    """Check if Rust backend is available."""
    return _RUST_AVAILABLE


__all__ = [
    "MerkleProof",
    "EventMerkleTree",
    "is_rust_backend",
]
