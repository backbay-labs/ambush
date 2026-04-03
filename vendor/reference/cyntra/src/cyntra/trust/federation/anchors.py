"""Helpers for building CCIP anchor batches."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Iterable

from cyntra.trust.membrane.receipt import RunReceipt


@dataclass
class AnchorBatch:
    """Merkle root + leaf hashes for attestation anchors."""

    root: str
    leaf_hashes: list[str]
    algorithm: str = "sha256_merkle"
    count: int = 0


def build_anchor_batch(receipts: Iterable[RunReceipt]) -> AnchorBatch:
    """Build a merkle root from receipt hashes."""
    leaf_hashes = [receipt.hash() for receipt in receipts]
    root = _build_merkle_root(leaf_hashes)
    return AnchorBatch(root=root, leaf_hashes=leaf_hashes, count=len(leaf_hashes))


def _build_merkle_root(leaf_hashes: list[str]) -> str:
    if not leaf_hashes:
        return "0x" + "0" * 64

    layer = [_normalize_hex(h) for h in leaf_hashes]
    while len(layer) > 1:
        next_layer: list[str] = []
        for idx in range(0, len(layer), 2):
            left = layer[idx]
            right = layer[idx + 1] if idx + 1 < len(layer) else left
            next_layer.append(_hash_pair(left, right))
        layer = next_layer
    return layer[0]


def _hash_pair(left: str, right: str) -> str:
    left_bytes = bytes.fromhex(left.removeprefix("0x"))
    right_bytes = bytes.fromhex(right.removeprefix("0x"))
    return "0x" + sha256(left_bytes + right_bytes).hexdigest()


def _normalize_hex(value: str) -> str:
    if not value.startswith("0x"):
        raise ValueError("Expected 0x-prefixed hex string")
    cleaned = value.lower()
    hex_value = cleaned.removeprefix("0x")
    if len(hex_value) != 64:
        raise ValueError("Expected 32-byte hex string")
    return "0x" + hex_value
