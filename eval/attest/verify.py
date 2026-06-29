"""`ambush verify` prototype -- proves the headline-demo's verifier is real, not vapor.

STATUS: stub interface. For one full eval run we emit each adjudicated cluster as an
in-toto Statement, hash-chain the bundle with a Merkle tree, and sign the root with
Ed25519 -- reusing the REAL engine crypto (not the absent Chio):
    engine/crates/swarm-crypto/src/lib.rs   -> Ed25519Signer, canonical_json_bytes, sha256_hex
    engine/crates/swarm-crypto/src/merkle.rs -> MerkleTree::from_leaves, inclusion_proof, verify
`ambush verify` re-derives the Merkle root and checks the signature on a CLEAN machine.
This is a side-quest (not part of GO/KILL) that de-risks the Pro 'Export Attestation' feature.

Two viable implementations: (a) shell out to a tiny Rust `attest` binary built from the
engine crate; (b) reimplement Ed25519+Merkle over canonical JSON in python (cryptography
lib) matching the engine's canonicalization exactly. (a) keeps one source of truth.
"""

from __future__ import annotations

from typing import Any


def build_in_toto_statement(cluster: dict) -> dict[str, Any]:  # pragma: no cover
    """Wrap one adjudicated finding-cluster as an in-toto Statement (predicate type
    'Vulnerability'/'TestResult'; embed SARIF for Semgrep corroboration)."""
    raise NotImplementedError("stub: map a cluster to an in-toto Statement")


def sign_bundle(statements: list[dict], signing_key_path: str) -> dict[str, Any]:  # pragma: no cover
    """Merkle-chain the statements and Ed25519-sign the root via the engine crypto.
    Shell out to a Rust `attest` binary built from engine/crates/swarm-crypto."""
    raise NotImplementedError("stub: call engine swarm-crypto to build + sign the bundle")


def verify_bundle(bundle_path: str) -> bool:  # pragma: no cover
    """Re-derive the Merkle root and verify the Ed25519 signature offline -- the
    `ambush verify` command. Returns True iff the chain is intact and untampered."""
    raise NotImplementedError("stub: re-derive Merkle root + verify Ed25519 signature")
