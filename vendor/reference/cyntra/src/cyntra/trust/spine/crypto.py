"""Spine cryptography helpers.

Implements the Spine v1 hashing/signature rules from:
- `docs/specs/cyntra-aegis-spine.md`

Key points:
- `envelope_hash = sha256(CCJ(envelope_without_signature_and_envelope_hash))`
- `signature = Ed25519.sign(sk, CCJ(envelope_without_signature_and_envelope_hash))`
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from cyntra.trust.primitives.canonical_json import canonicalize as canonicalize_json


def sha256_hex_prefixed(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()


def _strip_0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


def issuer_from_public_key_hex(public_key_hex: str) -> str:
    return f"aegis:ed25519:{_strip_0x(public_key_hex).lower()}"


def parse_issuer(issuer: str) -> str:
    """Return the Ed25519 public key hex (no 0x) from an issuer string."""
    prefix = "aegis:ed25519:"
    if not issuer.startswith(prefix):
        raise ValueError(f"Unsupported issuer format: {issuer}")
    return issuer[len(prefix) :].lower()


@dataclass(frozen=True)
class Ed25519Keypair:
    signing_key: SigningKey

    @property
    def verify_key(self) -> VerifyKey:
        return self.signing_key.verify_key

    @property
    def public_key_hex(self) -> str:
        return self.verify_key.encode(encoder=HexEncoder).decode().lower()

    @classmethod
    def generate(cls) -> "Ed25519Keypair":
        return cls(signing_key=SigningKey.generate())

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> "Ed25519Keypair":
        seed_bytes = bytes.fromhex(_strip_0x(seed_hex))
        return cls(signing_key=SigningKey(seed_bytes))

    @classmethod
    def load_or_generate(cls, path: Path) -> "Ed25519Keypair":
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            return cls.from_seed_hex(path.read_text().strip())
        keypair = cls.generate()
        seed_hex = keypair.signing_key.encode(encoder=HexEncoder).decode()
        path.write_text(seed_hex)
        return keypair

    def sign(self, data: bytes) -> str:
        sig = self.signing_key.sign(data).signature
        return "0x" + sig.hex()


def canonical_bytes_for_envelope(envelope_obj: dict[str, Any]) -> bytes:
    """Canonical bytes used by Spine v1 for envelope hashing/signing."""
    unsigned = dict(envelope_obj)
    unsigned.pop("signature", None)
    unsigned.pop("envelope_hash", None)
    return canonicalize_json(unsigned).encode("utf-8")


def canonical_bytes_without_signature(obj: dict[str, Any]) -> bytes:
    """Canonical bytes for signing objects that only exclude `signature`."""
    unsigned = dict(obj)
    unsigned.pop("signature", None)
    return canonicalize_json(unsigned).encode("utf-8")


def compute_envelope_hash(envelope_obj: dict[str, Any]) -> str:
    return sha256_hex_prefixed(canonical_bytes_for_envelope(envelope_obj))


def sign_envelope(envelope_obj: dict[str, Any], keypair: Ed25519Keypair) -> str:
    return keypair.sign(canonical_bytes_for_envelope(envelope_obj))


def verify_envelope_signature(envelope_obj: dict[str, Any]) -> bool:
    """Verify an envelope signature against its issuer."""
    try:
        issuer = envelope_obj.get("issuer", "")
        pub_hex = parse_issuer(issuer)
        verify_key = VerifyKey(bytes.fromhex(pub_hex))
        sig_hex = _strip_0x(str(envelope_obj.get("signature", "")))
        verify_key.verify(canonical_bytes_for_envelope(envelope_obj), bytes.fromhex(sig_hex))
        return True
    except (ValueError, BadSignatureError, TypeError):
        return False


def sign_by_issuer(obj: dict[str, Any], keypair: Ed25519Keypair) -> str:
    """Sign a Spine object that has an `issuer` field (eg head announcements)."""
    return keypair.sign(canonical_bytes_without_signature(obj))


def verify_signature_by_issuer(obj: dict[str, Any]) -> bool:
    """Verify a Spine object signature against its `issuer` field."""
    try:
        issuer = obj.get("issuer", "")
        pub_hex = parse_issuer(issuer)
        verify_key = VerifyKey(bytes.fromhex(pub_hex))
        sig_hex = _strip_0x(str(obj.get("signature", "")))
        verify_key.verify(canonical_bytes_without_signature(obj), bytes.fromhex(sig_hex))
        return True
    except (ValueError, BadSignatureError, TypeError):
        return False
