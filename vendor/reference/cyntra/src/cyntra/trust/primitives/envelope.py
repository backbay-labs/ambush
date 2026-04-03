"""Reference encryption envelope helpers (non-production)."""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from hashlib import sha256
import hmac
from pathlib import Path
from typing import Mapping

from nacl import public as nacl_public
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_scalarmult,
)


DEFAULT_CIPHER = "xchacha20poly1305"
DEFAULT_WRAP_ALG = "x25519-xchacha20poly1305"
DEFAULT_INFO = b"cyntra-envelope"
NONCE_BYTES = 24


@dataclass
class SealedKey:
    """Wrapped data key for a recipient."""

    recipient: str
    alg: str
    encrypted_key: str
    nonce: str
    ephemeral_pubkey: str

    def to_dict(self) -> dict:
        return {
            "recipient": self.recipient,
            "alg": self.alg,
            "encrypted_key": self.encrypted_key,
            "nonce": self.nonce,
            "ephemeral_pubkey": self.ephemeral_pubkey,
        }


@dataclass
class EncryptionEnvelope:
    """Envelope describing encrypted bundle access."""

    version: str
    bundle_hash: str
    cipher: str
    nonce: str
    sealed_keys: list[SealedKey]
    metadata: dict[str, str] | None = None

    def to_dict(self) -> dict:
        payload = {
            "version": self.version,
            "bundle_hash": self.bundle_hash,
            "cipher": self.cipher,
            "nonce": self.nonce,
            "sealed_keys": [entry.to_dict() for entry in self.sealed_keys],
        }
        if self.metadata is not None:
            payload["metadata"] = self.metadata
        return payload

    def to_canonical(self) -> str:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)


def generate_data_key(length: int = 32) -> bytes:
    """Generate a random data key for bundle encryption."""
    if length <= 0:
        raise ValueError("length must be positive")
    return secrets.token_bytes(length)


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """Generate an X25519 private/public keypair."""
    private_key = nacl_public.PrivateKey.generate()
    return private_key.encode(), private_key.public_key.encode()


def create_envelope(
    bundle_hash: str,
    data_key: bytes,
    recipients: Mapping[str, bytes],
    *,
    version: str = "1.0.0",
    cipher: str = DEFAULT_CIPHER,
    wrap_alg: str = DEFAULT_WRAP_ALG,
    metadata: dict[str, str] | None = None,
    nonce: bytes | None = None,
) -> EncryptionEnvelope:
    """Create an encryption envelope with wrapped data keys."""
    if nonce is None:
        nonce = secrets.token_bytes(NONCE_BYTES)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")

    sealed_keys = seal_data_key(
        data_key,
        recipients,
        bundle_hash=bundle_hash,
        wrap_alg=wrap_alg,
    )

    return EncryptionEnvelope(
        version=version,
        bundle_hash=bundle_hash,
        cipher=cipher,
        nonce=nonce_b64,
        sealed_keys=sealed_keys,
        metadata=metadata,
    )


def seal_data_key(
    data_key: bytes,
    recipients: Mapping[str, bytes],
    *,
    bundle_hash: str,
    wrap_alg: str = DEFAULT_WRAP_ALG,
    info: bytes = DEFAULT_INFO,
) -> list[SealedKey]:
    """Wrap a data key for each recipient."""
    if not recipients:
        raise ValueError("recipients must not be empty")
    if not data_key:
        raise ValueError("data_key must not be empty")

    sealed_keys: list[SealedKey] = []

    for recipient, recipient_key in recipients.items():
        recipient_info = info + b":" + recipient.encode("utf-8")
        aad = _build_aad(bundle_hash, recipient)
        wrapped, nonce, ephemeral_pubkey = wrap_key(
            data_key,
            recipient_key,
            bundle_hash=bundle_hash,
            info=recipient_info,
            aad=aad,
        )
        encrypted_key = base64.b64encode(wrapped).decode("ascii")
        nonce_b64 = base64.b64encode(nonce).decode("ascii")
        ephemeral_b64 = base64.b64encode(ephemeral_pubkey).decode("ascii")
        sealed_keys.append(
            SealedKey(
                recipient=recipient,
                alg=wrap_alg,
                encrypted_key=encrypted_key,
                nonce=nonce_b64,
                ephemeral_pubkey=ephemeral_b64,
            )
        )

    return sealed_keys


def unwrap_envelope_key(
    envelope: EncryptionEnvelope,
    *,
    recipient: str,
    recipient_private_key: bytes,
    info: bytes = DEFAULT_INFO,
) -> bytes:
    """Unwrap a data key for a recipient from an envelope."""
    match = next(
        (entry for entry in envelope.sealed_keys if entry.recipient == recipient), None
    )
    if match is None:
        raise KeyError(f"recipient {recipient} not found in envelope")
    if match.alg != DEFAULT_WRAP_ALG:
        raise ValueError(f"unsupported key wrap alg: {match.alg}")

    wrapped = base64.b64decode(match.encrypted_key.encode("ascii"))
    nonce = base64.b64decode(match.nonce.encode("ascii"))
    ephemeral_pubkey = base64.b64decode(match.ephemeral_pubkey.encode("ascii"))
    aad = _build_aad(envelope.bundle_hash, recipient)
    recipient_info = info + b":" + recipient.encode("utf-8")
    return unwrap_key(
        wrapped,
        recipient_private_key,
        ephemeral_public_key=ephemeral_pubkey,
        nonce=nonce,
        bundle_hash=envelope.bundle_hash,
        info=recipient_info,
        aad=aad,
    )


def wrap_key(
    data_key: bytes,
    recipient_public_key: bytes,
    *,
    bundle_hash: str,
    info: bytes,
    aad: bytes | None = None,
) -> tuple[bytes, bytes, bytes]:
    """Wrap a data key with X25519 + XChaCha20-Poly1305."""
    if not data_key:
        raise ValueError("data_key must not be empty")
    if not recipient_public_key:
        raise ValueError("recipient_public_key must not be empty")

    recipient_public = nacl_public.PublicKey(recipient_public_key)
    ephemeral_private = nacl_public.PrivateKey.generate()
    shared_secret = crypto_scalarmult(
        ephemeral_private.encode(), recipient_public.encode()
    )
    derived_key = _hkdf_sha256(
        shared_secret,
        salt=_salt_from_bundle_hash(bundle_hash),
        info=info,
        length=32,
    )

    nonce = secrets.token_bytes(NONCE_BYTES)
    aad_bytes = aad or b""
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        data_key, aad_bytes, nonce, derived_key
    )
    ephemeral_public = ephemeral_private.public_key.encode()
    return ciphertext, nonce, ephemeral_public


def unwrap_key(
    wrapped_key: bytes,
    recipient_private_key: bytes,
    *,
    ephemeral_public_key: bytes,
    nonce: bytes,
    bundle_hash: str,
    info: bytes,
    aad: bytes | None = None,
) -> bytes:
    """Unwrap a data key wrapped with X25519 + XChaCha20-Poly1305."""
    if not wrapped_key:
        raise ValueError("wrapped_key must not be empty")
    if not recipient_private_key:
        raise ValueError("recipient_private_key must not be empty")
    if not ephemeral_public_key:
        raise ValueError("ephemeral_public_key must not be empty")
    if not nonce:
        raise ValueError("nonce must not be empty")

    recipient_private = nacl_public.PrivateKey(recipient_private_key)
    ephemeral_public = nacl_public.PublicKey(ephemeral_public_key)
    shared_secret = crypto_scalarmult(
        recipient_private.encode(), ephemeral_public.encode()
    )
    derived_key = _hkdf_sha256(
        shared_secret,
        salt=_salt_from_bundle_hash(bundle_hash),
        info=info,
        length=32,
    )
    aad_bytes = aad or b""
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        wrapped_key, aad_bytes, nonce, derived_key
    )


def _salt_from_bundle_hash(bundle_hash: str) -> bytes:
    normalized = bundle_hash.lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    try:
        if normalized:
            return bytes.fromhex(normalized)
    except ValueError:
        pass
    return sha256(bundle_hash.encode("utf-8")).digest()


def _hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    if length <= 0:
        raise ValueError("length must be positive")
    if not salt:
        salt = bytes(sha256().digest_size)

    prk = hmac.new(salt, ikm, sha256).digest()
    okm = b""
    t = b""
    counter = 1

    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), sha256).digest()
        okm += t
        counter += 1

    return okm[:length]


def _build_aad(bundle_hash: str, recipient: str) -> bytes:
    return f"{bundle_hash}:{recipient}".encode("utf-8")


__all__ = [
    "EncryptionEnvelope",
    "SealedKey",
    "create_envelope",
    "generate_data_key",
    "generate_x25519_keypair",
    "seal_data_key",
    "unwrap_envelope_key",
    "wrap_key",
    "unwrap_key",
]
