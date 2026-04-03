"""
Rekor transparency log client.

Provides async HTTP client for interacting with Sigstore Rekor:
- Publishing hashedrekord entries
- Retrieving entries by UUID or log index
- Verifying inclusion proofs
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import httpx
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

from cyntra.trust.attestation.schemas import RekorRef


DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"


@dataclass
class RekorLogEntry:
    """Log entry returned by Rekor API."""

    uuid: str
    body: str  # base64-encoded
    log_index: int
    integrated_time: int  # Unix timestamp
    log_id: str
    inclusion_proof: Optional[dict] = None
    signed_entry_timestamp: Optional[str] = None


class RekorClient:
    """Async HTTP client for Rekor transparency log."""

    def __init__(self, base_url: str = DEFAULT_REKOR_URL):
        self.base_url = base_url.rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> RekorClient:
        self._client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, *args) -> None:
        if self._client:
            await self._client.aclose()

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def publish(
        self,
        hash_hex: str,
        signing_key: SigningKey,
    ) -> RekorRef:
        """
        Publish a hashedrekord entry to Rekor.

        Args:
            hash_hex: SHA-256 hash to log (hex-encoded, with or without 0x prefix)
            signing_key: Ed25519 signing key

        Returns:
            RekorRef with entry details
        """
        client = await self._ensure_client()

        # Normalize hash
        hash_hex = hash_hex.removeprefix("0x")
        hash_bytes = bytes.fromhex(hash_hex)

        # Sign the hash
        signature = signing_key.sign(hash_bytes, encoder=RawEncoder)
        public_key = signing_key.verify_key

        # Build the hashedrekord entry
        entry = {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": hash_hex,
                    },
                },
                "signature": {
                    "content": base64.b64encode(signature.signature).decode(),
                    "publicKey": {
                        "content": base64.b64encode(bytes(public_key)).decode(),
                    },
                },
            },
        }

        # Submit to Rekor
        url = f"{self.base_url}/api/v1/log/entries"
        response = await client.post(url, json=entry)
        response.raise_for_status()

        # Parse response (map of UUID -> entry)
        entries = response.json()
        uuid, entry_data = next(iter(entries.items()))

        # Extract verification info
        verification = entry_data.get("verification", {})
        inclusion_proof = verification.get("inclusionProof")

        return RekorRef(
            uuid=uuid,
            log_index=entry_data["logIndex"],
            integrated_time=datetime.fromtimestamp(
                entry_data["integratedTime"], tz=timezone.utc
            ),
            body_hash=hashlib.sha256(entry_data["body"].encode()).hexdigest(),
            inclusion_proof=json.dumps(inclusion_proof) if inclusion_proof else None,
            rekor_url=self.base_url,
        )

    async def get_by_uuid(self, uuid: str) -> RekorLogEntry:
        """Get an entry by UUID."""
        client = await self._ensure_client()
        url = f"{self.base_url}/api/v1/log/entries/{uuid}"
        response = await client.get(url)
        response.raise_for_status()

        entries = response.json()
        _, entry_data = next(iter(entries.items()))

        verification = entry_data.get("verification", {})
        return RekorLogEntry(
            uuid=uuid,
            body=entry_data["body"],
            log_index=entry_data["logIndex"],
            integrated_time=entry_data["integratedTime"],
            log_id=entry_data["logID"],
            inclusion_proof=verification.get("inclusionProof"),
            signed_entry_timestamp=verification.get("signedEntryTimestamp"),
        )

    async def get_by_index(self, index: int) -> RekorLogEntry:
        """Get an entry by log index."""
        client = await self._ensure_client()
        url = f"{self.base_url}/api/v1/log/entries"
        response = await client.get(url, params={"logIndex": index})
        response.raise_for_status()

        entries = response.json()
        uuid, entry_data = next(iter(entries.items()))

        verification = entry_data.get("verification", {})
        return RekorLogEntry(
            uuid=uuid,
            body=entry_data["body"],
            log_index=entry_data["logIndex"],
            integrated_time=entry_data["integratedTime"],
            log_id=entry_data["logID"],
            inclusion_proof=verification.get("inclusionProof"),
            signed_entry_timestamp=verification.get("signedEntryTimestamp"),
        )

    async def search_by_hash(self, hash_hex: str) -> list[str]:
        """Search for entries by hash. Returns list of UUIDs."""
        client = await self._ensure_client()
        hash_hex = hash_hex.removeprefix("0x")

        url = f"{self.base_url}/api/v1/index/retrieve"
        response = await client.post(url, json={"hash": f"sha256:{hash_hex}"})

        if response.status_code == 404:
            return []
        response.raise_for_status()
        return response.json()

    async def verify(self, entry_ref: RekorRef, expected_hash: str) -> bool:
        """
        Verify that an entry exists in Rekor and matches the expected hash.

        Args:
            entry_ref: Reference to the Rekor entry
            expected_hash: Expected receipt hash (hex-encoded)

        Returns:
            True if the entry's hash matches the expected hash
        """
        entry = await self.get_by_uuid(entry_ref.uuid)

        # Decode and parse the body
        body_bytes = base64.b64decode(entry.body)
        body = json.loads(body_bytes)

        # Extract the hash
        actual_hash = body["spec"]["data"]["hash"]["value"]

        # Normalize for comparison
        expected = expected_hash.removeprefix("0x").lower()
        actual = actual_hash.removeprefix("0x").lower()

        return expected == actual

    async def get_log_info(self) -> dict:
        """Get the current log info (tree size, root hash)."""
        client = await self._ensure_client()
        url = f"{self.base_url}/api/v1/log"
        response = await client.get(url)
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


# Convenience function for one-off operations
async def publish_to_rekor(
    hash_hex: str,
    signing_key: SigningKey,
    rekor_url: str = DEFAULT_REKOR_URL,
) -> RekorRef:
    """
    Publish a hash to Rekor transparency log.

    Args:
        hash_hex: SHA-256 hash to log (hex-encoded)
        signing_key: Ed25519 signing key
        rekor_url: Rekor instance URL

    Returns:
        RekorRef with entry details
    """
    async with RekorClient(rekor_url) as client:
        return await client.publish(hash_hex, signing_key)
