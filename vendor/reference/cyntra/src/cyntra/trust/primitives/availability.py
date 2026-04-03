"""
Data Availability layer for proof bundles.

Provides upload/retrieval of proof bundles to multiple storage backends:
- Local filesystem (development)
- IPFS (decentralized)
- S3-compatible (production)
- Arweave (permanent storage)

Bundles contain:
- Signed RunReceipt
- Merkle proofs for anchored events
- Ledger event subset
- Diff patches
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


@dataclass
class BundlePointer:
    """Pointer to a stored proof bundle."""

    uri: str  # Full URI (ipfs://, s3://, file://, ar://)
    content_hash: str  # SHA-256 of bundle contents
    size_bytes: int
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Storage metadata
    storage_type: str = "unknown"  # ipfs, s3, local, arweave
    replication_count: int = 1

    def to_dict(self) -> dict:
        return {
            "uri": self.uri,
            "content_hash": self.content_hash,
            "size_bytes": self.size_bytes,
            "created_at": self.created_at.isoformat(),
            "storage_type": self.storage_type,
            "replication_count": self.replication_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> BundlePointer:
        return cls(
            uri=data["uri"],
            content_hash=data["content_hash"],
            size_bytes=data["size_bytes"],
            created_at=datetime.fromisoformat(data["created_at"]),
            storage_type=data.get("storage_type", "unknown"),
            replication_count=data.get("replication_count", 1),
        )


@dataclass
class ProofBundle:
    """A proof bundle containing all verification artifacts."""

    # Receipt
    receipt_json: str
    receipt_hash: str

    # Merkle proofs
    merkle_root: str
    merkle_proofs: list[dict]  # Per-event proofs

    # Ledger events (anchored subset)
    events: list[dict]

    # Artifacts
    diff_patch: str | None = None

    # Metadata
    version: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_bytes(self) -> bytes:
        """Serialize bundle to compressed bytes."""
        data = {
            "version": self.version,
            "receipt_json": self.receipt_json,
            "receipt_hash": self.receipt_hash,
            "merkle_root": self.merkle_root,
            "merkle_proofs": self.merkle_proofs,
            "events": self.events,
            "diff_patch": self.diff_patch,
            "created_at": self.created_at.isoformat(),
        }
        json_bytes = json.dumps(data, separators=(",", ":")).encode()
        return gzip.compress(json_bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> ProofBundle:
        """Deserialize bundle from compressed bytes."""
        json_bytes = gzip.decompress(data)
        obj = json.loads(json_bytes)
        return cls(
            version=obj["version"],
            receipt_json=obj["receipt_json"],
            receipt_hash=obj["receipt_hash"],
            merkle_root=obj["merkle_root"],
            merkle_proofs=obj["merkle_proofs"],
            events=obj["events"],
            diff_patch=obj.get("diff_patch"),
            created_at=datetime.fromisoformat(obj["created_at"]),
        )

    def compute_hash(self) -> str:
        """Compute content hash of bundle."""
        return "0x" + hashlib.sha256(self.to_bytes()).hexdigest()


class DataAvailabilityStore(ABC):
    """Abstract interface for proof bundle storage."""

    @abstractmethod
    async def upload(self, bundle: ProofBundle) -> BundlePointer:
        """Upload a bundle and return its pointer."""
        pass

    @abstractmethod
    async def download(self, pointer: BundlePointer) -> ProofBundle:
        """Download a bundle by its pointer."""
        pass

    @abstractmethod
    async def exists(self, pointer: BundlePointer) -> bool:
        """Check if a bundle exists."""
        pass

    @abstractmethod
    async def delete(self, pointer: BundlePointer) -> bool:
        """Delete a bundle (if supported)."""
        pass


class LocalBundleStore(DataAvailabilityStore):
    """Local filesystem bundle storage for development."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _path_for_hash(self, content_hash: str) -> Path:
        """Get file path for a content hash."""
        clean_hash = content_hash.removeprefix("0x")
        # Use first 4 chars as subdirectory for better filesystem distribution
        return self.base_dir / clean_hash[:4] / f"{clean_hash}.bundle.gz"

    async def upload(self, bundle: ProofBundle) -> BundlePointer:
        data = bundle.to_bytes()
        content_hash = "0x" + hashlib.sha256(data).hexdigest()

        path = self._path_for_hash(content_hash)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Write atomically
        tmp_path = path.with_suffix(".tmp")
        tmp_path.write_bytes(data)
        tmp_path.rename(path)

        return BundlePointer(
            uri=f"file://{path.absolute()}",
            content_hash=content_hash,
            size_bytes=len(data),
            storage_type="local",
        )

    async def download(self, pointer: BundlePointer) -> ProofBundle:
        parsed = urlparse(pointer.uri)
        if parsed.scheme == "file":
            path = Path(parsed.path)
        else:
            # Try to find by hash
            path = self._path_for_hash(pointer.content_hash)

        if not path.exists():
            raise FileNotFoundError(f"Bundle not found: {pointer.uri}")

        data = path.read_bytes()

        # Verify hash
        actual_hash = "0x" + hashlib.sha256(data).hexdigest()
        if actual_hash != pointer.content_hash:
            raise ValueError(f"Hash mismatch: expected {pointer.content_hash}, got {actual_hash}")

        return ProofBundle.from_bytes(data)

    async def exists(self, pointer: BundlePointer) -> bool:
        path = self._path_for_hash(pointer.content_hash)
        return path.exists()

    async def delete(self, pointer: BundlePointer) -> bool:
        path = self._path_for_hash(pointer.content_hash)
        if path.exists():
            path.unlink()
            return True
        return False


class IPFSBundleStore(DataAvailabilityStore):
    """IPFS-based bundle storage for decentralization."""

    def __init__(
        self,
        api_url: str = "http://127.0.0.1:5001",
        gateway_url: str = "https://ipfs.io",
    ):
        self.api_url = api_url.rstrip("/")
        self.gateway_url = gateway_url.rstrip("/")
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=60.0)
        return self._client

    async def upload(self, bundle: ProofBundle) -> BundlePointer:
        client = await self._get_client()
        data = bundle.to_bytes()
        content_hash = "0x" + hashlib.sha256(data).hexdigest()

        # Upload to IPFS
        files = {"file": ("bundle.gz", data, "application/gzip")}
        response = await client.post(
            f"{self.api_url}/api/v0/add",
            files=files,
            params={"pin": "true"},
        )
        response.raise_for_status()

        result = response.json()
        cid = result["Hash"]

        return BundlePointer(
            uri=f"ipfs://{cid}",
            content_hash=content_hash,
            size_bytes=len(data),
            storage_type="ipfs",
        )

    async def download(self, pointer: BundlePointer) -> ProofBundle:
        client = await self._get_client()

        # Extract CID from URI
        parsed = urlparse(pointer.uri)
        if parsed.scheme == "ipfs":
            cid = parsed.netloc or parsed.path.lstrip("/")
        else:
            raise ValueError(f"Not an IPFS URI: {pointer.uri}")

        # Try IPFS API first, then gateway
        try:
            response = await client.post(
                f"{self.api_url}/api/v0/cat",
                params={"arg": cid},
            )
            response.raise_for_status()
            data = response.content
        except Exception:
            # Fall back to gateway
            response = await client.get(f"{self.gateway_url}/ipfs/{cid}")
            response.raise_for_status()
            data = response.content

        # Verify hash
        actual_hash = "0x" + hashlib.sha256(data).hexdigest()
        if actual_hash != pointer.content_hash:
            raise ValueError("Hash mismatch")

        return ProofBundle.from_bytes(data)

    async def exists(self, pointer: BundlePointer) -> bool:
        try:
            client = await self._get_client()
            parsed = urlparse(pointer.uri)
            cid = parsed.netloc or parsed.path.lstrip("/")

            response = await client.post(
                f"{self.api_url}/api/v0/files/stat",
                params={"arg": f"/ipfs/{cid}"},
                timeout=5.0,
            )
            return response.status_code == 200
        except Exception:
            return False

    async def delete(self, pointer: BundlePointer) -> bool:
        # IPFS doesn't support deletion, only unpinning
        try:
            client = await self._get_client()
            parsed = urlparse(pointer.uri)
            cid = parsed.netloc or parsed.path.lstrip("/")

            response = await client.post(
                f"{self.api_url}/api/v0/pin/rm",
                params={"arg": cid},
            )
            return response.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None


class S3BundleStore(DataAvailabilityStore):
    """S3-compatible bundle storage for production."""

    def __init__(
        self,
        bucket: str,
        prefix: str = "proof-bundles/",
        endpoint_url: str | None = None,
        region: str = "us-east-1",
    ):
        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/"
        self.endpoint_url = endpoint_url
        self.region = region
        self._client = None

    async def _get_client(self):
        if self._client is None:
            try:
                import aioboto3
            except ImportError:
                raise ImportError("aioboto3 required for S3 storage. Install with: pip install aioboto3")

            session = aioboto3.Session()
            self._client = await session.client(
                "s3",
                endpoint_url=self.endpoint_url,
                region_name=self.region,
            ).__aenter__()
        return self._client

    def _key_for_hash(self, content_hash: str) -> str:
        clean_hash = content_hash.removeprefix("0x")
        return f"{self.prefix}{clean_hash[:4]}/{clean_hash}.bundle.gz"

    async def upload(self, bundle: ProofBundle) -> BundlePointer:
        client = await self._get_client()
        data = bundle.to_bytes()
        content_hash = "0x" + hashlib.sha256(data).hexdigest()
        key = self._key_for_hash(content_hash)

        await client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=data,
            ContentType="application/gzip",
            Metadata={"content-hash": content_hash},
        )

        if self.endpoint_url:
            uri = f"s3://{self.bucket}/{key}"
        else:
            uri = f"s3://{self.bucket}/{key}"

        return BundlePointer(
            uri=uri,
            content_hash=content_hash,
            size_bytes=len(data),
            storage_type="s3",
        )

    async def download(self, pointer: BundlePointer) -> ProofBundle:
        client = await self._get_client()
        key = self._key_for_hash(pointer.content_hash)

        response = await client.get_object(Bucket=self.bucket, Key=key)
        data = await response["Body"].read()

        # Verify hash
        actual_hash = "0x" + hashlib.sha256(data).hexdigest()
        if actual_hash != pointer.content_hash:
            raise ValueError("Hash mismatch")

        return ProofBundle.from_bytes(data)

    async def exists(self, pointer: BundlePointer) -> bool:
        try:
            client = await self._get_client()
            key = self._key_for_hash(pointer.content_hash)
            await client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

    async def delete(self, pointer: BundlePointer) -> bool:
        try:
            client = await self._get_client()
            key = self._key_for_hash(pointer.content_hash)
            await client.delete_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False


class MultiStore(DataAvailabilityStore):
    """
    Multi-backend store for redundancy.
    
    Uploads to multiple backends, downloads from first available.
    """

    def __init__(self, stores: list[DataAvailabilityStore]):
        if not stores:
            raise ValueError("At least one store required")
        self.stores = stores

    async def upload(self, bundle: ProofBundle) -> BundlePointer:
        """Upload to all stores, return first successful pointer."""
        pointers = []
        errors = []

        for store in self.stores:
            try:
                pointer = await store.upload(bundle)
                pointers.append(pointer)
            except Exception as e:
                errors.append((store, e))
                logger.warning(f"Upload to {store.__class__.__name__} failed: {e}")

        if not pointers:
            raise RuntimeError(f"All uploads failed: {errors}")

        # Return first pointer with replication count
        result = pointers[0]
        result.replication_count = len(pointers)
        return result

    async def download(self, pointer: BundlePointer) -> ProofBundle:
        """Download from first available store."""
        errors = []

        for store in self.stores:
            try:
                return await store.download(pointer)
            except Exception as e:
                errors.append((store, e))
                logger.debug(f"Download from {store.__class__.__name__} failed: {e}")

        raise RuntimeError(f"All downloads failed: {errors}")

    async def exists(self, pointer: BundlePointer) -> bool:
        """Check if bundle exists in any store."""
        for store in self.stores:
            if await store.exists(pointer):
                return True
        return False

    async def delete(self, pointer: BundlePointer) -> bool:
        """Delete from all stores."""
        results = []
        for store in self.stores:
            try:
                results.append(await store.delete(pointer))
            except Exception:
                results.append(False)
        return any(results)


# Factory function
def create_store(
    storage_type: str = "local",
    **kwargs,
) -> DataAvailabilityStore:
    """
    Create a data availability store.
    
    Args:
        storage_type: "local", "ipfs", "s3", or "multi"
        **kwargs: Backend-specific configuration
        
    Returns:
        DataAvailabilityStore instance
    """
    if storage_type == "local":
        base_dir = kwargs.get("base_dir", Path.home() / ".cyntra" / "bundles")
        return LocalBundleStore(Path(base_dir))

    elif storage_type == "ipfs":
        return IPFSBundleStore(
            api_url=kwargs.get("api_url", "http://127.0.0.1:5001"),
            gateway_url=kwargs.get("gateway_url", "https://ipfs.io"),
        )

    elif storage_type == "s3":
        return S3BundleStore(
            bucket=kwargs["bucket"],
            prefix=kwargs.get("prefix", "proof-bundles/"),
            endpoint_url=kwargs.get("endpoint_url"),
            region=kwargs.get("region", "us-east-1"),
        )

    elif storage_type == "multi":
        stores = kwargs.get("stores", [])
        return MultiStore(stores)

    else:
        raise ValueError(f"Unknown storage type: {storage_type}")


@dataclass
class AvailabilityCheckResult:
    """Result of checking bundle availability across multiple stores."""

    uri: str
    content_hash: str
    total_stores: int
    available_stores: int
    unavailable_stores: int
    store_results: dict[str, bool]  # store_type -> available
    latency_ms: dict[str, float]  # store_type -> latency
    verified_hash: bool = False
    error: str | None = None

    @property
    def is_available(self) -> bool:
        """Bundle is available if at least one store has it."""
        return self.available_stores > 0

    @property
    def availability_ratio(self) -> float:
        """Ratio of stores with the bundle."""
        if self.total_stores == 0:
            return 0.0
        return self.available_stores / self.total_stores

    def to_dict(self) -> dict:
        return {
            "uri": self.uri,
            "content_hash": self.content_hash,
            "is_available": self.is_available,
            "total_stores": self.total_stores,
            "available_stores": self.available_stores,
            "unavailable_stores": self.unavailable_stores,
            "availability_ratio": self.availability_ratio,
            "store_results": self.store_results,
            "latency_ms": self.latency_ms,
            "verified_hash": self.verified_hash,
            "error": self.error,
        }


class AvailabilityChecker:
    """Check bundle availability across multiple storage backends."""

    def __init__(
        self,
        stores: dict[str, DataAvailabilityStore] | None = None,
        timeout: float = 10.0,
    ):
        self.stores = stores or {}
        self.timeout = timeout

    @classmethod
    def default(cls) -> AvailabilityChecker:
        """Create checker with default store configurations."""
        stores = {
            "local": LocalBundleStore(Path.home() / ".cyntra" / "bundles"),
        }

        # Add IPFS if available
        try:
            stores["ipfs"] = IPFSBundleStore()
        except Exception:
            pass

        return cls(stores=stores)

    async def check_pointer(self, pointer: BundlePointer) -> AvailabilityCheckResult:
        """Check availability of a bundle pointer across all configured stores."""
        import time

        store_results: dict[str, bool] = {}
        latency_ms: dict[str, float] = {}
        verified_hash = False

        for store_name, store in self.stores.items():
            start = time.perf_counter()
            try:
                exists = await asyncio.wait_for(
                    store.exists(pointer),
                    timeout=self.timeout,
                )
                store_results[store_name] = exists
                latency_ms[store_name] = (time.perf_counter() - start) * 1000

                # Try to verify hash by downloading
                if exists and not verified_hash:
                    try:
                        bundle = await asyncio.wait_for(
                            store.download(pointer),
                            timeout=self.timeout * 3,  # Download takes longer
                        )
                        actual_hash = bundle.compute_hash()
                        verified_hash = actual_hash == pointer.content_hash
                    except Exception:
                        pass

            except TimeoutError:
                store_results[store_name] = False
                latency_ms[store_name] = self.timeout * 1000
            except Exception as e:
                store_results[store_name] = False
                latency_ms[store_name] = (time.perf_counter() - start) * 1000
                logger.debug(f"Check failed for {store_name}: {e}")

        available = sum(1 for v in store_results.values() if v)
        unavailable = len(store_results) - available

        return AvailabilityCheckResult(
            uri=pointer.uri,
            content_hash=pointer.content_hash,
            total_stores=len(store_results),
            available_stores=available,
            unavailable_stores=unavailable,
            store_results=store_results,
            latency_ms=latency_ms,
            verified_hash=verified_hash,
        )

    async def check_uri(self, uri: str, content_hash: str | None = None) -> AvailabilityCheckResult:
        """Check availability of a bundle by URI."""
        # Try to parse content hash from pointer file if not provided
        if content_hash is None:
            # Extract from IPFS CID or local path
            parsed = urlparse(uri)
            if parsed.scheme == "ipfs":
                # IPFS CID is not a content hash, we need the actual hash
                content_hash = "0x" + "0" * 64  # Placeholder
            elif parsed.scheme == "file":
                path = Path(parsed.path)
                if path.exists():
                    data = path.read_bytes()
                    content_hash = "0x" + hashlib.sha256(data).hexdigest()
                else:
                    return AvailabilityCheckResult(
                        uri=uri,
                        content_hash="",
                        total_stores=0,
                        available_stores=0,
                        unavailable_stores=0,
                        store_results={},
                        latency_ms={},
                        error=f"File not found: {uri}",
                    )

        pointer = BundlePointer(
            uri=uri,
            content_hash=content_hash or "",
            size_bytes=0,
        )

        return await self.check_pointer(pointer)


async def check_availability(
    pointer: BundlePointer | str,
    stores: dict[str, DataAvailabilityStore] | None = None,
) -> AvailabilityCheckResult:
    """Convenience function to check bundle availability."""
    checker = AvailabilityChecker(stores=stores) if stores else AvailabilityChecker.default()

    if isinstance(pointer, str):
        return await checker.check_uri(pointer)
    else:
        return await checker.check_pointer(pointer)


__all__ = [
    "BundlePointer",
    "ProofBundle",
    "DataAvailabilityStore",
    "LocalBundleStore",
    "IPFSBundleStore",
    "S3BundleStore",
    "MultiStore",
    "create_store",
    "AvailabilityCheckResult",
    "AvailabilityChecker",
    "check_availability",
]
