"""
SPIFFE workload identity integration.

Provides:
- SVID (SPIFFE Verifiable Identity Document) management
- Workload attestation for workcells and agents
- mTLS credential retrieval from SPIRE agent

Reference: https://spiffe.io/docs/latest/spiffe-about/overview/
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol
from enum import Enum

logger = logging.getLogger(__name__)


class WorkloadType(str, Enum):
    """Types of workloads that can have SPIFFE identities."""
    
    KERNEL = "kernel"
    WORKCELL = "workcell"
    VERIFIER = "verifier"
    PROVIDER = "provider"
    AGENT = "agent"


@dataclass
class SpiffeId:
    """
    SPIFFE ID representing a workload identity.
    
    Format: spiffe://<trust_domain>/<workload_path>
    Example: spiffe://cyntra.local/kernel/default/main
    """
    
    trust_domain: str
    path: str
    
    def __str__(self) -> str:
        return f"spiffe://{self.trust_domain}/{self.path}"
    
    @classmethod
    def parse(cls, spiffe_id: str) -> SpiffeId:
        """Parse a SPIFFE ID string."""
        if not spiffe_id.startswith("spiffe://"):
            raise ValueError(f"Invalid SPIFFE ID format: {spiffe_id}")
        
        remainder = spiffe_id[9:]  # Remove "spiffe://"
        parts = remainder.split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid SPIFFE ID format: {spiffe_id}")
        
        return cls(trust_domain=parts[0], path=parts[1])
    
    @classmethod
    def for_kernel(
        cls,
        org: str = "default",
        instance: str = "main",
        trust_domain: str = "cyntra.local",
    ) -> SpiffeId:
        """Create SPIFFE ID for a kernel instance."""
        return cls(trust_domain=trust_domain, path=f"kernel/{org}/{instance}")
    
    @classmethod
    def for_workcell(
        cls,
        run_id: str,
        step_id: str = "main",
        trust_domain: str = "cyntra.local",
    ) -> SpiffeId:
        """Create SPIFFE ID for a workcell."""
        return cls(trust_domain=trust_domain, path=f"workcell/{run_id}/{step_id}")
    
    @classmethod
    def for_verifier(
        cls,
        org: str = "default",
        instance: str = "main",
        trust_domain: str = "cyntra.local",
    ) -> SpiffeId:
        """Create SPIFFE ID for a verifier."""
        return cls(trust_domain=trust_domain, path=f"verifier/{org}/{instance}")
    
    @classmethod
    def for_provider(
        cls,
        name: str,
        region: str = "local",
        trust_domain: str = "cyntra.local",
    ) -> SpiffeId:
        """Create SPIFFE ID for a provider."""
        return cls(trust_domain=trust_domain, path=f"provider/{name}/{region}")


@dataclass
class X509Svid:
    """
    X.509 SVID (SPIFFE Verifiable Identity Document).
    
    Contains the certificate chain and private key for mTLS.
    """
    
    spiffe_id: SpiffeId
    cert_chain_pem: bytes  # PEM-encoded certificate chain
    private_key_pem: bytes  # PEM-encoded private key
    bundle_pem: bytes  # Trust bundle (CA certs)
    expiry: datetime
    hint: str = ""  # Optional hint for key selection
    
    @property
    def is_expired(self) -> bool:
        """Check if SVID is expired."""
        return datetime.now(timezone.utc) >= self.expiry
    
    @property
    def ttl_seconds(self) -> float:
        """Get remaining TTL in seconds."""
        delta = self.expiry - datetime.now(timezone.utc)
        return max(0, delta.total_seconds())


@dataclass
class JwtSvid:
    """
    JWT SVID for token-based authentication.
    """
    
    spiffe_id: SpiffeId
    token: str  # JWT token
    expiry: datetime
    audience: list[str] = field(default_factory=list)
    
    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expiry


class SpiffeSource(Protocol):
    """Protocol for SVID sources (SPIRE agent, file, etc.)."""
    
    async def get_x509_svid(self) -> X509Svid:
        """Get current X.509 SVID."""
        ...
    
    async def get_jwt_svid(self, audience: list[str]) -> JwtSvid:
        """Get JWT SVID for the given audience."""
        ...
    
    async def get_bundle(self) -> bytes:
        """Get trust bundle (PEM-encoded CA certs)."""
        ...


@dataclass
class SpireConfig:
    """Configuration for SPIRE agent connection."""
    
    # Unix domain socket path for SPIRE agent
    socket_path: str = "unix:///tmp/spire-agent/public/api.sock"
    
    # Alternative: TCP connection
    agent_address: Optional[str] = None  # e.g., "localhost:8081"
    
    # Trust domain
    trust_domain: str = "cyntra.local"
    
    # Timeouts
    timeout_secs: float = 10.0
    
    # Refresh intervals
    svid_refresh_interval_secs: float = 60.0
    bundle_refresh_interval_secs: float = 300.0
    
    @classmethod
    def from_env(cls) -> SpireConfig:
        """Create config from environment variables."""
        return cls(
            socket_path=os.environ.get(
                "SPIFFE_ENDPOINT_SOCKET",
                "unix:///tmp/spire-agent/public/api.sock",
            ),
            agent_address=os.environ.get("SPIRE_AGENT_ADDRESS"),
            trust_domain=os.environ.get("SPIFFE_TRUST_DOMAIN", "cyntra.local"),
        )


class SpireWorkloadSource:
    """
    SPIRE Workload API client.
    
    Connects to the local SPIRE agent to obtain SVIDs.
    Implements automatic refresh and caching.
    """
    
    def __init__(self, config: Optional[SpireConfig] = None):
        self.config = config or SpireConfig.from_env()
        self._x509_svid: Optional[X509Svid] = None
        self._bundle: Optional[bytes] = None
        self._refresh_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self) -> None:
        """Start background refresh."""
        if self._running:
            return
        
        self._running = True
        self._refresh_task = asyncio.create_task(self._refresh_loop())
        logger.info(f"SPIRE workload source started: {self.config.socket_path}")
    
    async def stop(self) -> None:
        """Stop background refresh."""
        self._running = False
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
    
    async def get_x509_svid(self) -> X509Svid:
        """Get current X.509 SVID, fetching if needed."""
        if self._x509_svid is None or self._x509_svid.is_expired:
            await self._fetch_x509_svid()
        
        if self._x509_svid is None:
            raise RuntimeError("Failed to obtain X.509 SVID from SPIRE agent")
        
        return self._x509_svid
    
    async def get_jwt_svid(self, audience: list[str]) -> JwtSvid:
        """Get JWT SVID for the given audience."""
        # TODO: Implement via SPIRE Workload API
        # For now, return a placeholder
        raise NotImplementedError("JWT SVID fetch not yet implemented")
    
    async def get_bundle(self) -> bytes:
        """Get trust bundle."""
        if self._bundle is None:
            await self._fetch_bundle()
        
        if self._bundle is None:
            raise RuntimeError("Failed to obtain trust bundle from SPIRE agent")
        
        return self._bundle
    
    async def _refresh_loop(self) -> None:
        """Background loop to refresh SVIDs and bundles."""
        while self._running:
            try:
                await self._fetch_x509_svid()
                await self._fetch_bundle()
            except Exception as e:
                logger.warning(f"SVID refresh failed: {e}")
            
            await asyncio.sleep(self.config.svid_refresh_interval_secs)
    
    async def _fetch_x509_svid(self) -> None:
        """Fetch X.509 SVID from SPIRE agent."""
        try:
            # Try py-spiffe if available
            from spiffe import SpiffeWorkloadClient
            
            client = SpiffeWorkloadClient(self.config.socket_path)
            svid_response = await asyncio.to_thread(client.fetch_x509_svid)
            
            if svid_response.svids:
                svid = svid_response.svids[0]
                self._x509_svid = X509Svid(
                    spiffe_id=SpiffeId.parse(str(svid.spiffe_id)),
                    cert_chain_pem=svid.cert_chain_pem,
                    private_key_pem=svid.private_key_pem,
                    bundle_pem=svid_response.bundle_pem or b"",
                    expiry=svid.expiry,
                    hint=svid.hint or "",
                )
                logger.debug(f"Fetched X.509 SVID: {self._x509_svid.spiffe_id}")
        except ImportError:
            # py-spiffe not installed, use file-based fallback
            await self._fetch_x509_svid_from_files()
        except Exception as e:
            logger.error(f"Failed to fetch X.509 SVID: {e}")
            raise
    
    async def _fetch_x509_svid_from_files(self) -> None:
        """Fallback: load SVID from files (for testing/development)."""
        cert_path = Path(os.environ.get("SVID_CERT_PATH", "/var/run/secrets/spiffe/svid.pem"))
        key_path = Path(os.environ.get("SVID_KEY_PATH", "/var/run/secrets/spiffe/svid.key"))
        bundle_path = Path(os.environ.get("SVID_BUNDLE_PATH", "/var/run/secrets/spiffe/bundle.pem"))
        
        if not cert_path.exists():
            logger.warning("No SVID files found, using mock identity")
            self._x509_svid = self._create_mock_svid()
            return
        
        cert_chain = cert_path.read_bytes()
        private_key = key_path.read_bytes() if key_path.exists() else b""
        bundle = bundle_path.read_bytes() if bundle_path.exists() else b""
        
        # Parse SPIFFE ID from cert (simplified)
        # In production, use cryptography library to parse X.509
        spiffe_id = SpiffeId.for_kernel()  # Default
        
        self._x509_svid = X509Svid(
            spiffe_id=spiffe_id,
            cert_chain_pem=cert_chain,
            private_key_pem=private_key,
            bundle_pem=bundle,
            expiry=datetime.now(timezone.utc).replace(hour=23, minute=59, second=59),
        )
    
    async def _fetch_bundle(self) -> None:
        """Fetch trust bundle from SPIRE agent."""
        try:
            from spiffe import SpiffeWorkloadClient
            
            client = SpiffeWorkloadClient(self.config.socket_path)
            bundle_response = await asyncio.to_thread(client.fetch_trust_bundle)
            self._bundle = bundle_response.bundle_pem
        except ImportError:
            # Fallback to file
            bundle_path = Path(os.environ.get("SVID_BUNDLE_PATH", "/var/run/secrets/spiffe/bundle.pem"))
            if bundle_path.exists():
                self._bundle = bundle_path.read_bytes()
            else:
                self._bundle = b""
        except Exception as e:
            logger.error(f"Failed to fetch bundle: {e}")
    
    def _create_mock_svid(self) -> X509Svid:
        """Create mock SVID for testing."""
        return X509Svid(
            spiffe_id=SpiffeId.for_kernel(org="mock", instance="test"),
            cert_chain_pem=b"-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
            private_key_pem=b"-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----",
            bundle_pem=b"",
            expiry=datetime.now(timezone.utc).replace(year=2099),
        )


class WorkloadIdentity:
    """
    High-level workload identity manager.
    
    Provides:
    - Identity creation for different workload types
    - mTLS credential management
    - Token generation for inter-service auth
    """
    
    def __init__(
        self,
        source: Optional[SpiffeSource] = None,
        config: Optional[SpireConfig] = None,
    ):
        self._source = source
        self._config = config or SpireConfig.from_env()
        self._started = False
    
    async def start(self) -> None:
        """Start identity management."""
        if self._started:
            return
        
        if self._source is None:
            self._source = SpireWorkloadSource(self._config)
        
        if hasattr(self._source, "start"):
            await self._source.start()
        
        self._started = True
    
    async def stop(self) -> None:
        """Stop identity management."""
        if self._source and hasattr(self._source, "stop"):
            await self._source.stop()
        self._started = False
    
    async def get_identity(self) -> SpiffeId:
        """Get current workload identity."""
        svid = await self._source.get_x509_svid()
        return svid.spiffe_id
    
    async def get_mtls_credentials(self) -> tuple[bytes, bytes, bytes]:
        """
        Get mTLS credentials.
        
        Returns:
            Tuple of (cert_chain_pem, private_key_pem, ca_bundle_pem)
        """
        svid = await self._source.get_x509_svid()
        return (svid.cert_chain_pem, svid.private_key_pem, svid.bundle_pem)
    
    async def get_jwt_token(self, audience: list[str]) -> str:
        """Get JWT token for the given audience."""
        jwt_svid = await self._source.get_jwt_svid(audience)
        return jwt_svid.token
    
    async def validate_peer(self, peer_cert_pem: bytes) -> Optional[SpiffeId]:
        """
        Validate a peer certificate against the trust bundle.
        
        Returns the peer's SPIFFE ID if valid, None otherwise.
        """
        # TODO: Implement certificate validation using cryptography library
        # For now, return None (validation not performed)
        return None


# Singleton instance
_workload_identity: Optional[WorkloadIdentity] = None


async def get_workload_identity() -> WorkloadIdentity:
    """Get or create the global WorkloadIdentity instance."""
    global _workload_identity
    
    if _workload_identity is None:
        _workload_identity = WorkloadIdentity()
        await _workload_identity.start()
    
    return _workload_identity


# Convenience functions
async def get_current_identity() -> SpiffeId:
    """Get current workload's SPIFFE identity."""
    wi = await get_workload_identity()
    return await wi.get_identity()


async def get_mtls_credentials() -> tuple[bytes, bytes, bytes]:
    """Get mTLS credentials for the current workload."""
    wi = await get_workload_identity()
    return await wi.get_mtls_credentials()
