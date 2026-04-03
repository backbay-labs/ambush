"""
Multi-fetcher availability checker.

Implements independent fetcher checks across multiple storage backends
to verify bundle availability and detect DA failures.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from cyntra.trust.availability.obligation import (
    AvailabilityCheck,
    AvailabilityObligation,
    DABondRegistry,
    FetcherResult,
)

logger = logging.getLogger(__name__)


class BundleFetcher(Protocol):
    """Protocol for bundle fetcher implementations."""

    @property
    def fetcher_id(self) -> str:
        """Unique identifier for this fetcher."""
        ...

    async def fetch(self, uri: str, expected_hash: str | None = None) -> FetcherResult:
        """Attempt to fetch a bundle from the given URI."""
        ...


@dataclass
class LocalFetcher:
    """Local filesystem fetcher for development."""

    fetcher_id: str = "local"

    async def fetch(self, uri: str, expected_hash: str | None = None) -> FetcherResult:
        start = time.perf_counter()

        try:
            if not uri.startswith("file://"):
                return FetcherResult(
                    fetcher_id=self.fetcher_id,
                    success=False,
                    latency_ms=(time.perf_counter() - start) * 1000,
                    error=f"Not a file URI: {uri}",
                    storage_uri=uri,
                )

            path = Path(uri.removeprefix("file://"))
            if not path.exists():
                return FetcherResult(
                    fetcher_id=self.fetcher_id,
                    success=False,
                    latency_ms=(time.perf_counter() - start) * 1000,
                    error=f"File not found: {path}",
                    storage_uri=uri,
                )

            content = path.read_bytes()
            actual_hash = "0x" + hashlib.sha256(content).hexdigest()

            hash_verified = False
            if expected_hash:
                hash_verified = actual_hash.lower() == expected_hash.lower()

            return FetcherResult(
                fetcher_id=self.fetcher_id,
                success=True,
                latency_ms=(time.perf_counter() - start) * 1000,
                storage_uri=uri,
                content_hash_verified=hash_verified,
            )

        except Exception as e:
            return FetcherResult(
                fetcher_id=self.fetcher_id,
                success=False,
                latency_ms=(time.perf_counter() - start) * 1000,
                error=str(e),
                storage_uri=uri,
            )


@dataclass
class HTTPFetcher:
    """HTTP/HTTPS fetcher for remote storage."""

    fetcher_id: str = "http"
    timeout: float = 30.0

    async def fetch(self, uri: str, expected_hash: str | None = None) -> FetcherResult:
        import httpx

        start = time.perf_counter()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(uri)
                response.raise_for_status()

                content = response.content
                actual_hash = "0x" + hashlib.sha256(content).hexdigest()

                hash_verified = False
                if expected_hash:
                    hash_verified = actual_hash.lower() == expected_hash.lower()

                return FetcherResult(
                    fetcher_id=self.fetcher_id,
                    success=True,
                    latency_ms=(time.perf_counter() - start) * 1000,
                    storage_uri=uri,
                    content_hash_verified=hash_verified,
                )

        except Exception as e:
            return FetcherResult(
                fetcher_id=self.fetcher_id,
                success=False,
                latency_ms=(time.perf_counter() - start) * 1000,
                error=str(e),
                storage_uri=uri,
            )


@dataclass
class IPFSFetcher:
    """IPFS gateway fetcher."""

    fetcher_id: str = "ipfs"
    gateway_url: str = "https://ipfs.io"
    timeout: float = 60.0

    async def fetch(self, uri: str, expected_hash: str | None = None) -> FetcherResult:
        import httpx

        start = time.perf_counter()

        try:
            # Extract CID from ipfs:// URI
            if uri.startswith("ipfs://"):
                cid = uri.removeprefix("ipfs://").split("/")[0]
            elif "/ipfs/" in uri:
                cid = uri.split("/ipfs/")[1].split("/")[0]
            else:
                return FetcherResult(
                    fetcher_id=self.fetcher_id,
                    success=False,
                    latency_ms=(time.perf_counter() - start) * 1000,
                    error=f"Invalid IPFS URI: {uri}",
                    storage_uri=uri,
                )

            gateway_uri = f"{self.gateway_url}/ipfs/{cid}"

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(gateway_uri)
                response.raise_for_status()

                content = response.content
                actual_hash = "0x" + hashlib.sha256(content).hexdigest()

                hash_verified = False
                if expected_hash:
                    hash_verified = actual_hash.lower() == expected_hash.lower()

                return FetcherResult(
                    fetcher_id=self.fetcher_id,
                    success=True,
                    latency_ms=(time.perf_counter() - start) * 1000,
                    storage_uri=gateway_uri,
                    content_hash_verified=hash_verified,
                )

        except Exception as e:
            return FetcherResult(
                fetcher_id=self.fetcher_id,
                success=False,
                latency_ms=(time.perf_counter() - start) * 1000,
                error=str(e),
                storage_uri=uri,
            )


@dataclass
class MultiFetcherChecker:
    """
    Multi-fetcher availability checker.

    Runs independent fetchers in parallel to verify bundle availability
    across multiple storage backends. Used to determine if DA obligations
    are being met and to trigger bond slashing on failures.
    """

    fetchers: list[BundleFetcher] = field(default_factory=list)
    bond_registry: DABondRegistry | None = None
    fail_closed: bool = True  # Block settlement on DA failure

    @classmethod
    def default(cls, bond_registry: DABondRegistry | None = None) -> MultiFetcherChecker:
        """Create checker with default fetcher configurations."""
        return cls(
            fetchers=[
                LocalFetcher(fetcher_id="local-1"),
                LocalFetcher(fetcher_id="local-2"),
                LocalFetcher(fetcher_id="local-3"),
            ],
            bond_registry=bond_registry,
        )

    @classmethod
    def with_remote(cls, bond_registry: DABondRegistry | None = None) -> MultiFetcherChecker:
        """Create checker with remote fetcher configurations."""
        return cls(
            fetchers=[
                LocalFetcher(fetcher_id="local"),
                IPFSFetcher(fetcher_id="ipfs-io", gateway_url="https://ipfs.io"),
                IPFSFetcher(fetcher_id="ipfs-cloudflare", gateway_url="https://cloudflare-ipfs.com"),
                IPFSFetcher(fetcher_id="ipfs-dweb", gateway_url="https://dweb.link"),
            ],
            bond_registry=bond_registry,
        )

    async def check_obligation(
        self,
        obligation: AvailabilityObligation,
        slash_on_failure: bool = True,
    ) -> AvailabilityCheck:
        """
        Check if an availability obligation is being met.

        Runs all fetchers in parallel against all storage URIs.
        Returns an AvailabilityCheck with per-fetcher results.

        If slash_on_failure is True and the obligation fails,
        the associated bond will be slashed.
        """
        results: list[FetcherResult] = []

        # Run all fetchers against all URIs in parallel
        async def fetch_from_uri(fetcher: BundleFetcher, uri: str) -> FetcherResult:
            return await fetcher.fetch(uri, obligation.bundle_hash)

        tasks = []
        for fetcher in self.fetchers:
            for uri in obligation.storage_uris:
                tasks.append(fetch_from_uri(fetcher, uri))

        if tasks:
            completed = await asyncio.gather(*tasks, return_exceptions=True)

            for result in completed:
                if isinstance(result, Exception):
                    # Create a failed result for exceptions
                    results.append(
                        FetcherResult(
                            fetcher_id="unknown",
                            success=False,
                            latency_ms=0,
                            error=str(result),
                        )
                    )
                else:
                    results.append(result)

        # Deduplicate by fetcher (keep best result per fetcher)
        best_by_fetcher: dict[str, FetcherResult] = {}
        for result in results:
            if result.fetcher_id not in best_by_fetcher or result.success and not best_by_fetcher[result.fetcher_id].success or (
                result.success
                and best_by_fetcher[result.fetcher_id].success
                and result.latency_ms < best_by_fetcher[result.fetcher_id].latency_ms
            ):
                best_by_fetcher[result.fetcher_id] = result

        check = AvailabilityCheck(
            obligation_id=obligation.obligation_id,
            bundle_hash=obligation.bundle_hash,
            checked_at=datetime.now(UTC),
            fetchers=list(best_by_fetcher.values()),
            required_fetchers=obligation.min_fetchers,
        )

        # Slash bond on failure if configured
        if not check.available and slash_on_failure and self.bond_registry:
            failed_fetchers = [f.fetcher_id for f in check.fetchers if not f.success]
            reason = f"DA failure: {len(failed_fetchers)} fetchers failed, required {obligation.min_fetchers}"
            self.bond_registry.slash_bond(obligation.obligation_id, reason)

        return check

    async def check_bundle(
        self,
        bundle_hash: str,
        storage_uris: list[str],
        min_fetchers: int = 1,
    ) -> AvailabilityCheck:
        """
        Simple availability check without an obligation.

        Useful for ad-hoc bundle availability verification.
        """
        # Create a temporary obligation for the check
        obligation = AvailabilityObligation(
            bundle_hash=bundle_hash,
            availability_window_hours=1,  # Dummy
            min_fetchers=min_fetchers,
            storage_uris=storage_uris,
            da_bond_wei=0,  # No bond
        )

        return await self.check_obligation(obligation, slash_on_failure=False)


@dataclass
class DAFailureRecord:
    """Record of a DA failure event."""

    obligation_id: str
    bundle_hash: str
    check: AvailabilityCheck
    detected_at: datetime
    bond_slashed: bool
    settlement_blocked: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "bundle_hash": self.bundle_hash,
            "check": self.check.to_dict(),
            "detected_at": self.detected_at.isoformat(),
            "bond_slashed": self.bond_slashed,
            "settlement_blocked": self.settlement_blocked,
        }


class DAFailureDetector:
    """
    Detects DA failures and enforces fail-closed behavior.

    Monitors availability checks and:
    - Records failures
    - Triggers bond slashing
    - Blocks settlement for affected tasks
    """

    def __init__(
        self,
        checker: MultiFetcherChecker,
        bond_registry: DABondRegistry | None = None,
    ) -> None:
        self.checker = checker
        self.bond_registry = bond_registry or DABondRegistry()
        self._failures: list[DAFailureRecord] = []
        self._blocked_bundles: set[str] = set()

    async def check_and_detect(
        self,
        obligation: AvailabilityObligation,
    ) -> tuple[AvailabilityCheck, DAFailureRecord | None]:
        """
        Check obligation and detect failures.

        Returns the check result and a failure record if failure detected.
        """
        check = await self.checker.check_obligation(
            obligation,
            slash_on_failure=True,
        )

        if check.available:
            return check, None

        # Record failure
        failure = DAFailureRecord(
            obligation_id=obligation.obligation_id,
            bundle_hash=obligation.bundle_hash,
            check=check,
            detected_at=datetime.now(UTC),
            bond_slashed=self.bond_registry.get_bond(obligation.obligation_id) is not None,
            settlement_blocked=self.checker.fail_closed,
        )

        self._failures.append(failure)

        if self.checker.fail_closed:
            self._blocked_bundles.add(obligation.bundle_hash)

        logger.warning(
            f"DA failure detected for {obligation.bundle_hash}: "
            f"{check.successful_fetchers}/{obligation.min_fetchers} fetchers succeeded"
        )

        return check, failure

    def is_settlement_blocked(self, bundle_hash: str) -> bool:
        """Check if settlement is blocked for a bundle due to DA failure."""
        return bundle_hash in self._blocked_bundles

    def unblock_settlement(self, bundle_hash: str) -> bool:
        """
        Manually unblock settlement for a bundle.

        Use with caution - only for dispute resolution.
        """
        if bundle_hash in self._blocked_bundles:
            self._blocked_bundles.discard(bundle_hash)
            logger.info(f"Unblocked settlement for {bundle_hash}")
            return True
        return False

    @property
    def failures(self) -> list[DAFailureRecord]:
        """All recorded DA failures."""
        return list(self._failures)

    @property
    def blocked_bundles(self) -> set[str]:
        """Bundles currently blocked from settlement."""
        return set(self._blocked_bundles)


async def check_availability_obligation(
    obligation: AvailabilityObligation,
    fetchers: list[BundleFetcher] | None = None,
    bond_registry: DABondRegistry | None = None,
) -> AvailabilityCheck:
    """
    Convenience function to check an availability obligation.

    Args:
        obligation: The availability obligation to check
        fetchers: Optional list of fetchers (defaults to local fetchers)
        bond_registry: Optional bond registry for slash tracking

    Returns:
        AvailabilityCheck with results from all fetchers
    """
    if fetchers:
        checker = MultiFetcherChecker(fetchers=fetchers, bond_registry=bond_registry)
    else:
        checker = MultiFetcherChecker.default(bond_registry=bond_registry)

    return await checker.check_obligation(obligation)


__all__ = [
    "BundleFetcher",
    "LocalFetcher",
    "HTTPFetcher",
    "IPFSFetcher",
    "MultiFetcherChecker",
    "DAFailureRecord",
    "DAFailureDetector",
    "check_availability_obligation",
]
