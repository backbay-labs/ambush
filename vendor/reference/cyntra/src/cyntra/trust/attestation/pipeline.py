"""
Multi-chain attestation pipeline.

Orchestrates attestation across multiple chains for redundancy
and censorship resistance. Uses Rust backend when available.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from nacl.signing import SigningKey

from cyntra.trust.attestation.schemas import (
    AttestationBundle,
    RekorRef,
    EasRef,
    SolanaRef,
    EasReceiptData,
    is_rust_backend,
)
from cyntra.trust.attestation.rekor import RekorClient

# Try to use Rust hashing
try:
    from cyntra_trust import sha256 as _rust_sha256
    def _hash_receipt(data: bytes) -> str:
        return _rust_sha256(data).to_hex_prefixed()
except ImportError:
    import hashlib
    def _hash_receipt(data: bytes) -> str:
        return "0x" + hashlib.sha256(data).hexdigest()


logger = logging.getLogger(__name__)


@dataclass
class AttestationConfig:
    """Configuration for attestation pipeline."""

    # Enable/disable chains
    rekor_enabled: bool = True
    eas_enabled: bool = False  # Requires wallet
    solana_enabled: bool = False  # Future

    # Chain-specific config
    rekor_url: str = "https://rekor.sigstore.dev"
    eas_chain_id: int = 8453  # Base mainnet
    eas_rpc_url: Optional[str] = None
    solana_cluster: str = "devnet"

    # Signing keys
    signing_key_path: Optional[Path] = None

    # Retry config
    max_retries: int = 3
    retry_delay: float = 1.0


@dataclass
class AttestationResult:
    """Result of attestation operation."""

    success: bool
    bundle: Optional[AttestationBundle] = None
    errors: list[str] = field(default_factory=list)
    chains_attempted: list[str] = field(default_factory=list)
    chains_succeeded: list[str] = field(default_factory=list)


class AttestationPipeline:
    """
    Multi-chain attestation pipeline.

    Publishes receipts to multiple chains for redundancy.
    """

    def __init__(self, config: Optional[AttestationConfig] = None):
        self.config = config or AttestationConfig()
        self._signing_key: Optional[SigningKey] = None
        self._rekor_client: Optional[RekorClient] = None

    def load_signing_key(self, key_path: Optional[Path] = None) -> None:
        """Load signing key from file."""
        path = key_path or self.config.signing_key_path
        if path and path.exists():
            key_hex = path.read_text().strip()
            seed = bytes.fromhex(key_hex)
            self._signing_key = SigningKey(seed)
        else:
            # Generate ephemeral key for testing
            self._signing_key = SigningKey.generate()
            logger.warning("Using ephemeral signing key (not for production)")

    async def attest(
        self,
        receipt_hash: str,
        receipt_data: Optional[dict] = None,
    ) -> AttestationResult:
        """
        Attest a receipt hash to all enabled chains.

        Args:
            receipt_hash: SHA-256 hash of the receipt (hex-encoded)
            receipt_data: Optional receipt data for EAS attestation

        Returns:
            AttestationResult with bundle and status
        """
        result = AttestationResult(success=False)
        
        # Create bundle - Rust backend needs Hash object
        if is_rust_backend():
            from cyntra_trust import Hash
            hash_obj = Hash.from_hex(receipt_hash.removeprefix("0x"))
            bundle = AttestationBundle(receipt_hash=hash_obj)
        else:
            bundle = AttestationBundle(
                receipt_hash=receipt_hash.removeprefix("0x"),
                created_at=datetime.now(timezone.utc),
            )

        # Ensure signing key is loaded
        if self._signing_key is None:
            self.load_signing_key()

        # Run attestations in parallel
        tasks = []

        if self.config.rekor_enabled:
            result.chains_attempted.append("rekor")
            tasks.append(self._attest_rekor(receipt_hash))

        if self.config.eas_enabled and receipt_data:
            result.chains_attempted.append(f"eas-{self.config.eas_chain_id}")
            tasks.append(self._attest_eas(receipt_hash, receipt_data))

        if self.config.solana_enabled:
            result.chains_attempted.append(f"solana-{self.config.solana_cluster}")
            tasks.append(self._attest_solana(receipt_hash))

        if not tasks:
            result.errors.append("No attestation chains enabled")
            return result

        # Execute all attestations
        attestation_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect results
        for chain, att_result in zip(result.chains_attempted, attestation_results):
            if isinstance(att_result, Exception):
                logger.error(f"Attestation failed for {chain}: {att_result}")
                result.errors.append(f"{chain}: {str(att_result)}")
            elif att_result is not None:
                # Use appropriate add method for Rust backend
                if is_rust_backend():
                    if isinstance(att_result, RekorRef):
                        bundle.add_rekor(att_result)
                    elif isinstance(att_result, EasRef):
                        bundle.add_eas(att_result)
                    elif isinstance(att_result, SolanaRef):
                        bundle.add_solana(att_result)
                else:
                    bundle.add(att_result)
                result.chains_succeeded.append(chain)

        # Success if at least one attestation succeeded
        result.success = len(result.chains_succeeded) > 0
        result.bundle = bundle if result.success else None

        return result

    async def _attest_rekor(self, receipt_hash: str) -> Optional[RekorRef]:
        """Attest to Rekor transparency log."""
        if self._signing_key is None:
            raise ValueError("Signing key not loaded")

        client = RekorClient(self.config.rekor_url)

        for attempt in range(self.config.max_retries):
            try:
                async with client:
                    ref = await client.publish(receipt_hash, self._signing_key)
                    logger.info(
                        f"Published to Rekor: uuid={ref.uuid}, "
                        f"log_index={ref.log_index}"
                    )
                    return ref
            except Exception as e:
                if attempt < self.config.max_retries - 1:
                    logger.warning(
                        f"Rekor attempt {attempt + 1} failed: {e}, retrying..."
                    )
                    await asyncio.sleep(self.config.retry_delay)
                else:
                    raise

        return None

    async def _attest_eas(
        self,
        receipt_hash: str,
        receipt_data: dict,
    ) -> Optional[EasRef]:
        """
        Attest to Ethereum Attestation Service.

        NOTE: Full EAS integration requires web3.py and a wallet.
        This is a placeholder that returns None until implemented.
        """
        # TODO: Implement EAS attestation
        # This requires:
        # 1. Web3.py for contract interaction
        # 2. A funded wallet for gas
        # 3. EAS contract addresses for the target chain

        logger.warning("EAS attestation not yet implemented")
        return None

    async def _attest_solana(self, receipt_hash: str) -> Optional[SolanaRef]:
        """
        Attest to Solana Aegis program.

        NOTE: Solana integration requires solana-py and a wallet.
        This is a placeholder that returns None until implemented.
        """
        # TODO: Implement Solana attestation
        # This requires:
        # 1. solana-py for RPC interaction
        # 2. A funded wallet for fees
        # 3. Deployed Aegis program

        logger.warning("Solana attestation not yet implemented")
        return None

    async def verify(
        self,
        bundle: AttestationBundle,
        expected_hash: str,
    ) -> dict[str, bool]:
        """
        Verify all attestations in a bundle.

        Args:
            bundle: Attestation bundle to verify
            expected_hash: Expected receipt hash

        Returns:
            Dict mapping chain_id to verification result
        """
        results: dict[str, bool] = {}

        for attestation in bundle.attestations:
            if isinstance(attestation, RekorRef):
                try:
                    client = RekorClient(attestation.rekor_url)
                    async with client:
                        valid = await client.verify(attestation, expected_hash)
                        results["rekor"] = valid
                except Exception as e:
                    logger.error(f"Rekor verification failed: {e}")
                    results["rekor"] = False

            elif isinstance(attestation, EasRef):
                # TODO: Implement EAS verification
                results[attestation.chain_name] = False

            elif isinstance(attestation, SolanaRef):
                # TODO: Implement Solana verification
                chain_id = f"solana-{attestation.cluster}"
                results[chain_id] = False

        return results

    def save_bundle(self, bundle: AttestationBundle, path: Path) -> None:
        """Save attestation bundle to file."""
        if is_rust_backend():
            path.write_text(bundle.to_json())
        else:
            path.write_text(json.dumps(bundle.to_dict(), indent=2))

    def load_bundle(self, path: Path) -> AttestationBundle:
        """Load attestation bundle from file."""
        if is_rust_backend():
            return AttestationBundle.from_json(path.read_text())
        data = json.loads(path.read_text())
        return AttestationBundle.from_dict(data)


async def attest_receipt(
    receipt_hash: str,
    signing_key: Optional[SigningKey] = None,
    config: Optional[AttestationConfig] = None,
) -> AttestationResult:
    """
    Convenience function to attest a receipt hash.

    Args:
        receipt_hash: SHA-256 hash of the receipt
        signing_key: Optional signing key (generated if not provided)
        config: Optional attestation config

    Returns:
        AttestationResult with bundle
    """
    pipeline = AttestationPipeline(config)
    if signing_key:
        pipeline._signing_key = signing_key
    else:
        pipeline.load_signing_key()

    return await pipeline.attest(receipt_hash)
