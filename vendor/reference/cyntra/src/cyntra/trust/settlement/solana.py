"""Solana program clients for the Aegis verifier economy.

Provides Python clients for interacting with the Aegis Solana programs:
- AegisRegistry: RunReceipt commitments and verifier attestations
- AegisStaking: Stake/unbond, objective slashing, and jailing
- AegisFeeMarket: Verification tasks, USDC bounties, and payouts

Requires solana-py and anchorpy for full functionality.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime

from cyntra.core.scheduler.routing import SettlementConfig


class SolanaClientError(RuntimeError):
    """Raised when Solana client is not configured or encounters an error."""


@dataclass
class SolanaProgramIds:
    """Program IDs for Aegis Solana programs."""
    registry: str | None = None
    staking: str | None = None
    fee_market: str | None = None


@dataclass
class ReceiptPosted:
    """Event emitted when a receipt is posted to the registry."""
    receipt_hash: bytes
    submitter: str
    bundle_uri: str
    signature: str


@dataclass 
class AttestationSubmitted:
    """Event emitted when an attestation is submitted."""
    receipt_hash: bytes
    verifier: str
    verdict: str  # "Pass", "Fail", "Skip"
    proof_uri: Optional[str]
    signature: str


@dataclass
class TaskCreated:
    """Event emitted when a verification task is created."""
    task_id: int
    receipt_hash: bytes
    builder: str
    bounty: int
    quorum: int
    deadline: int
    signature: str


class SolanaClient:
    """Base Solana client with RPC integration.
    
    When solana-py is available, provides actual RPC connectivity.
    Otherwise, operates in stub mode for testing.
    """

    def __init__(self, config: SettlementConfig) -> None:
        self.config = config
        self.program_ids = SolanaProgramIds(
            registry=config.registry_program_id,
            staking=config.staking_program_id,
            fee_market=config.fee_market_program_id,
        )
        self._client = None
        self._keypair = None
        
        # Try to initialize actual client
        if config.enabled and config.rpc_url:
            self._init_client()

    def _init_client(self) -> None:
        """Initialize the Solana RPC client."""
        try:
            from solana.rpc.async_api import AsyncClient
            from solders.keypair import Keypair
            
            self._client = AsyncClient(self.config.rpc_url)
            
            # Load keypair if path provided
            if self.config.keypair_path:
                with open(self.config.keypair_path) as f:
                    secret = json.load(f)
                self._keypair = Keypair.from_bytes(bytes(secret))
        except ImportError:
            pass  # solana-py not installed

    def _ensure_configured(self) -> None:
        if not self.config.enabled or not self.config.rpc_url:
            raise SolanaClientError("Solana settlement is not configured")

    @property
    def is_connected(self) -> bool:
        """Check if client is connected to Solana."""
        return self._client is not None


class AegisRegistryClient(SolanaClient):
    """Client for AegisRegistry program.
    
    Manages receipt commitments and verifier attestations.
    """

    async def post_receipt(
        self,
        receipt_hash: str,
        bundle_uri: str,
    ) -> ReceiptPosted:
        """Post a receipt commitment to the registry.
        
        Args:
            receipt_hash: SHA-256 hash of the receipt (hex, no 0x prefix)
            bundle_uri: URI to the proof bundle (IPFS, S3, etc.)
            
        Returns:
            ReceiptPosted event with transaction signature
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        # TODO: Implement actual transaction building with anchorpy
        # For now, return a placeholder
        raise NotImplementedError(
            "AegisRegistry.post_receipt requires anchorpy integration. "
            "See infra/solana/programs/aegis_registry for the on-chain program and "
            "kernel/src/cyntra/trust/settlement/anchor_client.py for the planned client."
        )

    async def submit_attestation(
        self,
        receipt_hash: str,
        verdict: str,
        proof_uri: Optional[str] = None,
    ) -> AttestationSubmitted:
        """Submit an attestation for a receipt.
        
        Args:
            receipt_hash: SHA-256 hash of the receipt
            verdict: "Pass", "Fail", or "Skip"
            proof_uri: Optional URI to detailed proof
            
        Returns:
            AttestationSubmitted event with transaction signature
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        raise NotImplementedError(
            "AegisRegistry.submit_attestation requires anchorpy integration."
        )

    async def get_receipt(self, receipt_hash: str) -> Optional[dict]:
        """Get a receipt account by hash.
        
        Args:
            receipt_hash: SHA-256 hash of the receipt
            
        Returns:
            Receipt account data or None if not found
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        raise NotImplementedError(
            "AegisRegistry.get_receipt requires anchorpy integration."
        )


class AegisStakingClient(SolanaClient):
    """Client for AegisStaking program.
    
    Manages verifier staking, unbonding, and slashing.
    """

    async def stake(self, amount: int) -> str:
        """Stake AEGIS tokens to become a verifier.
        
        Args:
            amount: Amount of AEGIS tokens (in minor units)
            
        Returns:
            Transaction signature
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        raise NotImplementedError(
            "AegisStaking.stake requires anchorpy integration. "
            "See infra/solana/programs/aegis_staking for the on-chain program and "
            "kernel/src/cyntra/trust/settlement/anchor_client.py for the planned client."
        )

    async def begin_unbond(self, amount: int) -> str:
        """Begin unbonding period for staked tokens.
        
        Args:
            amount: Amount to unbond
            
        Returns:
            Transaction signature
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        raise NotImplementedError(
            "AegisStaking.begin_unbond requires anchorpy integration."
        )

    async def complete_unbond(self, unbond_account: str) -> str:
        """Complete unbonding and withdraw tokens.
        
        Args:
            unbond_account: Address of the unbond account
            
        Returns:
            Transaction signature
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        raise NotImplementedError(
            "AegisStaking.complete_unbond requires anchorpy integration."
        )

    async def slash_double_sign(
        self,
        verifier: str,
        proof: dict[str, Any],
    ) -> str:
        """Slash a verifier for double-signing.
        
        Args:
            verifier: Verifier pubkey
            proof: Proof of conflicting attestations
            
        Returns:
            Transaction signature
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        raise NotImplementedError(
            "AegisStaking.slash_double_sign requires anchorpy integration."
        )

    async def get_stake(self, verifier: str) -> Optional[dict]:
        """Get stake account for a verifier.
        
        Args:
            verifier: Verifier pubkey
            
        Returns:
            Stake account data or None
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        raise NotImplementedError(
            "AegisStaking.get_stake requires anchorpy integration."
        )


class AegisFeeMarketClient(SolanaClient):
    """Client for AegisFeeMarket program.
    
    Manages verification tasks, bounties, and payouts.
    """

    async def create_task(
        self,
        receipt_hash: str,
        bounty: int,
        quorum: int = 2,
        deadline_seconds: int = 86400,
    ) -> TaskCreated:
        """Create a verification task with USDC bounty.
        
        Args:
            receipt_hash: SHA-256 hash of the receipt
            bounty: USDC bounty in minor units (6 decimals)
            quorum: Minimum attestations required
            deadline_seconds: Task deadline from now
            
        Returns:
            TaskCreated event with transaction signature
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        raise NotImplementedError(
            "AegisFeeMarket.create_task requires anchorpy integration. "
            "See infra/solana/programs/aegis_fee_market for the on-chain program and "
            "kernel/src/cyntra/trust/settlement/anchor_client.py for the planned client."
        )

    async def claim_task(self, receipt_hash: str) -> str:
        """Claim a verification task.
        
        Args:
            receipt_hash: SHA-256 hash of the receipt
            
        Returns:
            Transaction signature
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        raise NotImplementedError(
            "AegisFeeMarket.claim_task requires anchorpy integration."
        )

    async def submit_result(
        self,
        receipt_hash: str,
        verdict: str,
    ) -> str:
        """Submit verification result for a task.
        
        Args:
            receipt_hash: SHA-256 hash of the receipt
            verdict: "Pass", "Fail", or "Skip"
            
        Returns:
            Transaction signature
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        raise NotImplementedError(
            "AegisFeeMarket.submit_result requires anchorpy integration."
        )

    async def finalize_task(self, receipt_hash: str) -> str:
        """Finalize a task after quorum is reached.
        
        Args:
            receipt_hash: SHA-256 hash of the receipt
            
        Returns:
            Transaction signature
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        raise NotImplementedError(
            "AegisFeeMarket.finalize_task requires anchorpy integration."
        )

    async def get_task(self, receipt_hash: str) -> Optional[dict]:
        """Get task account by receipt hash.
        
        Args:
            receipt_hash: SHA-256 hash of the receipt
            
        Returns:
            Task account data or None
        """
        self._ensure_configured()
        
        if not self._client:
            raise SolanaClientError("solana-py not installed")
            
        raise NotImplementedError(
            "AegisFeeMarket.get_task requires anchorpy integration."
        )


# Default program IDs (devnet)
DEFAULT_PROGRAM_IDS = SolanaProgramIds(
    registry="Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS",
    staking="Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnT",
    fee_market="Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnU",
)
