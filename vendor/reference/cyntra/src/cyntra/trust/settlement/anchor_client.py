"""
AnchorPy integration for Aegis Solana programs.

Provides typed Python clients for:
- AegisRegistry: Receipt commitments and attestations (updated per spec)
- AegisStaking: Verifier staking and slashing  
- AegisFeeMarket: Offers, tasks, and settlement (updated per spec)
- AegisIncident: Security incident reporting (new)

Requires: pip install 'cyntra[settlement]'
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Try to import Solana/Anchor dependencies
_ANCHOR_AVAILABLE = False
try:
    from anchorpy import Idl, Program, Provider, Wallet
    from anchorpy.program.context import Context
    from solders.keypair import Keypair
    from solders.pubkey import Pubkey
    from solders.system_program import ID as SYS_PROGRAM_ID
    from solana.rpc.async_api import AsyncClient
    from solana.rpc.commitment import Confirmed
    import base58
    _ANCHOR_AVAILABLE = True
except ImportError:
    logger.debug("anchorpy/solana not installed, using stub mode")


# Default program IDs (devnet)
DEFAULT_PROGRAM_IDS = {
    "aegis_registry": "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS",
    "aegis_staking": "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnT",
    "aegis_fee_market": "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnU",
    "aegis_incident": "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnI",
}


@dataclass
class AnchorConfig:
    """Configuration for Anchor clients."""
    
    rpc_url: str = "https://api.devnet.solana.com"
    keypair_path: Optional[Path] = None
    program_ids: dict[str, str] = None
    commitment: str = "confirmed"
    
    def __post_init__(self):
        if self.program_ids is None:
            self.program_ids = DEFAULT_PROGRAM_IDS.copy()


def _load_keypair(path: Path) -> "Keypair":
    """Load a Solana keypair from file."""
    with open(path) as f:
        secret = json.load(f)
    return Keypair.from_bytes(bytes(secret))


def _find_pda(seeds: list[bytes], program_id: "Pubkey") -> tuple["Pubkey", int]:
    """Find a program derived address."""
    return Pubkey.find_program_address(seeds, program_id)


class AegisRegistryAnchor:
    """
    AnchorPy client for AegisRegistry program.
    
    Updated to match spec with full commitment fields:
    - receipt_hash: SHA-256 of canonical receipt JSON
    - manifest_hash: SHA-256 of RunManifest
    - policy_hash: SHA-256 of SecurityPolicy
    - bundle_hash: SHA-256 of proof bundle
    - ledger_root: Merkle root of anchored events
    """
    
    def __init__(self, config: AnchorConfig):
        self.config = config
        self._provider: Optional["Provider"] = None
        self._program: Optional["Program"] = None
        
    async def connect(self) -> None:
        """Connect to the program."""
        if not _ANCHOR_AVAILABLE:
            raise ImportError("anchorpy not installed. Run: pip install 'cyntra[settlement]'")
        
        client = AsyncClient(self.config.rpc_url, commitment=Confirmed)
        
        if self.config.keypair_path:
            keypair = _load_keypair(self.config.keypair_path)
        else:
            keypair = Keypair()
            
        wallet = Wallet(keypair)
        self._provider = Provider(client, wallet)
        
        program_id = Pubkey.from_string(self.config.program_ids["aegis_registry"])
        
        idl_path = Path(__file__).parent.parent.parent.parent.parent / "solana" / "target" / "idl" / "aegis_registry.json"
        if idl_path.exists():
            with open(idl_path) as f:
                idl = Idl.from_json(f.read())
            self._program = Program(idl, program_id, self._provider)
        else:
            self._program = await Program.at(program_id, self._provider)
        
        logger.info(f"Connected to AegisRegistry at {program_id}")
    
    async def disconnect(self) -> None:
        """Disconnect from the program."""
        if self._provider:
            await self._provider.connection.close()
        self._provider = None
        self._program = None
    
    async def __aenter__(self) -> "AegisRegistryAnchor":
        await self.connect()
        return self
    
    async def __aexit__(self, *args) -> None:
        await self.disconnect()
    
    async def post_receipt(
        self,
        receipt_hash: bytes,
        manifest_hash: bytes,
        policy_hash: bytes,
        bundle_hash: bytes,
        bundle_uri: str,
        ledger_root: bytes,
    ) -> dict:
        """
        Post a receipt commitment with full cryptographic chain.
        
        Args:
            receipt_hash: 32-byte SHA-256 of canonical receipt JSON
            manifest_hash: 32-byte SHA-256 of RunManifest
            policy_hash: 32-byte SHA-256 of SecurityPolicy
            bundle_hash: 32-byte SHA-256 of proof bundle contents
            bundle_uri: URI to proof bundle (IPFS, S3, etc.)
            ledger_root: 32-byte Merkle root of anchored ledger events
            
        Returns:
            Transaction result with signature and PDA
        """
        if not self._program:
            raise RuntimeError("Not connected")
        
        program_id = self._program.program_id
        receipt_pda, bump = _find_pda([b"receipt", receipt_hash], program_id)
        
        tx = await self._program.rpc["post_receipt"](
            list(receipt_hash),
            list(manifest_hash),
            list(policy_hash),
            list(bundle_hash),
            bundle_uri,
            list(ledger_root),
            ctx=Context(
                accounts={
                    "receipt": receipt_pda,
                    "submitter": self._provider.wallet.public_key,
                    "system_program": SYS_PROGRAM_ID,
                },
            ),
        )
        
        logger.info(f"Posted receipt: {tx}")
        
        return {
            "signature": str(tx),
            "receipt_pda": str(receipt_pda),
            "receipt_hash": receipt_hash.hex(),
        }
    
    async def submit_attestation(
        self,
        receipt_hash: bytes,
        verdict: str,  # "Approve" or "Reject"
        signature: bytes,
        proof_pointer: str,
    ) -> dict:
        """
        Submit an attestation for a receipt.
        
        Args:
            receipt_hash: Hash of the receipt to attest
            verdict: "Approve" or "Reject"
            signature: Ed25519 signature over receipt hash
            proof_pointer: URI to detailed proof
            
        Returns:
            Transaction result
        """
        if not self._program:
            raise RuntimeError("Not connected")
        
        program_id = self._program.program_id
        
        receipt_pda, _ = _find_pda([b"receipt", receipt_hash], program_id)
        attestation_pda, _ = _find_pda(
            [b"attestation", bytes(receipt_pda), bytes(self._provider.wallet.public_key)],
            program_id
        )
        
        # Convert verdict to enum
        verdict_enum = {
            "Approve": {"approve": {}},
            "Reject": {"reject": {}},
        }[verdict]
        
        tx = await self._program.rpc["submit_attestation"](
            list(receipt_hash),
            verdict_enum,
            list(signature),
            proof_pointer,
            ctx=Context(
                accounts={
                    "receipt": receipt_pda,
                    "attestation": attestation_pda,
                    "verifier": self._provider.wallet.public_key,
                    "system_program": SYS_PROGRAM_ID,
                },
            ),
        )
        
        logger.info(f"Submitted attestation: {tx}")
        
        return {
            "signature": str(tx),
            "attestation_pda": str(attestation_pda),
        }
    
    async def finalize_receipt(self, receipt_hash: bytes, quorum: int = 2) -> dict:
        """Finalize a receipt after quorum reached."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        program_id = self._program.program_id
        receipt_pda, _ = _find_pda([b"receipt", receipt_hash], program_id)
        
        tx = await self._program.rpc["finalize_receipt"](
            quorum,
            ctx=Context(
                accounts={
                    "receipt": receipt_pda,
                    "authority": self._provider.wallet.public_key,
                },
            ),
        )
        
        return {"signature": str(tx)}
    
    async def get_receipt(self, receipt_hash: bytes) -> Optional[dict]:
        """Get receipt account data."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        program_id = self._program.program_id
        receipt_pda, _ = _find_pda([b"receipt", receipt_hash], program_id)
        
        try:
            account = await self._program.account["ReceiptAccount"].fetch(receipt_pda)
            return {
                "submitter": str(account.submitter),
                "receipt_hash": bytes(account.receipt_hash).hex(),
                "manifest_hash": bytes(account.manifest_hash).hex(),
                "policy_hash": bytes(account.policy_hash).hex(),
                "bundle_hash": bytes(account.bundle_hash).hex(),
                "bundle_uri": account.bundle_uri,
                "ledger_root": bytes(account.ledger_root).hex(),
                "status": str(account.status),
                "attestation_count": account.attestation_count,
                "created_at": account.created_at,
                "updated_at": account.updated_at,
            }
        except Exception as e:
            logger.debug(f"Receipt not found: {e}")
            return None


class AegisStakingAnchor:
    """
    AnchorPy client for AegisStaking program.
    """
    
    def __init__(self, config: AnchorConfig):
        self.config = config
        self._provider: Optional["Provider"] = None
        self._program: Optional["Program"] = None
    
    async def connect(self) -> None:
        """Connect to the program."""
        if not _ANCHOR_AVAILABLE:
            raise ImportError("anchorpy not installed")
        
        client = AsyncClient(self.config.rpc_url, commitment=Confirmed)
        
        if self.config.keypair_path:
            keypair = _load_keypair(self.config.keypair_path)
        else:
            keypair = Keypair()
            
        wallet = Wallet(keypair)
        self._provider = Provider(client, wallet)
        
        program_id = Pubkey.from_string(self.config.program_ids["aegis_staking"])
        
        idl_path = Path(__file__).parent.parent.parent.parent.parent / "solana" / "target" / "idl" / "aegis_staking.json"
        if idl_path.exists():
            with open(idl_path) as f:
                idl = Idl.from_json(f.read())
            self._program = Program(idl, program_id, self._provider)
        else:
            self._program = await Program.at(program_id, self._provider)
        
        logger.info(f"Connected to AegisStaking at {program_id}")
    
    async def disconnect(self) -> None:
        if self._provider:
            await self._provider.connection.close()
    
    async def __aenter__(self) -> "AegisStakingAnchor":
        await self.connect()
        return self
    
    async def __aexit__(self, *args) -> None:
        await self.disconnect()
    
    async def stake(self, amount: int) -> dict:
        """
        Stake tokens (simplified - uses native SOL).
        
        Args:
            amount: Amount in lamports
            
        Returns:
            Transaction result
        """
        if not self._program:
            raise RuntimeError("Not connected")
        
        program_id = self._program.program_id
        
        config_pda, _ = _find_pda([b"config"], program_id)
        stake_pda, _ = _find_pda(
            [b"stake", bytes(self._provider.wallet.public_key)],
            program_id
        )
        
        tx = await self._program.rpc["stake"](
            amount,
            ctx=Context(
                accounts={
                    "config": config_pda,
                    "stake_account": stake_pda,
                    "user": self._provider.wallet.public_key,
                    "system_program": SYS_PROGRAM_ID,
                },
            ),
        )
        
        return {"signature": str(tx), "stake_account": str(stake_pda)}
    
    async def begin_unbond(self, amount: int) -> dict:
        """Begin unbonding tokens."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        program_id = self._program.program_id
        
        config_pda, _ = _find_pda([b"config"], program_id)
        stake_pda, _ = _find_pda(
            [b"stake", bytes(self._provider.wallet.public_key)],
            program_id
        )
        
        # Get current unbond nonce from stake account
        stake_account = await self._program.account["StakeAccount"].fetch(stake_pda)
        nonce = stake_account.unbond_nonce
        
        unbond_pda, _ = _find_pda(
            [b"unbond", bytes(stake_pda), nonce.to_bytes(8, "little")],
            program_id
        )
        
        tx = await self._program.rpc["begin_unbond"](
            amount,
            ctx=Context(
                accounts={
                    "config": config_pda,
                    "stake_account": stake_pda,
                    "unbond_account": unbond_pda,
                    "user": self._provider.wallet.public_key,
                    "owner": self._provider.wallet.public_key,
                    "system_program": SYS_PROGRAM_ID,
                },
            ),
        )
        
        return {"signature": str(tx), "unbond_account": str(unbond_pda)}
    
    async def get_stake(self) -> Optional[dict]:
        """Get current stake account."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        program_id = self._program.program_id
        stake_pda, _ = _find_pda(
            [b"stake", bytes(self._provider.wallet.public_key)],
            program_id
        )
        
        try:
            account = await self._program.account["StakeAccount"].fetch(stake_pda)
            return {
                "owner": str(account.owner),
                "amount": account.amount,
                "unbonding_amount": account.unbonding_amount,
                "status": str(account.status),
                "total_slashed": account.total_slashed,
            }
        except Exception:
            return None


class AegisFeeMarketAnchor:
    """
    AnchorPy client for AegisFeeMarket program.
    
    Updated with offer system per spec:
    - offer_create: Create builder/verifier/responder offers
    - offer_update: Update offer parameters
    - offer_retire: Retire an offer
    - task_create: Create task referencing an offer
    - task_claim: Claim for execution
    - task_complete: Submit completion with receipt
    - task_attest: Submit verification attestation
    - task_finalize: Finalize after quorum
    """
    
    def __init__(self, config: AnchorConfig):
        self.config = config
        self._provider: Optional["Provider"] = None
        self._program: Optional["Program"] = None
    
    async def connect(self) -> None:
        """Connect to the program."""
        if not _ANCHOR_AVAILABLE:
            raise ImportError("anchorpy not installed")
        
        client = AsyncClient(self.config.rpc_url, commitment=Confirmed)
        
        if self.config.keypair_path:
            keypair = _load_keypair(self.config.keypair_path)
        else:
            keypair = Keypair()
            
        wallet = Wallet(keypair)
        self._provider = Provider(client, wallet)
        
        program_id = Pubkey.from_string(self.config.program_ids["aegis_fee_market"])
        
        idl_path = Path(__file__).parent.parent.parent.parent.parent / "solana" / "target" / "idl" / "aegis_fee_market.json"
        if idl_path.exists():
            with open(idl_path) as f:
                idl = Idl.from_json(f.read())
            self._program = Program(idl, program_id, self._provider)
        else:
            self._program = await Program.at(program_id, self._provider)
        
        logger.info(f"Connected to AegisFeeMarket at {program_id}")
    
    async def disconnect(self) -> None:
        if self._provider:
            await self._provider.connection.close()
    
    async def __aenter__(self) -> "AegisFeeMarketAnchor":
        await self.connect()
        return self
    
    async def __aexit__(self, *args) -> None:
        await self.disconnect()
    
    # ========================================================================
    # Offer methods
    # ========================================================================
    
    async def offer_create(
        self,
        offer_type: str,  # "Builder", "Verifier", "Responder"
        capabilities_hash: bytes,
        price_model: str,  # "Fixed", "PerMinute", "PerArtifact"
        price: int,
        min_stake: int,
        sla_latency_seconds: int,
        max_runtime_seconds: int,
        policy_hashes_allowed: list[bytes],
    ) -> dict:
        """Create a new offer."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        program_id = self._program.program_id
        config_pda, _ = _find_pda([b"config"], program_id)
        
        # Get offer count for PDA seed
        config = await self._program.account["FeeMarketConfig"].fetch(config_pda)
        offer_count = config.total_offers
        
        offer_pda, _ = _find_pda(
            [b"offer", bytes(self._provider.wallet.public_key), offer_count.to_bytes(8, "little")],
            program_id
        )
        
        offer_type_enum = {
            "Builder": {"builder": {}},
            "Verifier": {"verifier": {}},
            "Responder": {"responder": {}},
        }[offer_type]
        
        price_model_enum = {
            "Fixed": {"fixed": {}},
            "PerMinute": {"perMinute": {}},
            "PerArtifact": {"perArtifact": {}},
        }[price_model]
        
        tx = await self._program.rpc["offer_create"](
            offer_type_enum,
            list(capabilities_hash),
            price_model_enum,
            price,
            min_stake,
            sla_latency_seconds,
            max_runtime_seconds,
            [list(h) for h in policy_hashes_allowed],
            ctx=Context(
                accounts={
                    "config": config_pda,
                    "offer": offer_pda,
                    "owner": self._provider.wallet.public_key,
                    "system_program": SYS_PROGRAM_ID,
                },
            ),
        )
        
        return {"signature": str(tx), "offer_pda": str(offer_pda)}
    
    async def offer_update(
        self,
        offer_pda: str,
        status: Optional[str] = None,  # "Active", "Paused"
        price: Optional[int] = None,
        sla_latency_seconds: Optional[int] = None,
        max_runtime_seconds: Optional[int] = None,
    ) -> dict:
        """Update an offer."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        status_enum = None
        if status:
            status_enum = {
                "Active": {"active": {}},
                "Paused": {"paused": {}},
            }.get(status)
        
        tx = await self._program.rpc["offer_update"](
            status_enum,
            price,
            sla_latency_seconds,
            max_runtime_seconds,
            ctx=Context(
                accounts={
                    "offer": Pubkey.from_string(offer_pda),
                    "owner": self._provider.wallet.public_key,
                },
            ),
        )
        
        return {"signature": str(tx)}
    
    async def offer_retire(self, offer_pda: str) -> dict:
        """Retire an offer."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        tx = await self._program.rpc["offer_retire"](
            ctx=Context(
                accounts={
                    "offer": Pubkey.from_string(offer_pda),
                    "owner": self._provider.wallet.public_key,
                },
            ),
        )
        
        return {"signature": str(tx)}
    
    async def get_offer(self, offer_pda: str) -> Optional[dict]:
        """Get offer account data."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        try:
            account = await self._program.account["OfferAccount"].fetch(
                Pubkey.from_string(offer_pda)
            )
            return {
                "offer_id": str(account.offer_id),
                "owner": str(account.owner),
                "offer_type": str(account.offer_type),
                "capabilities_hash": bytes(account.capabilities_hash).hex(),
                "price_model": str(account.price_model),
                "price": account.price,
                "min_stake": account.min_stake,
                "sla_latency_seconds": account.sla_latency_seconds,
                "max_runtime_seconds": account.max_runtime_seconds,
                "status": str(account.status),
                "created_at": account.created_at,
                "updated_at": account.updated_at,
            }
        except Exception as e:
            logger.debug(f"Offer not found: {e}")
            return None
    
    # ========================================================================
    # Task methods
    # ========================================================================
    
    async def task_create(
        self,
        offer_pda: str,
        manifest_hash: bytes,
        policy_hash: bytes,
        bundle_requirements_hash: bytes,
        deadline_ts: int,
        escrow_amount: int,
        verifier_quorum: int = 2,
    ) -> dict:
        """Create a task referencing an offer."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        program_id = self._program.program_id
        
        config_pda, _ = _find_pda([b"config"], program_id)
        task_pda, _ = _find_pda([b"task", manifest_hash], program_id)
        escrow_pda, _ = _find_pda([b"escrow", bytes(task_pda)], program_id)
        
        tx = await self._program.rpc["task_create"](
            list(manifest_hash),
            list(policy_hash),
            list(bundle_requirements_hash),
            deadline_ts,
            escrow_amount,
            verifier_quorum,
            ctx=Context(
                accounts={
                    "config": config_pda,
                    "offer": Pubkey.from_string(offer_pda),
                    "task": task_pda,
                    "escrow_vault": escrow_pda,
                    "requester": self._provider.wallet.public_key,
                    "system_program": SYS_PROGRAM_ID,
                },
            ),
        )
        
        return {
            "signature": str(tx),
            "task_pda": str(task_pda),
            "escrow_pda": str(escrow_pda),
        }
    
    async def task_claim(self, task_pda: str) -> dict:
        """Claim a task for execution."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        tx = await self._program.rpc["task_claim"](
            ctx=Context(
                accounts={
                    "task": Pubkey.from_string(task_pda),
                    "claimer": self._provider.wallet.public_key,
                },
            ),
        )
        
        return {"signature": str(tx)}
    
    async def task_complete(self, task_pda: str, receipt_hash: bytes) -> dict:
        """Complete a task with receipt hash."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        tx = await self._program.rpc["task_complete"](
            list(receipt_hash),
            ctx=Context(
                accounts={
                    "task": Pubkey.from_string(task_pda),
                    "claimer": self._provider.wallet.public_key,
                },
            ),
        )
        
        return {"signature": str(tx)}
    
    async def task_attest(self, task_pda: str, verdict: str) -> dict:
        """Submit verification attestation."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        verdict_enum = {
            "Approve": {"approve": {}},
            "Reject": {"reject": {}},
        }[verdict]
        
        tx = await self._program.rpc["task_attest"](
            verdict_enum,
            ctx=Context(
                accounts={
                    "task": Pubkey.from_string(task_pda),
                    "verifier": self._provider.wallet.public_key,
                },
            ),
        )
        
        return {"signature": str(tx)}
    
    async def task_finalize(self, task_pda: str, quorum: int = 2) -> dict:
        """Finalize a task after quorum."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        program_id = self._program.program_id
        config_pda, _ = _find_pda([b"config"], program_id)
        
        tx = await self._program.rpc["task_finalize"](
            quorum,
            ctx=Context(
                accounts={
                    "config": config_pda,
                    "task": Pubkey.from_string(task_pda),
                    "authority": self._provider.wallet.public_key,
                },
            ),
        )
        
        return {"signature": str(tx)}
    
    async def get_task(self, task_pda: str) -> Optional[dict]:
        """Get task account data."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        try:
            account = await self._program.account["TaskAccount"].fetch(
                Pubkey.from_string(task_pda)
            )
            return {
                "task_id": str(account.task_id),
                "offer_id": str(account.offer_id),
                "requester": str(account.requester),
                "manifest_hash": bytes(account.manifest_hash).hex(),
                "policy_hash": bytes(account.policy_hash).hex(),
                "status": str(account.status),
                "escrow_amount": account.escrow_amount,
                "verifier_quorum": account.verifier_quorum,
                "claimer": str(account.claimer) if account.claimer else None,
                "receipt_hash": bytes(account.receipt_hash).hex() if account.receipt_hash else None,
                "attestation_count": account.attestation_count,
                "builder_payout": account.builder_payout,
                "verifier_payout_each": account.verifier_payout_each,
                "created_at": account.created_at,
            }
        except Exception as e:
            logger.debug(f"Task not found: {e}")
            return None


class AegisIncidentAnchor:
    """
    AnchorPy client for AegisIncident program.
    
    Methods:
    - incident_report: Report a security incident
    - incident_verify: Verify an incident
    - incident_finalize: Finalize incident status
    - incident_grant_decrypt: Grant decrypt access
    - incident_payout: Pay bounty to reporter
    """
    
    def __init__(self, config: AnchorConfig):
        self.config = config
        self._provider: Optional["Provider"] = None
        self._program: Optional["Program"] = None
    
    async def connect(self) -> None:
        """Connect to the program."""
        if not _ANCHOR_AVAILABLE:
            raise ImportError("anchorpy not installed")
        
        client = AsyncClient(self.config.rpc_url, commitment=Confirmed)
        
        if self.config.keypair_path:
            keypair = _load_keypair(self.config.keypair_path)
        else:
            keypair = Keypair()
            
        wallet = Wallet(keypair)
        self._provider = Provider(client, wallet)
        
        program_id = Pubkey.from_string(self.config.program_ids["aegis_incident"])
        
        idl_path = Path(__file__).parent.parent.parent.parent.parent / "solana" / "target" / "idl" / "aegis_incident.json"
        if idl_path.exists():
            with open(idl_path) as f:
                idl = Idl.from_json(f.read())
            self._program = Program(idl, program_id, self._provider)
        else:
            self._program = await Program.at(program_id, self._provider)
        
        logger.info(f"Connected to AegisIncident at {program_id}")
    
    async def disconnect(self) -> None:
        if self._provider:
            await self._provider.connection.close()
    
    async def __aenter__(self) -> "AegisIncidentAnchor":
        await self.connect()
        return self
    
    async def __aexit__(self, *args) -> None:
        await self.disconnect()
    
    async def incident_report(
        self,
        ioc_hashes: list[bytes],
        severity: str,  # "Low", "Medium", "High", "Critical"
        category: str,  # "DataExfil", "PolicyViolation", etc.
        policy_hash: bytes,
        bundle_hash: bytes,
        bundle_uri: str,
        bounty: int = 0,
    ) -> dict:
        """Report a security incident."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        program_id = self._program.program_id
        
        # Use timestamp for unique PDA
        import time
        ts = int(time.time())
        
        incident_pda, _ = _find_pda(
            [b"incident", bytes(self._provider.wallet.public_key), ts.to_bytes(8, "little")],
            program_id
        )
        escrow_pda, _ = _find_pda([b"escrow", bytes(incident_pda)], program_id)
        
        severity_enum = {
            "Low": {"low": {}},
            "Medium": {"medium": {}},
            "High": {"high": {}},
            "Critical": {"critical": {}},
        }[severity]
        
        category_enum = {
            "DataExfil": {"dataExfil": {}},
            "PolicyViolation": {"policyViolation": {}},
            "MaliciousPatch": {"maliciousPatch": {}},
            "SupplyChainCompromise": {"supplyChainCompromise": {}},
            "JailbreakAttempt": {"jailbreakAttempt": {}},
        }[category]
        
        tx = await self._program.rpc["incident_report"](
            [list(h) for h in ioc_hashes],
            severity_enum,
            category_enum,
            list(policy_hash),
            list(bundle_hash),
            bundle_uri,
            bounty,
            ctx=Context(
                accounts={
                    "incident": incident_pda,
                    "escrow": escrow_pda,
                    "reporter": self._provider.wallet.public_key,
                    "system_program": SYS_PROGRAM_ID,
                },
            ),
        )
        
        return {
            "signature": str(tx),
            "incident_pda": str(incident_pda),
        }
    
    async def incident_verify(self, incident_pda: str, verdict: str) -> dict:
        """Verify an incident report."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        verdict_enum = {
            "Confirm": {"confirm": {}},
            "Reject": {"reject": {}},
        }[verdict]
        
        tx = await self._program.rpc["incident_verify"](
            verdict_enum,
            ctx=Context(
                accounts={
                    "incident": Pubkey.from_string(incident_pda),
                    "verifier": self._provider.wallet.public_key,
                },
            ),
        )
        
        return {"signature": str(tx)}
    
    async def incident_finalize(self, incident_pda: str, status: str) -> dict:
        """Finalize incident status."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        status_enum = {
            "Verified": {"verified": {}},
            "Resolved": {"resolved": {}},
            "Paid": {"paid": {}},
        }[status]
        
        tx = await self._program.rpc["incident_finalize"](
            status_enum,
            ctx=Context(
                accounts={
                    "incident": Pubkey.from_string(incident_pda),
                    "authority": self._provider.wallet.public_key,
                },
            ),
        )
        
        return {"signature": str(tx)}
    
    async def incident_grant_decrypt(
        self,
        incident_pda: str,
        recipient: str,
        expires_at: int,
    ) -> dict:
        """Grant decrypt access to incident bundle."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        program_id = self._program.program_id
        config_pda, _ = _find_pda([b"config"], program_id)
        
        tx = await self._program.rpc["incident_grant_decrypt"](
            recipient,
            expires_at,
            ctx=Context(
                accounts={
                    "incident": Pubkey.from_string(incident_pda),
                    "config": config_pda,
                    "authority": self._provider.wallet.public_key,
                },
            ),
        )
        
        return {"signature": str(tx)}
    
    async def get_incident(self, incident_pda: str) -> Optional[dict]:
        """Get incident account data."""
        if not self._program:
            raise RuntimeError("Not connected")
        
        try:
            account = await self._program.account["IncidentReportAccount"].fetch(
                Pubkey.from_string(incident_pda)
            )
            return {
                "incident_id": str(account.incident_id),
                "reporter": str(account.reporter),
                "severity": str(account.severity),
                "category": str(account.category),
                "policy_hash": bytes(account.policy_hash).hex(),
                "bundle_hash": bytes(account.bundle_hash).hex(),
                "bundle_uri": account.bundle_uri,
                "bounty": account.bounty,
                "status": str(account.status),
                "verification_count": account.verification_count,
                "created_at": account.created_at,
            }
        except Exception as e:
            logger.debug(f"Incident not found: {e}")
            return None


def is_anchor_available() -> bool:
    """Check if AnchorPy is available."""
    return _ANCHOR_AVAILABLE


__all__ = [
    "AnchorConfig",
    "AegisRegistryAnchor",
    "AegisStakingAnchor",
    "AegisFeeMarketAnchor",
    "AegisIncidentAnchor",
    "is_anchor_available",
]
