"""
Ethereum Attestation Service (EAS) client for Base.

Provides:
- Schema registration and lookup
- Attestation creation and verification
- Batch attestation via Merkle roots
- Multi-chain support (Base, Base Sepolia, Ethereum)

Reference: https://attest.org/
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from enum import Enum

from cyntra.trust.attestation.schemas import EasRef, EasReceiptData

logger = logging.getLogger(__name__)


# EAS Contract Addresses
class EasChain(Enum):
    """Supported EAS chains."""
    
    BASE = 8453
    BASE_SEPOLIA = 84532
    ETHEREUM = 1
    SEPOLIA = 11155111


EAS_ADDRESSES: dict[int, str] = {
    8453: "0x4200000000000000000000000000000000000021",  # Base mainnet
    84532: "0x4200000000000000000000000000000000000021",  # Base Sepolia
    1: "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587",  # Ethereum mainnet
    11155111: "0xC2679fBD37d54388Ce493F1DB75320D236e1815e",  # Sepolia
}

SCHEMA_REGISTRY_ADDRESSES: dict[int, str] = {
    8453: "0x4200000000000000000000000000000000000020",  # Base mainnet
    84532: "0x4200000000000000000000000000000000000020",  # Base Sepolia
    1: "0xA7b39296258348C78294F95B872b282326A97BDF",  # Ethereum mainnet
    11155111: "0x0a7E2Ff54e76B8E6659aedc9103FB21c038050D0",  # Sepolia
}

# CNP Receipt Schema
CNP_RECEIPT_SCHEMA = (
    "bytes32 receiptHash,"
    "bytes32 taskId,"
    "address worker,"
    "bool passed,"
    "uint256 difficulty,"
    "uint256 tokenCount,"
    "uint256 timestamp"
)

# ABI for EAS contract
EAS_ABI = [
    {
        "inputs": [
            {
                "components": [
                    {"name": "schema", "type": "bytes32"},
                    {
                        "components": [
                            {"name": "recipient", "type": "address"},
                            {"name": "expirationTime", "type": "uint64"},
                            {"name": "revocable", "type": "bool"},
                            {"name": "refUID", "type": "bytes32"},
                            {"name": "data", "type": "bytes"},
                            {"name": "value", "type": "uint256"},
                        ],
                        "name": "data",
                        "type": "tuple",
                    },
                ],
                "name": "request",
                "type": "tuple",
            }
        ],
        "name": "attest",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "payable",
        "type": "function",
    },
    {
        "inputs": [{"name": "uid", "type": "bytes32"}],
        "name": "getAttestation",
        "outputs": [
            {
                "components": [
                    {"name": "uid", "type": "bytes32"},
                    {"name": "schema", "type": "bytes32"},
                    {"name": "time", "type": "uint64"},
                    {"name": "expirationTime", "type": "uint64"},
                    {"name": "revocationTime", "type": "uint64"},
                    {"name": "refUID", "type": "bytes32"},
                    {"name": "recipient", "type": "address"},
                    {"name": "attester", "type": "address"},
                    {"name": "revocable", "type": "bool"},
                    {"name": "data", "type": "bytes"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "uid", "type": "bytes32"}],
        "name": "isAttestationValid",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
]

SCHEMA_REGISTRY_ABI = [
    {
        "inputs": [
            {"name": "schema", "type": "string"},
            {"name": "resolver", "type": "address"},
            {"name": "revocable", "type": "bool"},
        ],
        "name": "register",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "uid", "type": "bytes32"}],
        "name": "getSchema",
        "outputs": [
            {
                "components": [
                    {"name": "uid", "type": "bytes32"},
                    {"name": "resolver", "type": "address"},
                    {"name": "revocable", "type": "bool"},
                    {"name": "schema", "type": "string"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
]


@dataclass
class EasConfig:
    """Configuration for EAS client."""
    
    # Chain selection
    chain_id: int = 8453  # Base mainnet
    
    # RPC endpoints
    rpc_url: Optional[str] = None
    
    # Wallet
    private_key: Optional[str] = None  # Hex-encoded private key
    
    # Schema
    schema_uid: Optional[str] = None  # Pre-registered schema UID
    
    # Gas settings
    max_priority_fee_gwei: float = 0.001
    max_fee_gwei: float = 0.01
    
    # Timeouts
    timeout_secs: float = 60.0
    
    @property
    def eas_address(self) -> str:
        return EAS_ADDRESSES.get(self.chain_id, "")
    
    @property
    def schema_registry_address(self) -> str:
        return SCHEMA_REGISTRY_ADDRESSES.get(self.chain_id, "")
    
    @classmethod
    def base_mainnet(cls, rpc_url: str, private_key: str) -> EasConfig:
        """Create config for Base mainnet."""
        return cls(
            chain_id=8453,
            rpc_url=rpc_url,
            private_key=private_key,
        )
    
    @classmethod
    def base_sepolia(cls, rpc_url: str, private_key: str) -> EasConfig:
        """Create config for Base Sepolia testnet."""
        return cls(
            chain_id=84532,
            rpc_url=rpc_url,
            private_key=private_key,
        )


@dataclass
class AttestationData:
    """Data for an EAS attestation."""
    
    schema_uid: str  # bytes32 as hex
    recipient: str = "0x0000000000000000000000000000000000000000"
    expiration_time: int = 0  # 0 = no expiration
    revocable: bool = True
    ref_uid: str = "0x" + "0" * 64  # Reference to another attestation
    data: bytes = b""  # ABI-encoded data
    value: int = 0  # ETH value to send


class EasClient:
    """
    Async client for Ethereum Attestation Service.
    
    Supports:
    - Creating attestations
    - Verifying attestations
    - Schema registration
    - Multi-chain operation
    """
    
    def __init__(self, config: EasConfig):
        self.config = config
        self._web3 = None
        self._account = None
        self._eas_contract = None
        self._schema_registry = None
    
    async def connect(self) -> None:
        """Connect to the blockchain."""
        try:
            from web3 import Web3, AsyncWeb3
            from eth_account import Account
        except ImportError:
            raise ImportError(
                "web3 and eth-account required. Install with: "
                "pip install 'cyntra[attestation]'"
            )
        
        if not self.config.rpc_url:
            raise ValueError("RPC URL required for EAS client")
        
        # Use async Web3
        self._web3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(self.config.rpc_url))
        
        # Set up account if private key provided
        if self.config.private_key:
            self._account = Account.from_key(self.config.private_key)
        
        # Set up contracts
        self._eas_contract = self._web3.eth.contract(
            address=Web3.to_checksum_address(self.config.eas_address),
            abi=EAS_ABI,
        )
        self._schema_registry = self._web3.eth.contract(
            address=Web3.to_checksum_address(self.config.schema_registry_address),
            abi=SCHEMA_REGISTRY_ABI,
        )
        
        # Verify connection
        chain_id = await self._web3.eth.chain_id
        if chain_id != self.config.chain_id:
            logger.warning(
                f"Chain ID mismatch: expected {self.config.chain_id}, got {chain_id}"
            )
        
        logger.info(f"Connected to EAS on chain {chain_id}")
    
    async def disconnect(self) -> None:
        """Disconnect from the blockchain."""
        if self._web3 and hasattr(self._web3.provider, "disconnect"):
            await self._web3.provider.disconnect()
        self._web3 = None
    
    async def __aenter__(self) -> EasClient:
        await self.connect()
        return self
    
    async def __aexit__(self, *args) -> None:
        await self.disconnect()
    
    async def register_schema(
        self,
        schema: str = CNP_RECEIPT_SCHEMA,
        resolver: str = "0x0000000000000000000000000000000000000000",
        revocable: bool = True,
    ) -> str:
        """
        Register a new schema.
        
        Returns the schema UID.
        """
        if not self._account:
            raise ValueError("Private key required to register schema")
        
        from web3 import Web3
        
        # Build transaction
        tx = await self._schema_registry.functions.register(
            schema,
            Web3.to_checksum_address(resolver),
            revocable,
        ).build_transaction({
            "from": self._account.address,
            "nonce": await self._web3.eth.get_transaction_count(self._account.address),
            "maxPriorityFeePerGas": Web3.to_wei(self.config.max_priority_fee_gwei, "gwei"),
            "maxFeePerGas": Web3.to_wei(self.config.max_fee_gwei, "gwei"),
        })
        
        # Sign and send
        signed = self._account.sign_transaction(tx)
        tx_hash = await self._web3.eth.send_raw_transaction(signed.raw_transaction)
        
        # Wait for receipt
        receipt = await self._web3.eth.wait_for_transaction_receipt(
            tx_hash, timeout=self.config.timeout_secs
        )
        
        # Extract schema UID from logs (simplified)
        # In production, parse the Registered event
        schema_uid = receipt["logs"][0]["topics"][1].hex() if receipt["logs"] else ""
        
        logger.info(f"Registered schema: {schema_uid}")
        return schema_uid
    
    async def attest(self, data: AttestationData) -> EasRef:
        """
        Create an attestation.
        
        Returns EasRef with attestation details.
        """
        if not self._account:
            raise ValueError("Private key required to create attestation")
        
        from web3 import Web3
        
        # Build attestation request
        request = (
            bytes.fromhex(data.schema_uid.removeprefix("0x")),
            (
                Web3.to_checksum_address(data.recipient),
                data.expiration_time,
                data.revocable,
                bytes.fromhex(data.ref_uid.removeprefix("0x")),
                data.data,
                data.value,
            ),
        )
        
        # Build transaction
        tx = await self._eas_contract.functions.attest(request).build_transaction({
            "from": self._account.address,
            "value": data.value,
            "nonce": await self._web3.eth.get_transaction_count(self._account.address),
            "maxPriorityFeePerGas": Web3.to_wei(self.config.max_priority_fee_gwei, "gwei"),
            "maxFeePerGas": Web3.to_wei(self.config.max_fee_gwei, "gwei"),
        })
        
        # Estimate gas
        gas_estimate = await self._web3.eth.estimate_gas(tx)
        tx["gas"] = int(gas_estimate * 1.2)  # Add 20% buffer
        
        # Sign and send
        signed = self._account.sign_transaction(tx)
        tx_hash = await self._web3.eth.send_raw_transaction(signed.raw_transaction)
        
        logger.info(f"Attestation tx sent: {tx_hash.hex()}")
        
        # Wait for receipt
        receipt = await self._web3.eth.wait_for_transaction_receipt(
            tx_hash, timeout=self.config.timeout_secs
        )
        
        # Extract attestation UID from logs
        uid = "0x" + receipt["logs"][0]["topics"][1].hex() if receipt["logs"] else ""
        
        return EasRef(
            uid=uid,
            chain_id=self.config.chain_id,
            schema_uid=data.schema_uid,
            attester=self._account.address,
            recipient=data.recipient if data.recipient != "0x" + "0" * 40 else None,
            block_number=receipt["blockNumber"],
            tx_hash=tx_hash.hex(),
            timestamp=datetime.now(timezone.utc),
        )
    
    async def attest_receipt(self, receipt_data: EasReceiptData) -> EasRef:
        """
        Create attestation for a CNP receipt.
        
        Convenience method that handles ABI encoding.
        """
        if not self.config.schema_uid:
            raise ValueError("Schema UID required for receipt attestation")
        
        data = AttestationData(
            schema_uid=self.config.schema_uid,
            recipient=receipt_data.worker,
            data=receipt_data.abi_encode(),
        )
        
        return await self.attest(data)
    
    async def verify(self, uid: str) -> bool:
        """Verify an attestation is valid (exists and not revoked)."""
        uid_bytes = bytes.fromhex(uid.removeprefix("0x"))
        return await self._eas_contract.functions.isAttestationValid(uid_bytes).call()
    
    async def get_attestation(self, uid: str) -> Optional[dict]:
        """Get attestation data by UID."""
        uid_bytes = bytes.fromhex(uid.removeprefix("0x"))
        
        try:
            result = await self._eas_contract.functions.getAttestation(uid_bytes).call()
            
            return {
                "uid": "0x" + result[0].hex(),
                "schema": "0x" + result[1].hex(),
                "time": result[2],
                "expirationTime": result[3],
                "revocationTime": result[4],
                "refUID": "0x" + result[5].hex(),
                "recipient": result[6],
                "attester": result[7],
                "revocable": result[8],
                "data": result[9].hex(),
            }
        except Exception as e:
            logger.error(f"Failed to get attestation {uid}: {e}")
            return None
    
    async def get_schema(self, uid: str) -> Optional[dict]:
        """Get schema by UID."""
        uid_bytes = bytes.fromhex(uid.removeprefix("0x"))
        
        try:
            result = await self._schema_registry.functions.getSchema(uid_bytes).call()
            
            return {
                "uid": "0x" + result[0].hex(),
                "resolver": result[1],
                "revocable": result[2],
                "schema": result[3],
            }
        except Exception as e:
            logger.error(f"Failed to get schema {uid}: {e}")
            return None


# Offline-capable functions (no web3 required)

def encode_receipt_data(
    receipt_hash: str,
    task_id: str,
    worker: str,
    passed: bool,
    difficulty: int,
    token_count: int,
    timestamp: int,
) -> bytes:
    """
    ABI-encode receipt data for EAS attestation.
    
    Can be used offline to prepare attestation data.
    """
    data = EasReceiptData(
        receipt_hash=receipt_hash,
        task_id=task_id,
        worker=worker,
        passed=passed,
        difficulty=difficulty,
        token_count=token_count,
        timestamp=timestamp,
    )
    return data.abi_encode()


def decode_receipt_data(data: bytes) -> EasReceiptData:
    """
    Decode ABI-encoded receipt data.
    """
    if len(data) < 224:  # 7 * 32 bytes
        raise ValueError("Data too short for receipt")
    
    receipt_hash = "0x" + data[0:32].hex()
    task_id = "0x" + data[32:64].hex()
    worker = "0x" + data[76:96].hex()  # Address is right-aligned in 32 bytes
    passed = data[127] == 1
    difficulty = int.from_bytes(data[128:160], "big")
    token_count = int.from_bytes(data[160:192], "big")
    timestamp = int.from_bytes(data[192:224], "big")
    
    return EasReceiptData(
        receipt_hash=receipt_hash,
        task_id=task_id,
        worker=worker,
        passed=passed,
        difficulty=difficulty,
        token_count=token_count,
        timestamp=timestamp,
    )
