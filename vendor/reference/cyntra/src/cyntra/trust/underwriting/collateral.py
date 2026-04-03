"""
Collateral management for the verification market.

Handles collateral deposits, haircuts, and value calculations
for the capitalization layer.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class CollateralType(str, Enum):
    """Types of accepted collateral."""

    ETH = "eth"  # Native Ethereum
    WETH = "weth"  # Wrapped Ethereum
    USDC = "usdc"  # USD Coin (stablecoin)
    USDT = "usdt"  # Tether (stablecoin)
    DAI = "dai"  # DAI stablecoin
    STETH = "steth"  # Staked ETH (Lido)
    RETH = "reth"  # Rocket Pool staked ETH
    WBTC = "wbtc"  # Wrapped Bitcoin
    AEGIS = "aegis"  # Native protocol token


@dataclass
class CollateralConfig:
    """
    Configuration for a collateral type.

    Defines acceptance parameters, haircuts, and limits
    for a specific type of collateral.
    """

    collateral_type: CollateralType
    is_accepted: bool = True

    # Haircut configuration (risk discount)
    base_haircut_bps: int = 0  # Base haircut in basis points
    volatility_haircut_bps: int = 0  # Additional haircut for volatility
    concentration_haircut_bps: int = 0  # Haircut for large positions

    # Price oracle
    price_feed_address: str = ""  # Chainlink or other oracle
    max_price_age_seconds: int = 3600  # Maximum staleness

    # Limits
    min_deposit_wei: int = 0  # Minimum deposit amount
    max_deposit_wei: int = 0  # Maximum per deposit (0 = unlimited)
    max_pool_allocation_bps: int = 10000  # Max % of pool (100%)

    # Liquidation parameters
    liquidation_threshold_bps: int = 8000  # 80% - trigger liquidation
    liquidation_bonus_bps: int = 500  # 5% bonus for liquidators

    def total_haircut_bps(self, concentration_ratio: float = 0.0) -> int:
        """
        Calculate total haircut including concentration adjustment.

        Args:
            concentration_ratio: Position size / pool size (0-1)

        Returns:
            Total haircut in basis points
        """
        haircut = self.base_haircut_bps + self.volatility_haircut_bps

        # Add concentration haircut if position is large
        if concentration_ratio > 0.1:  # >10% of pool
            # Scale concentration haircut linearly above 10%
            excess = concentration_ratio - 0.1
            haircut += int(self.concentration_haircut_bps * (excess / 0.9))

        return min(haircut, 9000)  # Cap at 90%

    @property
    def total_haircut(self) -> float:
        """Total base haircut as decimal."""
        return (self.base_haircut_bps + self.volatility_haircut_bps) / 10_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "collateral_type": self.collateral_type.value,
            "is_accepted": self.is_accepted,
            "base_haircut_bps": self.base_haircut_bps,
            "volatility_haircut_bps": self.volatility_haircut_bps,
            "concentration_haircut_bps": self.concentration_haircut_bps,
            "price_feed_address": self.price_feed_address,
            "max_price_age_seconds": self.max_price_age_seconds,
            "min_deposit_wei": self.min_deposit_wei,
            "max_deposit_wei": self.max_deposit_wei,
            "max_pool_allocation_bps": self.max_pool_allocation_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "liquidation_bonus_bps": self.liquidation_bonus_bps,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CollateralConfig:
        return cls(
            collateral_type=CollateralType(data["collateral_type"]),
            is_accepted=data.get("is_accepted", True),
            base_haircut_bps=data.get("base_haircut_bps", 0),
            volatility_haircut_bps=data.get("volatility_haircut_bps", 0),
            concentration_haircut_bps=data.get("concentration_haircut_bps", 0),
            price_feed_address=data.get("price_feed_address", ""),
            max_price_age_seconds=data.get("max_price_age_seconds", 3600),
            min_deposit_wei=data.get("min_deposit_wei", 0),
            max_deposit_wei=data.get("max_deposit_wei", 0),
            max_pool_allocation_bps=data.get("max_pool_allocation_bps", 10000),
            liquidation_threshold_bps=data.get("liquidation_threshold_bps", 8000),
            liquidation_bonus_bps=data.get("liquidation_bonus_bps", 500),
        )


@dataclass
class CollateralDeposit:
    """
    A single collateral deposit.

    Represents tokens deposited by a user to back coverage.
    """

    deposit_id: str
    depositor: str  # Public key of depositor
    collateral_type: CollateralType
    amount_wei: int

    # Valuation
    price_at_deposit: int = 0  # USD price (scaled by 1e8)
    current_price: int = 0  # Current USD price
    price_updated_at: datetime | None = None

    # Status
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    withdrawn_at: datetime | None = None
    is_locked: bool = False  # Locked for active coverage
    lock_expires_at: datetime | None = None

    # Effective values (after haircut)
    effective_value_wei: int = 0
    haircut_applied_bps: int = 0

    @property
    def is_withdrawn(self) -> bool:
        return self.withdrawn_at is not None

    @property
    def is_lock_expired(self) -> bool:
        if not self.is_locked or not self.lock_expires_at:
            return False
        return datetime.now(UTC) > self.lock_expires_at

    @property
    def usd_value(self) -> int:
        """Current USD value (scaled by 1e8)."""
        if self.current_price == 0:
            return 0
        # Price is per 1e18 wei, scaled by 1e8
        return int(self.amount_wei * self.current_price / 10**18)

    def update_price(self, new_price: int) -> None:
        """Update current price and effective value."""
        self.current_price = new_price
        self.price_updated_at = datetime.now(UTC)

    def to_dict(self) -> dict[str, Any]:
        return {
            "deposit_id": self.deposit_id,
            "depositor": self.depositor,
            "collateral_type": self.collateral_type.value,
            "amount_wei": self.amount_wei,
            "price_at_deposit": self.price_at_deposit,
            "current_price": self.current_price,
            "price_updated_at": self.price_updated_at.isoformat() if self.price_updated_at else None,
            "created_at": self.created_at.isoformat(),
            "withdrawn_at": self.withdrawn_at.isoformat() if self.withdrawn_at else None,
            "is_locked": self.is_locked,
            "lock_expires_at": self.lock_expires_at.isoformat() if self.lock_expires_at else None,
            "effective_value_wei": self.effective_value_wei,
            "haircut_applied_bps": self.haircut_applied_bps,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CollateralDeposit:
        deposit = cls(
            deposit_id=data["deposit_id"],
            depositor=data["depositor"],
            collateral_type=CollateralType(data["collateral_type"]),
            amount_wei=data["amount_wei"],
            price_at_deposit=data.get("price_at_deposit", 0),
            current_price=data.get("current_price", 0),
            created_at=datetime.fromisoformat(data["created_at"]),
            is_locked=data.get("is_locked", False),
            effective_value_wei=data.get("effective_value_wei", 0),
            haircut_applied_bps=data.get("haircut_applied_bps", 0),
        )
        if data.get("price_updated_at"):
            deposit.price_updated_at = datetime.fromisoformat(data["price_updated_at"])
        if data.get("withdrawn_at"):
            deposit.withdrawn_at = datetime.fromisoformat(data["withdrawn_at"])
        if data.get("lock_expires_at"):
            deposit.lock_expires_at = datetime.fromisoformat(data["lock_expires_at"])
        return deposit


class CollateralPool:
    """
    Pool of collateral backing verification coverage.

    Manages deposits, withdrawals, and collateral valuation.
    """

    def __init__(self) -> None:
        self._deposits: dict[str, CollateralDeposit] = {}
        self._configs: dict[CollateralType, CollateralConfig] = {}
        self._by_depositor: dict[str, list[str]] = {}

        # Initialize default configs
        self._init_default_configs()

    def _init_default_configs(self) -> None:
        """Initialize default collateral configurations."""
        # ETH - base asset, no haircut
        self._configs[CollateralType.ETH] = CollateralConfig(
            collateral_type=CollateralType.ETH,
            base_haircut_bps=0,
            volatility_haircut_bps=500,  # 5% for volatility
        )

        # Stablecoins - low haircut
        for stable in [CollateralType.USDC, CollateralType.USDT, CollateralType.DAI]:
            self._configs[stable] = CollateralConfig(
                collateral_type=stable,
                base_haircut_bps=100,  # 1% base
                volatility_haircut_bps=100,  # 1% volatility
            )

        # Staked ETH - moderate haircut for illiquidity
        for staked in [CollateralType.STETH, CollateralType.RETH]:
            self._configs[staked] = CollateralConfig(
                collateral_type=staked,
                base_haircut_bps=300,  # 3% base
                volatility_haircut_bps=700,  # 7% volatility
            )

        # Protocol token - higher haircut
        self._configs[CollateralType.AEGIS] = CollateralConfig(
            collateral_type=CollateralType.AEGIS,
            base_haircut_bps=2000,  # 20% base
            volatility_haircut_bps=1000,  # 10% volatility
            concentration_haircut_bps=1000,  # 10% concentration
        )

    def set_config(self, config: CollateralConfig) -> None:
        """Set or update collateral configuration."""
        self._configs[config.collateral_type] = config

    def get_config(self, collateral_type: CollateralType) -> CollateralConfig | None:
        """Get configuration for a collateral type."""
        return self._configs.get(collateral_type)

    def deposit(
        self,
        depositor: str,
        collateral_type: CollateralType,
        amount_wei: int,
        price: int = 0,
    ) -> CollateralDeposit:
        """
        Record a new deposit.

        Args:
            depositor: Public key of depositor
            collateral_type: Type of collateral
            amount_wei: Amount in wei
            price: Current USD price (scaled by 1e8)

        Returns:
            The created CollateralDeposit

        Raises:
            ValueError: If collateral type is not accepted or limits exceeded
        """
        config = self._configs.get(collateral_type)
        if not config or not config.is_accepted:
            raise ValueError(f"Collateral type not accepted: {collateral_type}")

        # Check deposit limits
        if config.min_deposit_wei and amount_wei < config.min_deposit_wei:
            raise ValueError(f"Below minimum deposit: {config.min_deposit_wei}")
        if config.max_deposit_wei and amount_wei > config.max_deposit_wei:
            raise ValueError(f"Exceeds maximum deposit: {config.max_deposit_wei}")

        # Create deposit
        deposit_id = f"dep_{depositor[:8]}_{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
        deposit = CollateralDeposit(
            deposit_id=deposit_id,
            depositor=depositor,
            collateral_type=collateral_type,
            amount_wei=amount_wei,
            price_at_deposit=price,
            current_price=price,
            price_updated_at=datetime.now(UTC) if price else None,
        )

        # Calculate effective value
        haircut = calculate_haircut(config, amount_wei, self.total_value_by_type(collateral_type))
        deposit.haircut_applied_bps = haircut
        deposit.effective_value_wei = compute_collateral_value(amount_wei, haircut)

        # Store
        self._deposits[deposit_id] = deposit
        if depositor not in self._by_depositor:
            self._by_depositor[depositor] = []
        self._by_depositor[depositor].append(deposit_id)

        logger.info(f"Deposit recorded: {deposit_id} - {amount_wei} {collateral_type.value}")
        return deposit

    def withdraw(self, deposit_id: str) -> CollateralDeposit:
        """
        Mark a deposit as withdrawn.

        Args:
            deposit_id: ID of the deposit

        Returns:
            The updated deposit

        Raises:
            ValueError: If deposit not found or locked
        """
        deposit = self._deposits.get(deposit_id)
        if not deposit:
            raise ValueError(f"Deposit not found: {deposit_id}")
        if deposit.is_locked and not deposit.is_lock_expired:
            raise ValueError(f"Deposit is locked until {deposit.lock_expires_at}")
        if deposit.is_withdrawn:
            raise ValueError("Deposit already withdrawn")

        deposit.withdrawn_at = datetime.now(UTC)
        logger.info(f"Deposit withdrawn: {deposit_id}")
        return deposit

    def lock(self, deposit_id: str, until: datetime) -> CollateralDeposit:
        """Lock a deposit for active coverage."""
        deposit = self._deposits.get(deposit_id)
        if not deposit:
            raise ValueError(f"Deposit not found: {deposit_id}")

        deposit.is_locked = True
        deposit.lock_expires_at = until
        return deposit

    def unlock(self, deposit_id: str) -> CollateralDeposit:
        """Unlock a deposit."""
        deposit = self._deposits.get(deposit_id)
        if not deposit:
            raise ValueError(f"Deposit not found: {deposit_id}")

        deposit.is_locked = False
        deposit.lock_expires_at = None
        return deposit

    def get_deposit(self, deposit_id: str) -> CollateralDeposit | None:
        """Get a deposit by ID."""
        return self._deposits.get(deposit_id)

    def get_deposits_by_depositor(self, depositor: str) -> list[CollateralDeposit]:
        """Get all deposits for a depositor."""
        deposit_ids = self._by_depositor.get(depositor, [])
        return [self._deposits[did] for did in deposit_ids if did in self._deposits]

    def get_active_deposits(self) -> list[CollateralDeposit]:
        """Get all non-withdrawn deposits."""
        return [d for d in self._deposits.values() if not d.is_withdrawn]

    def total_value_by_type(self, collateral_type: CollateralType) -> int:
        """Get total value of a collateral type (in wei)."""
        return sum(
            d.amount_wei
            for d in self._deposits.values()
            if d.collateral_type == collateral_type and not d.is_withdrawn
        )

    def total_effective_value(self) -> int:
        """Get total effective value of all collateral (after haircuts)."""
        return sum(
            d.effective_value_wei
            for d in self._deposits.values()
            if not d.is_withdrawn
        )

    def total_locked_value(self) -> int:
        """Get total value of locked collateral."""
        return sum(
            d.effective_value_wei
            for d in self._deposits.values()
            if not d.is_withdrawn and d.is_locked
        )

    def available_value(self) -> int:
        """Get total value available for new coverage."""
        return self.total_effective_value() - self.total_locked_value()

    def update_prices(self, prices: dict[CollateralType, int]) -> None:
        """
        Update prices for collateral types.

        Args:
            prices: Dict of collateral type to USD price (1e8 scaled)
        """
        for deposit in self._deposits.values():
            if deposit.is_withdrawn:
                continue

            price = prices.get(deposit.collateral_type)
            if price is not None:
                deposit.update_price(price)

                # Recalculate effective value
                config = self._configs.get(deposit.collateral_type)
                if config:
                    haircut = calculate_haircut(
                        config,
                        deposit.amount_wei,
                        self.total_value_by_type(deposit.collateral_type),
                    )
                    deposit.haircut_applied_bps = haircut
                    deposit.effective_value_wei = compute_collateral_value(
                        deposit.amount_wei, haircut
                    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "deposits": {k: v.to_dict() for k, v in self._deposits.items()},
            "configs": {k.value: v.to_dict() for k, v in self._configs.items()},
            "total_effective_value_wei": self.total_effective_value(),
            "total_locked_value_wei": self.total_locked_value(),
            "available_value_wei": self.available_value(),
        }


def calculate_haircut(
    config: CollateralConfig,
    deposit_amount_wei: int,
    pool_total_wei: int,
) -> int:
    """
    Calculate haircut for a deposit.

    Args:
        config: Collateral configuration
        deposit_amount_wei: Amount being deposited
        pool_total_wei: Current pool total for this type

    Returns:
        Haircut in basis points
    """
    # Calculate concentration ratio
    if pool_total_wei == 0:
        concentration = 1.0  # First deposit is 100%
    else:
        concentration = deposit_amount_wei / (pool_total_wei + deposit_amount_wei)

    return config.total_haircut_bps(concentration)


def compute_collateral_value(amount_wei: int, haircut_bps: int) -> int:
    """
    Compute effective collateral value after haircut.

    Args:
        amount_wei: Raw collateral amount
        haircut_bps: Haircut in basis points

    Returns:
        Effective value in wei
    """
    discount = 10_000 - haircut_bps
    return int(amount_wei * discount / 10_000)
