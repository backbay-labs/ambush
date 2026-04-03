"""
Governance configuration for the verification market.

Defines roles, permissions, pause authorities, and parameter bounds.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class GovernanceRole(str, Enum):
    """Governance roles with different permission levels."""

    ADMIN = "admin"  # Full control
    GUARDIAN = "guardian"  # Emergency actions only
    OPERATOR = "operator"  # Operational management
    AUDITOR = "auditor"  # Read-only audit access
    PROPOSER = "proposer"  # Can propose changes (no execute)


class PauseReason(str, Enum):
    """Reasons for pausing operations."""

    SECURITY_INCIDENT = "security_incident"
    ECONOMIC_ATTACK = "economic_attack"
    ORACLE_FAILURE = "oracle_failure"
    CIRCUIT_BREAKER = "circuit_breaker"
    SCHEDULED_MAINTENANCE = "scheduled_maintenance"
    GOVERNANCE_VOTE = "governance_vote"
    MANUAL_OVERRIDE = "manual_override"


class PauseScope(str, Enum):
    """Scope of a pause action."""

    GLOBAL = "global"  # All operations
    NEW_COVERAGE = "new_coverage"  # Block new coverage only
    CLAIMS = "claims"  # Block claim processing
    DEPOSITS = "deposits"  # Block new deposits
    WITHDRAWALS = "withdrawals"  # Block withdrawals
    PRICING = "pricing"  # Freeze pricing
    SPECIFIC_PRODUCT = "specific_product"  # Single product


@dataclass
class PauseAuthority:
    """
    Configuration for pause authority.

    Defines who can pause what, under what conditions.
    """

    authority_id: str
    name: str
    pubkey: str  # Public key of authority
    role: GovernanceRole

    # Scope permissions
    allowed_scopes: list[PauseScope] = field(default_factory=lambda: [PauseScope.GLOBAL])
    max_pause_duration_hours: int = 24  # Maximum pause duration

    # Conditions
    requires_multi_sig: bool = False
    multi_sig_threshold: int = 1  # Required signatures
    cooldown_between_pauses_hours: int = 0

    # Activity tracking
    last_pause_at: datetime | None = None
    pause_count: int = 0
    is_active: bool = True

    def can_pause(self, scope: PauseScope) -> tuple[bool, str | None]:
        """Check if this authority can pause a scope."""
        if not self.is_active:
            return False, "Authority is inactive"

        if scope not in self.allowed_scopes and PauseScope.GLOBAL not in self.allowed_scopes:
            return False, f"Scope {scope} not allowed for this authority"

        if self.last_pause_at and self.cooldown_between_pauses_hours > 0:
            elapsed = (datetime.now(UTC) - self.last_pause_at).total_seconds() / 3600
            if elapsed < self.cooldown_between_pauses_hours:
                return False, f"Cooldown period not elapsed ({self.cooldown_between_pauses_hours}h)"

        return True, None

    def record_pause(self) -> None:
        """Record that a pause was executed."""
        self.last_pause_at = datetime.now(UTC)
        self.pause_count += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_id": self.authority_id,
            "name": self.name,
            "pubkey": self.pubkey,
            "role": self.role.value,
            "allowed_scopes": [s.value for s in self.allowed_scopes],
            "max_pause_duration_hours": self.max_pause_duration_hours,
            "requires_multi_sig": self.requires_multi_sig,
            "multi_sig_threshold": self.multi_sig_threshold,
            "cooldown_between_pauses_hours": self.cooldown_between_pauses_hours,
            "last_pause_at": self.last_pause_at.isoformat() if self.last_pause_at else None,
            "pause_count": self.pause_count,
            "is_active": self.is_active,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PauseAuthority:
        authority = cls(
            authority_id=data["authority_id"],
            name=data["name"],
            pubkey=data["pubkey"],
            role=GovernanceRole(data["role"]),
            allowed_scopes=[PauseScope(s) for s in data.get("allowed_scopes", ["global"])],
            max_pause_duration_hours=data.get("max_pause_duration_hours", 24),
            requires_multi_sig=data.get("requires_multi_sig", False),
            multi_sig_threshold=data.get("multi_sig_threshold", 1),
            cooldown_between_pauses_hours=data.get("cooldown_between_pauses_hours", 0),
            pause_count=data.get("pause_count", 0),
            is_active=data.get("is_active", True),
        )
        if data.get("last_pause_at"):
            authority.last_pause_at = datetime.fromisoformat(data["last_pause_at"])
        return authority


@dataclass
class RoleAssignment:
    """Assignment of a role to an address."""

    assignment_id: str
    pubkey: str
    role: GovernanceRole
    granted_by: str
    granted_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    is_active: bool = True
    notes: str = ""

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(UTC) > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "assignment_id": self.assignment_id,
            "pubkey": self.pubkey,
            "role": self.role.value,
            "granted_by": self.granted_by,
            "granted_at": self.granted_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
            "notes": self.notes,
        }


@dataclass
class ParameterBounds:
    """
    Bounds for a governable parameter.

    Defines the allowed range and rate of change for a parameter.
    """

    parameter_name: str
    min_value: int | float
    max_value: int | float
    default_value: int | float

    # Rate limiting
    max_change_per_day_pct: float = 10.0  # Maximum % change per day
    min_time_between_changes_hours: int = 1  # Minimum time between changes

    # Who can modify
    required_role: GovernanceRole = GovernanceRole.ADMIN
    requires_timelock: bool = False
    timelock_hours: int = 24

    # Tracking
    current_value: int | float = 0
    last_changed_at: datetime | None = None
    change_count: int = 0

    def __post_init__(self) -> None:
        if self.current_value == 0:
            self.current_value = self.default_value

    def validate_change(self, new_value: int | float) -> tuple[bool, str | None]:
        """
        Validate a proposed parameter change.

        Args:
            new_value: Proposed new value

        Returns:
            Tuple of (valid, reason_if_not)
        """
        if new_value < self.min_value:
            return False, f"Below minimum: {self.min_value}"
        if new_value > self.max_value:
            return False, f"Above maximum: {self.max_value}"

        # Check rate of change
        if self.last_changed_at:
            elapsed = (datetime.now(UTC) - self.last_changed_at).total_seconds() / 3600
            if elapsed < self.min_time_between_changes_hours:
                return False, "Minimum time between changes not elapsed"

            # Calculate daily rate
            days = elapsed / 24
            if days > 0 and self.current_value != 0:
                pct_change = abs(new_value - self.current_value) / abs(self.current_value) * 100
                daily_pct = pct_change / days
                if daily_pct > self.max_change_per_day_pct:
                    return False, f"Change rate {daily_pct:.1f}%/day exceeds max {self.max_change_per_day_pct}%/day"

        return True, None

    def apply_change(self, new_value: int | float) -> None:
        """Apply a validated change."""
        self.current_value = new_value
        self.last_changed_at = datetime.now(UTC)
        self.change_count += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "parameter_name": self.parameter_name,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "default_value": self.default_value,
            "max_change_per_day_pct": self.max_change_per_day_pct,
            "min_time_between_changes_hours": self.min_time_between_changes_hours,
            "required_role": self.required_role.value,
            "requires_timelock": self.requires_timelock,
            "timelock_hours": self.timelock_hours,
            "current_value": self.current_value,
            "last_changed_at": self.last_changed_at.isoformat() if self.last_changed_at else None,
            "change_count": self.change_count,
        }


@dataclass
class GovernanceConfig:
    """
    Main governance configuration.

    Centralizes all governance settings for the verification market.
    """

    config_id: str
    version: int = 1

    # Global pause state
    is_paused: bool = False
    pause_scope: PauseScope | None = None
    pause_reason: PauseReason | None = None
    paused_at: datetime | None = None
    paused_by: str | None = None
    pause_expires_at: datetime | None = None

    # Timelock settings
    default_timelock_hours: int = 24
    emergency_timelock_hours: int = 1
    proposal_expiry_days: int = 7

    # Multi-sig settings
    default_multi_sig_threshold: int = 2
    emergency_multi_sig_threshold: int = 1

    # Created/updated timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_pause_expired(self) -> bool:
        if not self.is_paused or not self.pause_expires_at:
            return False
        return datetime.now(UTC) > self.pause_expires_at

    def pause(
        self,
        scope: PauseScope,
        reason: PauseReason,
        paused_by: str,
        duration_hours: int = 24,
    ) -> None:
        """
        Pause operations.

        Args:
            scope: Scope of the pause
            reason: Reason for pausing
            paused_by: Pubkey of who initiated pause
            duration_hours: Duration of pause
        """
        self.is_paused = True
        self.pause_scope = scope
        self.pause_reason = reason
        self.paused_at = datetime.now(UTC)
        self.paused_by = paused_by
        self.pause_expires_at = self.paused_at + timedelta(hours=duration_hours)
        self.updated_at = datetime.now(UTC)
        logger.warning(f"Operations paused: {scope.value} - {reason.value} by {paused_by}")

    def unpause(self, unpaused_by: str) -> None:
        """Unpause operations."""
        self.is_paused = False
        self.pause_scope = None
        self.pause_reason = None
        self.pause_expires_at = None
        self.updated_at = datetime.now(UTC)
        logger.info(f"Operations unpaused by {unpaused_by}")

    def check_pause_status(self) -> tuple[bool, PauseScope | None, PauseReason | None]:
        """
        Check current pause status.

        Automatically expires pause if duration exceeded.

        Returns:
            Tuple of (is_paused, scope, reason)
        """
        if self.is_paused and self.is_pause_expired:
            self.is_paused = False
            logger.info("Pause expired automatically")

        return self.is_paused, self.pause_scope, self.pause_reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "config_id": self.config_id,
            "version": self.version,
            "is_paused": self.is_paused,
            "pause_scope": self.pause_scope.value if self.pause_scope else None,
            "pause_reason": self.pause_reason.value if self.pause_reason else None,
            "paused_at": self.paused_at.isoformat() if self.paused_at else None,
            "paused_by": self.paused_by,
            "pause_expires_at": self.pause_expires_at.isoformat() if self.pause_expires_at else None,
            "default_timelock_hours": self.default_timelock_hours,
            "emergency_timelock_hours": self.emergency_timelock_hours,
            "proposal_expiry_days": self.proposal_expiry_days,
            "default_multi_sig_threshold": self.default_multi_sig_threshold,
            "emergency_multi_sig_threshold": self.emergency_multi_sig_threshold,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GovernanceConfig:
        config = cls(
            config_id=data["config_id"],
            version=data.get("version", 1),
            is_paused=data.get("is_paused", False),
            default_timelock_hours=data.get("default_timelock_hours", 24),
            emergency_timelock_hours=data.get("emergency_timelock_hours", 1),
            proposal_expiry_days=data.get("proposal_expiry_days", 7),
            default_multi_sig_threshold=data.get("default_multi_sig_threshold", 2),
            emergency_multi_sig_threshold=data.get("emergency_multi_sig_threshold", 1),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
        )
        if data.get("pause_scope"):
            config.pause_scope = PauseScope(data["pause_scope"])
        if data.get("pause_reason"):
            config.pause_reason = PauseReason(data["pause_reason"])
        if data.get("paused_at"):
            config.paused_at = datetime.fromisoformat(data["paused_at"])
        if data.get("pause_expires_at"):
            config.pause_expires_at = datetime.fromisoformat(data["pause_expires_at"])
        config.paused_by = data.get("paused_by")
        return config


class GovernanceRegistry:
    """
    Registry for governance entities.

    Manages roles, authorities, and parameters.
    """

    def __init__(self, config: GovernanceConfig | None = None) -> None:
        self.config = config or GovernanceConfig(config_id="default")
        self._authorities: dict[str, PauseAuthority] = {}
        self._roles: dict[str, RoleAssignment] = {}
        self._parameters: dict[str, ParameterBounds] = {}
        self._by_pubkey: dict[str, list[str]] = {}  # pubkey -> assignment_ids

    def register_authority(self, authority: PauseAuthority) -> None:
        """Register a pause authority."""
        self._authorities[authority.authority_id] = authority
        logger.info(f"Registered authority: {authority.authority_id} - {authority.name}")

    def get_authority(self, authority_id: str) -> PauseAuthority | None:
        """Get an authority by ID."""
        return self._authorities.get(authority_id)

    def grant_role(
        self,
        pubkey: str,
        role: GovernanceRole,
        granted_by: str,
        expires_in_days: int | None = None,
        notes: str = "",
    ) -> RoleAssignment:
        """
        Grant a role to an address.

        Args:
            pubkey: Address to grant role to
            role: Role to grant
            granted_by: Address granting the role
            expires_in_days: Optional expiration
            notes: Optional notes

        Returns:
            The role assignment
        """
        assignment_id = f"role_{pubkey[:8]}_{role.value}_{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
        assignment = RoleAssignment(
            assignment_id=assignment_id,
            pubkey=pubkey,
            role=role,
            granted_by=granted_by,
            notes=notes,
        )
        if expires_in_days:
            assignment.expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)

        self._roles[assignment_id] = assignment
        self._by_pubkey.setdefault(pubkey, []).append(assignment_id)

        logger.info(f"Role granted: {role.value} to {pubkey} by {granted_by}")
        return assignment

    def revoke_role(self, assignment_id: str) -> RoleAssignment | None:
        """Revoke a role assignment."""
        assignment = self._roles.get(assignment_id)
        if assignment:
            assignment.is_active = False
            logger.info(f"Role revoked: {assignment_id}")
        return assignment

    def has_role(self, pubkey: str, role: GovernanceRole) -> bool:
        """Check if an address has a role."""
        assignment_ids = self._by_pubkey.get(pubkey, [])
        for aid in assignment_ids:
            assignment = self._roles.get(aid)
            if assignment and assignment.is_active and not assignment.is_expired:
                if assignment.role == role or assignment.role == GovernanceRole.ADMIN:
                    return True
        return False

    def get_roles(self, pubkey: str) -> list[GovernanceRole]:
        """Get all active roles for an address."""
        roles = []
        assignment_ids = self._by_pubkey.get(pubkey, [])
        for aid in assignment_ids:
            assignment = self._roles.get(aid)
            if assignment and assignment.is_active and not assignment.is_expired:
                roles.append(assignment.role)
        return roles

    def register_parameter(self, bounds: ParameterBounds) -> None:
        """Register a governable parameter."""
        self._parameters[bounds.parameter_name] = bounds
        logger.info(f"Registered parameter: {bounds.parameter_name}")

    def get_parameter(self, name: str) -> ParameterBounds | None:
        """Get parameter bounds."""
        return self._parameters.get(name)

    def update_parameter(
        self,
        name: str,
        new_value: int | float,
        updated_by: str,
    ) -> tuple[bool, str | None]:
        """
        Update a parameter value.

        Args:
            name: Parameter name
            new_value: New value
            updated_by: Address making the update

        Returns:
            Tuple of (success, error_message)
        """
        bounds = self._parameters.get(name)
        if not bounds:
            return False, f"Parameter not found: {name}"

        # Check role
        if not self.has_role(updated_by, bounds.required_role):
            return False, f"Insufficient permissions (requires {bounds.required_role.value})"

        # Validate change
        valid, error = bounds.validate_change(new_value)
        if not valid:
            return False, error

        bounds.apply_change(new_value)
        logger.info(f"Parameter updated: {name} = {new_value} by {updated_by}")
        return True, None

    def execute_pause(
        self,
        authority_id: str,
        scope: PauseScope,
        reason: PauseReason,
        duration_hours: int | None = None,
    ) -> tuple[bool, str | None]:
        """
        Execute a pause action.

        Args:
            authority_id: ID of the authority executing pause
            scope: Scope of the pause
            reason: Reason for pausing
            duration_hours: Optional override of duration

        Returns:
            Tuple of (success, error_message)
        """
        authority = self._authorities.get(authority_id)
        if not authority:
            return False, f"Authority not found: {authority_id}"

        can_pause, error = authority.can_pause(scope)
        if not can_pause:
            return False, error

        duration = duration_hours or authority.max_pause_duration_hours
        if duration > authority.max_pause_duration_hours:
            duration = authority.max_pause_duration_hours

        self.config.pause(scope, reason, authority.pubkey, duration)
        authority.record_pause()

        return True, None

    def execute_unpause(self, authority_id: str) -> tuple[bool, str | None]:
        """Execute an unpause action."""
        authority = self._authorities.get(authority_id)
        if not authority:
            return False, f"Authority not found: {authority_id}"

        if not authority.is_active:
            return False, "Authority is inactive"

        self.config.unpause(authority.pubkey)
        return True, None

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "authorities": {k: v.to_dict() for k, v in self._authorities.items()},
            "roles": {k: v.to_dict() for k, v in self._roles.items()},
            "parameters": {k: v.to_dict() for k, v in self._parameters.items()},
        }
