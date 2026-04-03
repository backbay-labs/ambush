"""
Governance audit logging for the verification market.

Provides immutable audit trail for all governance actions.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from cyntra.trust.primitives.canonical_json import canonicalize as canonicalize_json

logger = logging.getLogger(__name__)


class GovernanceActionType(str, Enum):
    """Types of governance actions."""

    # Pause/unpause
    PAUSE = "pause"
    UNPAUSE = "unpause"

    # Role management
    GRANT_ROLE = "grant_role"
    REVOKE_ROLE = "revoke_role"

    # Parameter changes
    UPDATE_PARAMETER = "update_parameter"

    # Authority management
    REGISTER_AUTHORITY = "register_authority"
    DEACTIVATE_AUTHORITY = "deactivate_authority"

    # Product management
    REGISTER_PRODUCT = "register_product"
    DEACTIVATE_PRODUCT = "deactivate_product"
    UPDATE_PRODUCT_LIMITS = "update_product_limits"

    # Tranche management
    CONFIGURE_TRANCHE = "configure_tranche"
    CLOSE_TRANCHE = "close_tranche"

    # Incident response
    CREATE_INCIDENT = "create_incident"
    RESOLVE_INCIDENT = "resolve_incident"
    CLOSE_INCIDENT = "close_incident"

    # Emergency actions
    EMERGENCY_PAUSE = "emergency_pause"
    EMERGENCY_WITHDRAWAL = "emergency_withdrawal"
    MANUAL_OVERRIDE = "manual_override"

    # Configuration
    UPDATE_CONFIG = "update_config"
    DEPLOY_RUNBOOK = "deploy_runbook"


@dataclass
class GovernanceAction:
    """
    A governance action to be logged.

    Contains all details of the action for audit purposes.
    """

    action_type: GovernanceActionType
    performed_by: str  # Public key of actor
    target: str  # What was acted upon
    details: dict[str, Any] = field(default_factory=dict)

    # Context
    reason: str = ""
    proposal_id: str = ""  # If action was from a proposal
    incident_id: str = ""  # If action was incident response

    # Result
    success: bool = True
    error_message: str = ""

    # Signatures for multi-sig actions
    signatures: list[str] = field(default_factory=list)
    required_signatures: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type.value,
            "performed_by": self.performed_by,
            "target": self.target,
            "details": self.details,
            "reason": self.reason,
            "proposal_id": self.proposal_id,
            "incident_id": self.incident_id,
            "success": self.success,
            "error_message": self.error_message,
            "signatures": self.signatures,
            "required_signatures": self.required_signatures,
        }


@dataclass
class AuditEntry:
    """
    An entry in the governance audit log.

    Immutable record with hash chaining for tamper evidence.
    """

    entry_id: str
    timestamp: datetime
    action: GovernanceAction

    # Hash chain
    prev_hash: str  # Hash of previous entry
    entry_hash: str  # Hash of this entry (computed)

    # Metadata
    block_height: int = 0  # Optional blockchain block
    tx_hash: str = ""  # Optional transaction hash

    @classmethod
    def create(
        cls,
        action: GovernanceAction,
        prev_hash: str,
        entry_id: str | None = None,
    ) -> AuditEntry:
        """
        Create a new audit entry with computed hash.

        Args:
            action: The governance action
            prev_hash: Hash of the previous entry
            entry_id: Optional entry ID (auto-generated if not provided)

        Returns:
            New AuditEntry with computed hash
        """
        timestamp = datetime.now(UTC)
        if not entry_id:
            entry_id = f"audit_{timestamp.strftime('%Y%m%d%H%M%S%f')}"

        entry = cls(
            entry_id=entry_id,
            timestamp=timestamp,
            action=action,
            prev_hash=prev_hash,
            entry_hash="",  # Will be computed
        )

        # Compute hash
        entry.entry_hash = entry._compute_hash()
        return entry

    def _compute_hash(self) -> str:
        """Compute the hash for this entry."""
        data = {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action.to_dict(),
            "prev_hash": self.prev_hash,
        }
        canonical = canonicalize_json(data)
        return "0x" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify_hash(self) -> bool:
        """Verify this entry's hash is correct."""
        computed = self._compute_hash()
        return computed == self.entry_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action.to_dict(),
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "block_height": self.block_height,
            "tx_hash": self.tx_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        action_data = data["action"]
        action = GovernanceAction(
            action_type=GovernanceActionType(action_data["action_type"]),
            performed_by=action_data["performed_by"],
            target=action_data["target"],
            details=action_data.get("details", {}),
            reason=action_data.get("reason", ""),
            proposal_id=action_data.get("proposal_id", ""),
            incident_id=action_data.get("incident_id", ""),
            success=action_data.get("success", True),
            error_message=action_data.get("error_message", ""),
            signatures=action_data.get("signatures", []),
            required_signatures=action_data.get("required_signatures", 1),
        )

        return cls(
            entry_id=data["entry_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            action=action,
            prev_hash=data["prev_hash"],
            entry_hash=data["entry_hash"],
            block_height=data.get("block_height", 0),
            tx_hash=data.get("tx_hash", ""),
        )


class GovernanceAuditLog:
    """
    Immutable audit log for governance actions.

    Provides hash-chained logging with integrity verification.
    """

    GENESIS_HASH = "0x" + "00" * 32  # Genesis block hash

    def __init__(self, log_path: Path | None = None) -> None:
        """
        Initialize the audit log.

        Args:
            log_path: Optional path for persistent JSONL storage
        """
        self._entries: list[AuditEntry] = []
        self._by_actor: dict[str, list[int]] = {}  # pubkey -> entry indexes
        self._by_type: dict[GovernanceActionType, list[int]] = {}
        self._by_target: dict[str, list[int]] = {}
        self._log_path = log_path
        self._last_hash = self.GENESIS_HASH

        # Load existing log if path provided
        if log_path and log_path.exists():
            self._load_from_file()

    def _load_from_file(self) -> None:
        """Load entries from JSONL file."""
        if not self._log_path:
            return

        with open(self._log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                entry = AuditEntry.from_dict(data)
                self._add_to_memory(entry)

        if self._entries:
            self._last_hash = self._entries[-1].entry_hash

    def _add_to_memory(self, entry: AuditEntry) -> None:
        """Add entry to in-memory indexes."""
        idx = len(self._entries)
        self._entries.append(entry)

        # Index by actor
        actor = entry.action.performed_by
        if actor not in self._by_actor:
            self._by_actor[actor] = []
        self._by_actor[actor].append(idx)

        # Index by type
        action_type = entry.action.action_type
        if action_type not in self._by_type:
            self._by_type[action_type] = []
        self._by_type[action_type].append(idx)

        # Index by target
        target = entry.action.target
        if target not in self._by_target:
            self._by_target[target] = []
        self._by_target[target].append(idx)

    def _persist_entry(self, entry: AuditEntry) -> None:
        """Persist entry to JSONL file."""
        if not self._log_path:
            return

        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), separators=(",", ":"), sort_keys=True) + "\n")

    def append(self, action: GovernanceAction) -> AuditEntry:
        """
        Append a new governance action to the log.

        Args:
            action: The governance action to log

        Returns:
            The created audit entry
        """
        entry = AuditEntry.create(action, self._last_hash)
        self._add_to_memory(entry)
        self._last_hash = entry.entry_hash
        self._persist_entry(entry)

        logger.info(
            f"Audit log: {action.action_type.value} on {action.target} "
            f"by {action.performed_by} - {entry.entry_id}"
        )
        return entry

    def log_action(
        self,
        action_type: GovernanceActionType,
        performed_by: str,
        target: str,
        details: dict[str, Any] | None = None,
        reason: str = "",
        success: bool = True,
        error_message: str = "",
    ) -> AuditEntry:
        """
        Convenience method to log an action.

        Args:
            action_type: Type of action
            performed_by: Actor's public key
            target: What was acted upon
            details: Additional details
            reason: Reason for action
            success: Whether action succeeded
            error_message: Error message if failed

        Returns:
            The created audit entry
        """
        action = GovernanceAction(
            action_type=action_type,
            performed_by=performed_by,
            target=target,
            details=details or {},
            reason=reason,
            success=success,
            error_message=error_message,
        )
        return self.append(action)

    def get_entry(self, entry_id: str) -> AuditEntry | None:
        """Get an entry by ID."""
        for entry in self._entries:
            if entry.entry_id == entry_id:
                return entry
        return None

    def get_by_actor(self, actor: str) -> list[AuditEntry]:
        """Get all entries by an actor."""
        indexes = self._by_actor.get(actor, [])
        return [self._entries[i] for i in indexes]

    def get_by_type(self, action_type: GovernanceActionType) -> list[AuditEntry]:
        """Get all entries of a type."""
        indexes = self._by_type.get(action_type, [])
        return [self._entries[i] for i in indexes]

    def get_by_target(self, target: str) -> list[AuditEntry]:
        """Get all entries for a target."""
        indexes = self._by_target.get(target, [])
        return [self._entries[i] for i in indexes]

    def get_recent(self, count: int = 100) -> list[AuditEntry]:
        """Get the most recent entries."""
        return list(reversed(self._entries[-count:]))

    def get_range(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[AuditEntry]:
        """Get entries within a time range."""
        result = []
        for entry in self._entries:
            if start and entry.timestamp < start:
                continue
            if end and entry.timestamp > end:
                continue
            result.append(entry)
        return result

    def verify_chain(self) -> tuple[bool, list[str]]:
        """
        Verify the integrity of the entire audit chain.

        Returns:
            Tuple of (valid, list_of_errors)
        """
        errors = []

        if not self._entries:
            return True, []

        # Verify first entry links to genesis
        if self._entries[0].prev_hash != self.GENESIS_HASH:
            errors.append("First entry does not link to genesis hash")

        # Verify each entry
        for i, entry in enumerate(self._entries):
            # Verify hash
            if not entry.verify_hash():
                errors.append(f"Entry {entry.entry_id} has invalid hash")

            # Verify chain link (except first entry)
            if i > 0:
                if entry.prev_hash != self._entries[i - 1].entry_hash:
                    errors.append(
                        f"Entry {entry.entry_id} does not link to previous entry "
                        f"(expected {self._entries[i - 1].entry_hash}, "
                        f"got {entry.prev_hash})"
                    )

        return len(errors) == 0, errors

    def get_summary(self) -> dict[str, Any]:
        """Get summary statistics of the audit log."""
        by_type = {t.value: len(idxs) for t, idxs in self._by_type.items()}
        by_success = {"success": 0, "failure": 0}
        for entry in self._entries:
            if entry.action.success:
                by_success["success"] += 1
            else:
                by_success["failure"] += 1

        return {
            "total_entries": len(self._entries),
            "unique_actors": len(self._by_actor),
            "unique_targets": len(self._by_target),
            "by_type": by_type,
            "by_success": by_success,
            "first_entry": self._entries[0].timestamp.isoformat() if self._entries else None,
            "last_entry": self._entries[-1].timestamp.isoformat() if self._entries else None,
            "last_hash": self._last_hash,
        }

    @property
    def entry_count(self) -> int:
        """Get total number of entries."""
        return len(self._entries)

    @property
    def last_hash(self) -> str:
        """Get the hash of the last entry."""
        return self._last_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [e.to_dict() for e in self._entries],
            "summary": self.get_summary(),
        }

    def export_jsonl(self, path: Path) -> int:
        """
        Export the entire log to a JSONL file.

        Args:
            path: Output path

        Returns:
            Number of entries exported
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for entry in self._entries:
                f.write(json.dumps(entry.to_dict(), separators=(",", ":"), sort_keys=True) + "\n")
        return len(self._entries)
