"""
Trail schemas for stigmergic coordination.

Trails are signed records of successful agent actions that can be
shared across organizations to enable collective learning.

Uses Rust crypto when available, falls back to nacl.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

# Try Rust crypto first
_RUST_CRYPTO = False
_NACL_AVAILABLE = False

try:
    from cyntra_trust import Keypair as RustKeypair, sha256 as rust_sha256
    _RUST_CRYPTO = True
except ImportError:
    pass

if not _RUST_CRYPTO:
    try:
        from nacl.signing import SigningKey, VerifyKey
        from nacl.encoding import HexEncoder
        from nacl.exceptions import BadSignatureError
        _NACL_AVAILABLE = True
    except ImportError:
        pass


class ActionType(str, Enum):
    """Categories of agent actions for trail matching."""

    BUG_FIX = "bug_fix"
    FEATURE = "feature"
    REFACTOR = "refactor"
    TEST = "test"
    DOCS = "docs"
    PERF = "performance"
    SECURITY = "security"
    DEPS = "dependencies"
    CONFIG = "config"
    OTHER = "other"


class TaskComplexity(str, Enum):
    """Task complexity levels."""

    TRIVIAL = "trivial"
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    EXTREME = "extreme"


@dataclass
class StateFeatures:
    """
    Features extracted from codebase state for similarity matching.

    Uses locality-sensitive hashing (LSH) for efficient similarity search.
    """

    # Language distribution (normalized)
    languages: dict[str, float] = field(default_factory=dict)

    # Framework indicators
    frameworks: list[str] = field(default_factory=list)

    # Structural features
    file_count: int = 0
    avg_file_size: int = 0
    test_ratio: float = 0.0

    # Complexity indicators
    cyclomatic_avg: float = 0.0
    depth_avg: float = 0.0

    def to_vector(self) -> list[float]:
        """Convert to fixed-size feature vector for LSH."""
        # Simplified - real implementation would use proper feature extraction
        vec = []
        # Top 5 language weights
        lang_weights = sorted(self.languages.values(), reverse=True)[:5]
        vec.extend(lang_weights + [0.0] * (5 - len(lang_weights)))
        # Numeric features (normalized)
        vec.extend([
            min(self.file_count / 1000, 1.0),
            min(self.avg_file_size / 10000, 1.0),
            self.test_ratio,
            min(self.cyclomatic_avg / 20, 1.0),
            min(self.depth_avg / 10, 1.0),
        ])
        return vec


@dataclass
class TrailOutcome:
    """Outcome of following a trail (action result)."""

    success: bool
    tests_passed: int = 0
    tests_failed: int = 0
    coverage: float = 0.0
    token_count: int = 0
    duration_ms: int = 0

    # Gate verdicts
    gates_passed: list[str] = field(default_factory=list)
    gates_failed: list[str] = field(default_factory=list)


@dataclass
class TrailContext:
    """Context information for trail matching."""

    language: str
    framework: Optional[str] = None
    task_complexity: TaskComplexity = TaskComplexity.MODERATE

    # Additional context hints
    tags: list[str] = field(default_factory=list)


@dataclass
class Trail:
    """
    Stigmergic trail - a signed record of a successful agent action.

    Trails enable pattern sharing across organizations without
    exposing proprietary code. They contain enough information
    for other agents to recognize similar situations and apply
    similar strategies.
    """

    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: int = 1

    # State matching (LSH for similarity)
    state_hash: str = ""  # Locality-sensitive hash
    state_features: StateFeatures = field(default_factory=StateFeatures)

    # Action
    action_type: ActionType = ActionType.OTHER
    action_description: str = ""
    action_embedding: list[float] = field(default_factory=list)  # 384-dim semantic

    # Outcome
    outcome: TrailOutcome = field(default_factory=TrailOutcome)

    # Context
    context: TrailContext = field(default_factory=lambda: TrailContext(language="python"))

    # Provenance
    worker_id: str = ""  # Pseudonymous worker identifier
    receipt_hash: str = ""  # Link to full run receipt
    signature: str = ""  # Ed25519 signature

    # Dynamics
    strength: float = 1.0  # Decays over time (pheromone evaporation)
    citations: int = 0  # Times successfully followed
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_cited_at: Optional[datetime] = None

    def canonical_bytes(self) -> bytes:
        """Get canonical byte representation for signing."""
        # Include all fields except signature and dynamic fields
        parts = [
            self.id.encode(),
            str(self.version).encode(),
            self.state_hash.encode(),
            self.action_type.value.encode(),
            self.action_description.encode(),
            str(self.outcome.success).encode(),
            str(self.outcome.tests_passed).encode(),
            str(self.outcome.token_count).encode(),
            self.context.language.encode(),
            self.worker_id.encode(),
            self.receipt_hash.encode(),
            self.created_at.isoformat().encode(),
        ]
        return b"|".join(parts)

    def hash(self) -> str:
        """Compute SHA-256 hash of trail."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def sign(self, signing_key: Any) -> None:
        """Sign the trail with Ed25519 key.
        
        Accepts either a Rust Keypair or nacl SigningKey.
        """
        if _RUST_CRYPTO and hasattr(signing_key, 'sign'):
            # Rust crypto
            sig = signing_key.sign(self.canonical_bytes())
            self.signature = sig.to_hex()
        elif _NACL_AVAILABLE:
            # nacl crypto
            signed = signing_key.sign(self.canonical_bytes(), encoder=HexEncoder)
            self.signature = signed.signature.decode()
        else:
            raise RuntimeError("No cryptographic backend available")

    def verify(self, verify_key: Any) -> bool:
        """Verify trail signature.
        
        Accepts either a Rust PublicKey or nacl VerifyKey.
        """
        if not self.signature:
            return False
        
        try:
            if _RUST_CRYPTO and hasattr(verify_key, 'verify'):
                # Rust crypto
                from cyntra_trust import Signature
                sig = Signature.from_hex(self.signature)
                return verify_key.verify(self.canonical_bytes(), sig)
            elif _NACL_AVAILABLE:
                # nacl crypto
                verify_key.verify(
                    self.canonical_bytes(),
                    bytes.fromhex(self.signature),
                )
                return True
            else:
                return False
        except Exception:
            return False

    def decay(self, lambda_: float = 0.01) -> None:
        """
        Apply exponential decay to trail strength.

        λ is the decay rate per day (default 0.01 = 1% per day).
        """
        if self.last_cited_at:
            reference = self.last_cited_at
        else:
            reference = self.created_at

        days_elapsed = (datetime.now(timezone.utc) - reference).total_seconds() / 86400
        self.strength = self.strength * (1 - lambda_) ** days_elapsed

    def cite(self, success: bool) -> None:
        """Record that this trail was followed."""
        self.last_cited_at = datetime.now(timezone.utc)
        if success:
            self.citations += 1
            # Reinforce strength on success
            self.strength = min(1.0, self.strength * 1.1)
        else:
            # Slight decay on failure
            self.strength = self.strength * 0.95


@dataclass
class TrailQuery:
    """Query parameters for finding matching trails."""

    # State similarity
    state_hash: Optional[str] = None
    state_features: Optional[StateFeatures] = None
    similarity_threshold: float = 0.7

    # Action filtering
    action_type: Optional[ActionType] = None
    action_embedding: Optional[list[float]] = None  # For semantic search

    # Context filtering
    language: Optional[str] = None
    framework: Optional[str] = None
    max_complexity: Optional[TaskComplexity] = None

    # Quality filtering
    min_strength: float = 0.1
    min_citations: int = 0
    require_success: bool = True

    # Pagination
    limit: int = 10
    offset: int = 0


@dataclass
class TrailCitation:
    """Record of following a trail."""

    trail_id: str
    success: bool
    outcome: Optional[TrailOutcome] = None
    cited_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    worker_id: str = ""
