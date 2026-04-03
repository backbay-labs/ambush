"""
Online Policy Learner - Contextual bandit for cycle decisions.

Replaces static heuristic rules with a learned weight matrix that maps
feature vectors (extracted from PolicySignals) to scores for each
CycleDecision. Uses a simple linear model with online TD-style updates.

The weight matrix is 7 decisions x 15 features = 105 floats, stored as
plain JSON in `.cyntra/state/policy_weights.json`. No numpy/scipy needed.

Safety constraints enforce hard floors:
- Never ABORT if budget remaining > 50%
- Never skip ESCALATE if consecutive_failures >= 5

Cold start: delegates to HeuristicCyclePolicy until >= 20 observations.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from cyntra.core.topology.cycle import CycleDecision, PolicySignals

logger = logging.getLogger(__name__)

# All decisions in a fixed order for indexing into the weight matrix
DECISIONS = list(CycleDecision)
DECISION_NAMES = [d.value for d in DECISIONS]
NUM_DECISIONS = len(DECISIONS)

# Feature names in fixed order
FEATURE_NAMES = [
    "state_potential",
    "action_measure",
    "trap_probability",
    "entropy_production",
    "phase_completion",
    "gates_pass_rate",
    "consecutive_failures",
    "cycles_without_progress",
    "token_efficiency",
    "time_efficiency",
    "priority_boost",
    "deadline_pressure",
    "budget_fraction",
    "cycle_count_norm",
    "bias",
]
NUM_FEATURES = len(FEATURE_NAMES)


@dataclass
class DecisionRecord:
    """Snapshot of a decision made during a cycle, for later credit assignment."""

    decision: CycleDecision
    features: list[float]
    timestamp_ms: int = 0


@dataclass
class PolicyLearnerConfig:
    """Configuration for the online policy learner."""

    alpha: float = 0.01  # Base learning rate
    alpha_decay: float = 0.9999  # Per-update decay
    alpha_min: float = 0.001  # Floor on learning rate
    cold_start_threshold: int = 20  # Min observations before using learned weights
    discount: float = 0.9  # Temporal discount for credit assignment
    weights_path: Path | None = None  # Path to persist weights


class PolicyLearner:
    """
    Online contextual bandit learner for cycle decisions.

    Maintains a weight matrix W[d][f] where:
    - d indexes into CycleDecision (7 decisions)
    - f indexes into the feature vector (15 features)

    score(decision) = dot(W[decision], features)

    Updates via a TD-style rule:
        W[d][f] += alpha * reward * features[f]
    where reward is the observed outcome signal.
    """

    def __init__(self, config: PolicyLearnerConfig | None = None) -> None:
        self.config = config or PolicyLearnerConfig()
        self._alpha = self.config.alpha
        self._observation_count = 0

        # Weight matrix: decision_index -> list of feature weights
        self._weights: list[list[float]] = [
            [0.0] * NUM_FEATURES for _ in range(NUM_DECISIONS)
        ]

        # Try to load persisted weights
        if self.config.weights_path is not None:
            self._load_weights()

    # =========================================================================
    # Feature Extraction
    # =========================================================================

    def extract_features(
        self,
        signals: PolicySignals,
        budget_fraction: float = 1.0,
        cycle_count: int = 0,
        max_cycles: int = 10,
    ) -> list[float]:
        """
        Extract a fixed-length feature vector from PolicySignals.

        All features are normalized to roughly [0, 1] or [-1, 1] range
        so the weight magnitudes stay comparable.
        """
        features = [
            _clamp(signals.state_potential / 10.0 if signals.state_potential is not None else 0.0, -1.0, 1.0),
            _clamp(signals.action_measure if signals.action_measure is not None else 0.0, 0.0, 1.0),
            _clamp(signals.trap_probability, 0.0, 1.0),
            _clamp(signals.entropy_production / 2.0 if signals.entropy_production is not None else 0.0, 0.0, 1.0),
            _clamp(signals.phase_completion, 0.0, 1.0),
            _clamp(signals.gates_pass_rate, 0.0, 1.0),
            _clamp(signals.consecutive_failures / 5.0, 0.0, 1.0),
            _clamp(signals.cycles_without_progress / 5.0, 0.0, 1.0),
            _clamp(signals.token_efficiency, 0.0, 1.0),
            _clamp(signals.time_efficiency, 0.0, 1.0),
            _clamp(signals.priority_boost, 0.0, 2.0) / 2.0,
            _clamp(signals.deadline_pressure, 0.0, 1.0),
            _clamp(budget_fraction, 0.0, 1.0),
            _clamp(cycle_count / max(max_cycles, 1), 0.0, 1.0),
            1.0,  # bias term
        ]
        assert len(features) == NUM_FEATURES
        return features

    # =========================================================================
    # Prediction
    # =========================================================================

    def predict(self, features: list[float]) -> dict[CycleDecision, float]:
        """
        Score each decision given a feature vector.

        Returns a dict mapping CycleDecision -> raw score.
        Higher score = more preferred.
        """
        scores: dict[CycleDecision, float] = {}
        for i, decision in enumerate(DECISIONS):
            score = _dot(self._weights[i], features)
            scores[decision] = score
        return scores

    def predict_from_signals(
        self,
        signals: PolicySignals,
        budget_fraction: float = 1.0,
        cycle_count: int = 0,
        max_cycles: int = 10,
    ) -> dict[CycleDecision, float]:
        """Convenience: extract features then predict."""
        features = self.extract_features(
            signals,
            budget_fraction=budget_fraction,
            cycle_count=cycle_count,
            max_cycles=max_cycles,
        )
        return self.predict(features)

    # =========================================================================
    # Update
    # =========================================================================

    def update(
        self,
        decision: CycleDecision,
        features: list[float],
        reward: float,
    ) -> None:
        """
        Update weights for the chosen decision based on observed reward.

        Uses a simple policy gradient style update:
            W[d][f] += alpha * reward * features[f]

        The reward should be in [-1, 1]:
        - +1.0 for full success (gates passed, task progressed)
        - -1.0 for failure with no progress
        - Partial values for partial outcomes
        """
        d_idx = DECISIONS.index(decision)
        w = self._weights[d_idx]

        for f in range(NUM_FEATURES):
            w[f] += self._alpha * reward * features[f]

        self._observation_count += 1

        # Decay learning rate
        self._alpha = max(
            self.config.alpha_min,
            self._alpha * self.config.alpha_decay,
        )

        # Persist periodically (every 5 updates)
        if self._observation_count % 5 == 0:
            self._save_weights()

    def update_batch(
        self,
        records: list[DecisionRecord],
        final_reward: float,
    ) -> None:
        """
        Update weights for a sequence of decisions with temporal discounting.

        Decisions closer to the outcome (later in the list) get higher
        reward signal. Uses geometric discounting from the end.
        """
        if not records:
            return

        n = len(records)
        for i, record in enumerate(records):
            # Discount: last decision gets full reward, earlier ones decay
            steps_from_end = n - 1 - i
            discounted_reward = final_reward * (self.config.discount ** steps_from_end)
            self.update(record.decision, record.features, discounted_reward)

    # =========================================================================
    # Safety Constraints
    # =========================================================================

    def apply_safety_constraints(
        self,
        scores: dict[CycleDecision, float],
        signals: PolicySignals,
        budget_fraction: float = 1.0,
    ) -> dict[CycleDecision, float]:
        """
        Apply hard safety constraints to decision scores.

        These override the learned policy to prevent dangerous decisions:
        1. Never ABORT if budget remaining > 50%
        2. Force ESCALATE if consecutive_failures >= 5
        """
        constrained = dict(scores)

        # Constraint 1: Don't abort prematurely
        if budget_fraction > 0.5:
            constrained[CycleDecision.ABORT] = -1e6

        # Constraint 2: Force escalation on sustained failures
        if signals.consecutive_failures >= 5:
            # Boost ESCALATE to be the clear winner
            max_score = max(constrained.values())
            constrained[CycleDecision.ESCALATE] = max_score + 10.0

        return constrained

    def select_decision(
        self,
        scores: dict[CycleDecision, float],
    ) -> CycleDecision:
        """Select the highest-scoring decision after constraints."""
        best_decision = max(scores, key=scores.get)  # type: ignore[arg-type]
        return best_decision

    # =========================================================================
    # Persistence
    # =========================================================================

    def _save_weights(self) -> None:
        """Persist weights to JSON file."""
        if self.config.weights_path is None:
            return

        data = {
            "version": 1,
            "observation_count": self._observation_count,
            "alpha": self._alpha,
            "decisions": DECISION_NAMES,
            "features": FEATURE_NAMES,
            "weights": self._weights,
        }

        try:
            self.config.weights_path.parent.mkdir(parents=True, exist_ok=True)
            self.config.weights_path.write_text(
                json.dumps(data, indent=2),
                encoding="utf-8",
            )
            logger.debug(
                "Saved policy weights (%d observations) to %s",
                self._observation_count,
                self.config.weights_path,
            )
        except Exception as e:
            logger.warning("Failed to save policy weights: %s", e)

    def _load_weights(self) -> None:
        """Load weights from JSON file."""
        if self.config.weights_path is None or not self.config.weights_path.exists():
            return

        try:
            data = json.loads(
                self.config.weights_path.read_text(encoding="utf-8")
            )

            if data.get("version") != 1:
                logger.warning("Unknown policy weights version, ignoring")
                return

            loaded_weights = data.get("weights")
            if (
                isinstance(loaded_weights, list)
                and len(loaded_weights) == NUM_DECISIONS
                and all(
                    isinstance(row, list) and len(row) == NUM_FEATURES
                    for row in loaded_weights
                )
            ):
                self._weights = loaded_weights
                self._observation_count = data.get("observation_count", 0)
                self._alpha = data.get("alpha", self.config.alpha)
                logger.info(
                    "Loaded policy weights (%d observations) from %s",
                    self._observation_count,
                    self.config.weights_path,
                )
            else:
                logger.warning(
                    "Policy weights shape mismatch (expected %dx%d), reinitializing",
                    NUM_DECISIONS,
                    NUM_FEATURES,
                )

        except Exception as e:
            logger.warning("Failed to load policy weights: %s", e)

    def save(self) -> None:
        """Force-save weights (called at shutdown)."""
        self._save_weights()

    # =========================================================================
    # Introspection
    # =========================================================================

    @property
    def observation_count(self) -> int:
        return self._observation_count

    @property
    def is_cold(self) -> bool:
        """True if we haven't collected enough data for learned decisions."""
        return self._observation_count < self.config.cold_start_threshold

    @property
    def current_alpha(self) -> float:
        return self._alpha

    def top_features_for(self, decision: CycleDecision, n: int = 5) -> list[tuple[str, float]]:
        """Return top-N most influential features for a decision."""
        d_idx = DECISIONS.index(decision)
        w = self._weights[d_idx]
        pairs = list(zip(FEATURE_NAMES, w, strict=True))
        pairs.sort(key=lambda p: abs(p[1]), reverse=True)
        return pairs[:n]


# =============================================================================
# Utility Functions
# =============================================================================


def _clamp(value: float, lo: float, hi: float) -> float:
    """Clamp a value to [lo, hi]."""
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _dot(a: list[float], b: list[float]) -> float:
    """Dot product of two equal-length lists."""
    total = 0.0
    for i in range(len(a)):
        total += a[i] * b[i]
    return total


def compute_reward(
    success: bool,
    partial_progress: float,
    gates_pass_rate: float,
    tokens_used: int,
    token_budget: int,
) -> float:
    """
    Compute a scalar reward signal from cycle outcome.

    Returns a value in [-1, 1]:
    - Full success with good efficiency: ~+1.0
    - Partial progress: ~+0.3
    - Failure with no progress: ~-0.5
    - Failure burning lots of tokens: ~-1.0
    """
    if success:
        # Base reward for success
        reward = 0.6

        # Bonus for gate quality
        reward += 0.2 * gates_pass_rate

        # Bonus for token efficiency (lower usage = better)
        if token_budget > 0:
            efficiency = 1.0 - min(tokens_used / token_budget, 1.0)
            reward += 0.2 * efficiency

        return min(reward, 1.0)

    # Failure case
    if partial_progress > 0.5:
        # Some progress made
        return -0.1 + 0.4 * partial_progress

    # Little to no progress
    waste_penalty = 0.0
    if token_budget > 0:
        waste_penalty = 0.3 * min(tokens_used / token_budget, 1.0)

    return -0.5 - waste_penalty
