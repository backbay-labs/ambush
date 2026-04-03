"""
Dynamics-Based Router

Routes tasks to toolchains based on historical success rates from the
dynamics transition database. Blends empirical evidence with static rules.

Queries the transition DB to find:
- Which toolchains succeeded from similar states
- Success rates per toolchain per domain
- Exploration opportunities for under-tested toolchains
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from cyntra.cognition.dynamics.state_t1 import build_state_t1
from cyntra.cognition.dynamics.transition_db import TransitionDB

if TYPE_CHECKING:
    pass

logger = structlog.get_logger()

# Default dynamics database path
DEFAULT_DYNAMICS_DB_PATH = Path(".cyntra/dynamics/cyntra.db")


class DynamicsRouter:
    """
    Route based on historical transition success rates.

    Queries the dynamics transition database to estimate which toolchain
    is most likely to succeed for a given state.

    Usage:
        router = DynamicsRouter(db_path=".cyntra/dynamics/cyntra.db")

        probabilities = router.get_toolchain_probabilities(
            domain="code",
            job_type="code",
            features={"phase": "plan", "failing_gate": "none"},
        )

        ranked = router.rank_toolchains(
            candidates=["claude", "codex", "opencode"],
            domain="code",
            job_type="code",
            features={...},
        )
    """

    def __init__(
        self,
        db_path: Path | str | None = None,
        cache_ttl: int = 300,  # 5 minutes
    ):
        self.db_path = Path(db_path) if db_path else DEFAULT_DYNAMICS_DB_PATH
        self.cache_ttl = cache_ttl
        self._cache: dict[str, dict[str, float]] = {}
        self._domain_cache: dict[str, dict[str, float]] = {}
        self._last_refresh: float = 0

    def get_toolchain_probabilities(
        self,
        domain: str,
        job_type: str,
        features: dict[str, Any] | None = None,
    ) -> dict[str, float]:
        """
        Get estimated success probability for each toolchain from current state.

        First tries to find exact state matches, then falls back to domain-level
        statistics if no exact matches found.

        Args:
            domain: Domain (code, fab_asset, fab_world)
            job_type: Job type
            features: State features (phase, failing_gate, etc.)

        Returns:
            {toolchain: probability} where probability is based on historical outcomes
        """
        # Check if DB exists
        if not self.db_path.exists():
            logger.debug("Dynamics DB not found", path=str(self.db_path))
            return {}

        # Build state representation
        features = features or {}
        current_state = build_state_t1(
            domain=domain,
            job_type=job_type,
            features=features,
            policy_key={},  # Toolchain not yet chosen
        )
        state_id = current_state.get("state_id", "")

        # Check cache
        now = time.time()
        if state_id in self._cache and now - self._last_refresh < self.cache_ttl:
            return self._cache[state_id]

        # Query dynamics DB
        probabilities = self._query_state_probabilities(state_id, domain)

        # If no state-specific data, fall back to domain averages
        if not probabilities:
            probabilities = self._get_domain_probabilities(domain)

        # Update cache
        self._cache[state_id] = probabilities
        self._last_refresh = now

        return probabilities

    def _query_state_probabilities(
        self,
        state_id: str,
        domain: str,
    ) -> dict[str, float]:
        """Query transition DB for success rates by toolchain from specific state."""
        try:
            db = TransitionDB(self.db_path)

            # Get transitions from this state or similar states in same domain
            cursor = db.conn.cursor()

            # Try exact state match first
            rows = cursor.execute(
                """
                SELECT
                    t.toolchain,
                    s_to.data_json as to_state_data,
                    COUNT(*) as count
                FROM transitions t
                JOIN states s_to ON t.to_state = s_to.state_id
                WHERE t.from_state = ?
                GROUP BY t.toolchain, s_to.data_json
            """,
                (state_id,),
            ).fetchall()

            # If no exact matches, try domain-level
            if not rows:
                rows = cursor.execute(
                    """
                    SELECT
                        t.toolchain,
                        s_to.data_json as to_state_data,
                        COUNT(*) as count
                    FROM transitions t
                    JOIN states s_from ON t.from_state = s_from.state_id
                    JOIN states s_to ON t.to_state = s_to.state_id
                    WHERE s_from.domain = ?
                    GROUP BY t.toolchain, s_to.data_json
                """,
                    (domain,),
                ).fetchall()

            db.close()

            # Aggregate success by toolchain
            toolchain_outcomes: dict[str, dict[str, int]] = {}

            for row in rows:
                toolchain = row["toolchain"]
                if not toolchain:
                    continue

                count = row["count"]

                if toolchain not in toolchain_outcomes:
                    toolchain_outcomes[toolchain] = {"success": 0, "total": 0}

                toolchain_outcomes[toolchain]["total"] += count

                # Check if destination state is success
                try:
                    to_state = json.loads(row["to_state_data"]) if row["to_state_data"] else {}
                    to_features = to_state.get("features", {})
                    to_phase = to_features.get("phase", "")

                    # Success phases: verified, merge, done
                    if to_phase in ("verified", "merge", "done", "success"):
                        toolchain_outcomes[toolchain]["success"] += count
                    # Partial success: made progress
                    elif to_phase in ("test", "edit"):
                        toolchain_outcomes[toolchain]["success"] += count * 0.5
                except (json.JSONDecodeError, TypeError):
                    pass

            # Calculate probabilities
            probabilities: dict[str, float] = {}
            for toolchain, outcomes in toolchain_outcomes.items():
                if outcomes["total"] > 0:
                    probabilities[toolchain] = outcomes["success"] / outcomes["total"]

            return probabilities

        except Exception as e:
            logger.warning("Dynamics query failed", error=str(e))
            return {}

    def _get_domain_probabilities(self, domain: str) -> dict[str, float]:
        """Get domain-level success rates as fallback."""
        if domain in self._domain_cache and time.time() - self._last_refresh < self.cache_ttl:
            return self._domain_cache[domain]

        try:
            db = TransitionDB(self.db_path)

            cursor = db.conn.cursor()
            rows = cursor.execute(
                """
                SELECT
                    t.toolchain,
                    COUNT(*) as total,
                    SUM(CASE
                        WHEN json_extract(s_to.data_json, '$.features.phase') IN ('verified', 'merge', 'done', 'success')
                        THEN 1 ELSE 0
                    END) as successes
                FROM transitions t
                JOIN states s_from ON t.from_state = s_from.state_id
                JOIN states s_to ON t.to_state = s_to.state_id
                WHERE s_from.domain = ?
                GROUP BY t.toolchain
            """,
                (domain,),
            ).fetchall()

            db.close()

            probabilities: dict[str, float] = {}
            for row in rows:
                toolchain = row["toolchain"]
                if toolchain and row["total"] > 0:
                    probabilities[toolchain] = row["successes"] / row["total"]

            self._domain_cache[domain] = probabilities
            return probabilities

        except Exception as e:
            logger.warning("Domain probability query failed", error=str(e))
            return {}

    def rank_toolchains(
        self,
        candidates: list[str],
        domain: str,
        job_type: str,
        features: dict[str, Any] | None = None,
        exploration_rate: float = 0.1,
        default_probability: float = 0.5,
    ) -> list[tuple[str, float]]:
        """
        Rank toolchain candidates by estimated success probability.

        Args:
            candidates: Available toolchains to rank
            domain: Current domain
            job_type: Job type
            features: State features
            exploration_rate: Bonus for under-tested toolchains
            default_probability: Probability for unknown toolchains

        Returns:
            [(toolchain, probability), ...] sorted by probability descending
        """
        probabilities = self.get_toolchain_probabilities(domain, job_type, features)

        ranked = []
        for tc in candidates:
            prob = probabilities.get(tc, default_probability)

            # Add exploration bonus for rarely-tried or unknown toolchains
            if tc not in probabilities:
                prob += exploration_rate

            ranked.append((tc, prob))

        # Sort by probability descending
        ranked.sort(key=lambda x: x[1], reverse=True)

        logger.debug(
            "Dynamics ranking",
            domain=domain,
            candidates=candidates,
            ranked=ranked,
        )

        return ranked

    def get_toolchain_stats(self, domain: str | None = None) -> dict[str, Any]:
        """
        Get statistics about toolchain usage and success rates.

        Useful for debugging and observability.

        Args:
            domain: Optional domain filter

        Returns:
            {
                "toolchains": {name: {total, successes, success_rate}},
                "total_transitions": int,
                "domains": [...]
            }
        """
        if not self.db_path.exists():
            return {"toolchains": {}, "total_transitions": 0, "domains": []}

        try:
            db = TransitionDB(self.db_path)
            cursor = db.conn.cursor()

            # Get domain list
            domains_rows = cursor.execute("SELECT DISTINCT domain FROM states").fetchall()
            domains = [r["domain"] for r in domains_rows]

            # Get toolchain stats
            query = """
                SELECT
                    t.toolchain,
                    COUNT(*) as total,
                    SUM(CASE
                        WHEN json_extract(s_to.data_json, '$.features.phase') IN ('verified', 'merge', 'done', 'success')
                        THEN 1 ELSE 0
                    END) as successes
                FROM transitions t
                JOIN states s_from ON t.from_state = s_from.state_id
                JOIN states s_to ON t.to_state = s_to.state_id
            """
            params: tuple = ()

            if domain:
                query += " WHERE s_from.domain = ?"
                params = (domain,)

            query += " GROUP BY t.toolchain"

            rows = cursor.execute(query, params).fetchall()

            toolchains: dict[str, dict[str, Any]] = {}
            total_transitions = 0

            for row in rows:
                tc = row["toolchain"]
                if tc:
                    total = row["total"]
                    successes = row["successes"]
                    toolchains[tc] = {
                        "total": total,
                        "successes": successes,
                        "success_rate": successes / total if total > 0 else 0,
                    }
                    total_transitions += total

            db.close()

            return {
                "toolchains": toolchains,
                "total_transitions": total_transitions,
                "domains": domains,
            }

        except Exception as e:
            logger.warning("Stats query failed", error=str(e))
            return {"toolchains": {}, "total_transitions": 0, "domains": [], "error": str(e)}

    def clear_cache(self) -> None:
        """Clear the probability cache."""
        self._cache.clear()
        self._domain_cache.clear()
        self._last_refresh = 0
