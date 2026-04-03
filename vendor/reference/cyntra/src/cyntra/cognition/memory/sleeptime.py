"""
Sleeptime Processing - Background memory maintenance.

Runs during kernel idle periods to:
- Consolidate similar memories
- Discover patterns
- Analyze dynamics
- Recalculate scores
- Archive stale memories
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

from .collective import CollectiveMemoryService
from .consolidation import ConsolidationHandler
from .models import AgentMemory, MemoryType
from .scoring import get_archival_candidates, recalculate_all_scores

logger = logging.getLogger(__name__)


@dataclass
class SleeptimeReport:
    """Report from sleeptime processing."""

    # Timing
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    duration_seconds: float = 0.0

    # Consolidation
    memories_consolidated: int = 0
    consolidation_clusters: int = 0
    tokens_saved: int = 0

    # Pattern discovery
    patterns_discovered: int = 0
    patterns_promoted: int = 0

    # Dynamics analysis
    dynamics_analyzed: int = 0
    dynamics_created: int = 0

    # Scoring
    scores_recalculated: int = 0

    # Archival
    memories_archived: int = 0

    # Errors
    errors: list[str] = field(default_factory=list)


class SleeptimeProcessor:
    """
    Background memory maintenance processor.

    Runs during kernel idle periods to optimize memory quality.
    """

    def __init__(
        self,
        store,  # MemoryStore
        vector_ops=None,  # VectorOps
        collective_service: CollectiveMemoryService | None = None,
        consolidation_handler: ConsolidationHandler | None = None,
    ):
        """
        Initialize sleeptime processor.

        Args:
            store: MemoryStore for database access
            vector_ops: VectorOps for embeddings
            collective_service: Optional collective memory service
            consolidation_handler: Optional consolidation handler
        """
        self.store = store
        self.vector_ops = vector_ops
        self.collective_service = collective_service
        self.consolidation_handler = consolidation_handler or ConsolidationHandler(
            store=store,
            vector_ops=vector_ops,
        )

    async def process(self, agent_id: str) -> SleeptimeReport:
        """
        Run all sleeptime operations for an agent.

        Operations:
        1. Memory consolidation
        2. Pattern discovery
        3. Dynamics analysis
        4. Score recalculation
        5. Garbage collection

        Args:
            agent_id: Agent to process

        Returns:
            SleeptimeReport with processing results
        """
        report = SleeptimeReport()
        logger.info(f"Starting sleeptime processing for agent {agent_id}")

        try:
            # 1. Memory consolidation
            consolidated, clusters, tokens = await self.consolidate_similar_memories(agent_id)
            report.memories_consolidated = consolidated
            report.consolidation_clusters = clusters
            report.tokens_saved = tokens

            # 2. Pattern discovery
            patterns = await self.discover_patterns(agent_id)
            report.patterns_discovered = len(patterns)

            # 3. Pattern promotion (if collective service available)
            if self.collective_service:
                promoted = await self._promote_patterns(patterns)
                report.patterns_promoted = promoted

            # 4. Dynamics analysis (trap detection from dynamics layer)
            try:
                dynamics_memories = await self.analyze_dynamics(agent_id)
                report.dynamics_analyzed = 1  # Report ran once
                report.dynamics_created = len(dynamics_memories)
            except Exception as e:
                logger.warning(f"Dynamics analysis skipped due to error: {e}")
                report.dynamics_analyzed = 0
                report.dynamics_created = 0

            # 5. Score recalculation
            try:
                recalculated = await recalculate_all_scores(self.store, agent_id)
            except Exception as e:
                logger.warning(f"Score recalculation skipped due to error: {e}")
                recalculated = 0
            report.scores_recalculated = recalculated

            # 6. Archive stale memories
            try:
                archived = await self.archive_stale_memories(agent_id)
            except Exception as e:
                logger.warning(f"Archival skipped due to error: {e}")
                archived = 0
            report.memories_archived = archived

        except Exception as e:
            logger.error(f"Sleeptime processing error: {e}")
            report.errors.append(str(e))

        report.completed_at = datetime.utcnow()
        report.duration_seconds = (report.completed_at - report.started_at).total_seconds()

        logger.info(
            f"Sleeptime completed for {agent_id}: "
            f"consolidated={report.memories_consolidated}, "
            f"patterns={report.patterns_discovered}, "
            f"dynamics_traps={report.dynamics_created}, "
            f"archived={report.memories_archived}, "
            f"duration={report.duration_seconds:.1f}s"
        )

        return report

    async def consolidate_similar_memories(
        self,
        agent_id: str,
    ) -> tuple[int, int, int]:
        """
        Consolidate similar memories to reduce redundancy.

        Args:
            agent_id: Agent to process

        Returns:
            Tuple of (memories_consolidated, cluster_count, tokens_saved)
        """
        # Find consolidation clusters. In mocked/unit-test contexts the store may not
        # support the full DB-backed consolidation flow; treat failures as "no-op"
        # rather than aborting the entire sleeptime run.
        try:
            clusters = await self.consolidation_handler.find_clusters(agent_id)
        except Exception as e:
            logger.warning(f"Consolidation skipped due to error: {e}")
            return 0, 0, 0

        if not clusters:
            return 0, 0, 0

        total_consolidated = 0
        total_tokens_saved = 0

        for cluster in clusters:
            try:
                result = await self.consolidation_handler.consolidate_cluster(cluster)
                if result:
                    total_consolidated += len(cluster.memory_ids)
                    # Estimate token savings (rough: 0.75 tokens per char)
                    original_chars = sum(len(t) for t in cluster.memory_texts)
                    new_chars = len(result.text)
                    total_tokens_saved += int((original_chars - new_chars) * 0.75)
            except Exception as e:
                logger.warning(f"Failed to consolidate cluster: {e}")

        return total_consolidated, len(clusters), total_tokens_saved

    async def discover_patterns(
        self,
        agent_id: str,
        limit: int = 10,
    ) -> list[AgentMemory]:
        """
        Discover new patterns from successful runs.

        Looks for:
        - Frequently accessed memories that should be patterns
        - Similar successes that can be generalized

        Args:
            agent_id: Agent to analyze
            limit: Maximum patterns to discover

        Returns:
            List of discovered pattern memories
        """
        # Find high-value non-pattern memories that could be patterns
        hubs = await self.store.find_hubs(
            agent_id=agent_id,
            min_importance=0.6,
            min_access=5,
            min_links=2,
            limit=limit,
        )

        discovered = []
        for hub in hubs:
            # Skip if already a pattern
            if hub.memory_type == MemoryType.PATTERN:
                continue

            # Consider for pattern promotion
            if hub.memory_type in (MemoryType.CONTEXT, MemoryType.DYNAMIC):
                # Update to pattern type
                try:
                    await self.store.update(
                        memory_id=hub.id, updates={"memory_type": MemoryType.PATTERN.value}
                    )
                    discovered.append(hub)
                except Exception as e:
                    logger.warning(f"Failed to promote to pattern: {e}")

        return discovered

    async def analyze_dynamics(
        self,
        agent_id: str,
    ) -> list[AgentMemory]:
        """
        Analyze behavioral dynamics from run history.

        Integrates with the dynamics layer to:
        - Generate dynamics report (potentials, action metrics)
        - Detect trap states (low action rate + low delta V)
        - Create memory entries for trap warnings

        Args:
            agent_id: Agent to analyze

        Returns:
            List of new dynamic memories (trap warnings, behavioral patterns)
        """
        import uuid
        from pathlib import Path

        from cyntra.cognition.dynamics.report import build_report
        from cyntra.cognition.dynamics.transition_db import TransitionDB

        dynamics_db_path = Path(".cyntra/dynamics/cyntra.db")
        if not dynamics_db_path.exists():
            logger.debug("Dynamics DB not found, skipping analysis")
            return []

        try:
            # Build dynamics report
            report = build_report(dynamics_db_path)
            action_summary = report.get("action_summary", {})
            traps = action_summary.get("traps", [])

            created_memories: list[AgentMemory] = []
            now = datetime.utcnow()

            # Create memory entries for detected traps
            for trap in traps:
                state_id = trap.get("state_id", "unknown")
                reason = trap.get("reason", "")
                recommendation = trap.get("recommendation", "")

                # Create a DYNAMIC memory for trap detection
                trap_memory = AgentMemory(
                    id=uuid.uuid4(),
                    agent_id=agent_id,
                    memory_type=MemoryType.DYNAMIC,
                    text=f"Trap detected at state {state_id}: {reason}. {recommendation}",
                    importance_score=0.8,
                    confidence=0.7,
                    created_at=now,
                )

                # Persist trap warning to dynamics DB for Ralph integration
                try:
                    from datetime import timezone
                    db = TransitionDB(dynamics_db_path)

                    db.conn.execute(
                        """
                        INSERT OR REPLACE INTO trap_warnings
                            (state_id, trap_type, source, message, detected_at, context_json)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            state_id,
                            "low_action_delta_v",
                            "sleeptime_processor",
                            f"{reason}. {recommendation}",
                            datetime.now(timezone.utc).isoformat(),
                            "{}",
                        ),
                    )
                    db.conn.commit()
                    db.close()
                except Exception as e:
                    logger.warning(f"Failed to persist trap warning: {e}")

                created_memories.append(trap_memory)

            # Regenerate dynamics_report.json for exploration controller
            try:
                from cyntra.cognition.dynamics.report import write_report
                report_path = dynamics_db_path.parent / "dynamics_report.json"
                write_report(dynamics_db_path, report_path)
                logger.debug("Dynamics report regenerated", path=str(report_path))
            except Exception as e:
                logger.warning(f"Failed to regenerate dynamics report: {e}")

            logger.info(
                f"Dynamics analysis complete for {agent_id}: "
                f"global_action_rate={action_summary.get('global_action_rate', 0):.3f}, "
                f"traps_detected={len(traps)}"
            )

            return created_memories

        except Exception as e:
            logger.warning(f"Dynamics analysis failed: {e}")
            return []

    async def archive_stale_memories(
        self,
        agent_id: str,
        threshold: float = 0.001,
        limit: int = 100,
    ) -> int:
        """
        Archive memories below importance threshold.

        Args:
            agent_id: Agent to process
            threshold: Importance threshold
            limit: Maximum to archive in one pass

        Returns:
            Number of memories archived
        """
        # Find archival candidates
        candidate_ids = await get_archival_candidates(
            store=self.store,
            agent_id=agent_id,
            threshold=threshold,
            limit=limit,
        )

        if not candidate_ids:
            return 0

        # Archive each candidate
        archived = 0
        for memory_id in candidate_ids:
            try:
                await self.store.archive(memory_id)
                archived += 1
            except Exception as e:
                logger.warning(f"Failed to archive memory {memory_id}: {e}")

        return archived

    async def _promote_patterns(
        self,
        patterns: list[AgentMemory],
    ) -> int:
        """Promote discovered patterns to collective scope."""
        if not self.collective_service:
            return 0

        promoted = 0
        for pattern in patterns:
            # Find similar patterns in other agents
            similar = await self.collective_service.find_similar_across_agents(pattern)
            if len(similar) >= 2:  # At least 2 other agents have similar
                agents = [s.agent_id for s in similar] + [pattern.agent_id]
                if await self.collective_service.promote_to_collective(
                    memory_id=pattern.id,
                    validation_agents=list(set(agents)),
                ):
                    promoted += 1

        return promoted
