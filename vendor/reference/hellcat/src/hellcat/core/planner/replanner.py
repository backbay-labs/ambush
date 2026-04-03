"""
Replanner - Triggers replanning when credential chaining unlocks new paths.

After a dispatch cycle harvests credentials, the Replanner checks whether
those credentials unlock new attack paths via ENABLES edges and produces
a follow-up AttackPlan targeting the newly reachable nodes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from hellcat.offensive.target_graph.graph import TargetGraph
from hellcat.offensive.target_graph.models import AttackStatus, EdgeType, NodeType

logger = structlog.get_logger()


@dataclass
class CredentialChain:
    """A multi-hop credential chain: vuln -> credential -> new_target -> vuln."""

    credential_id: str
    credential_username: str
    source_vuln_id: str
    reachable_target_ids: list[str] = field(default_factory=list)
    depth: int = 1
    score: float = 0.0


@dataclass
class ReplanResult:
    """Outcome of a replanning check."""

    new_credentials: list[dict[str, Any]] = field(default_factory=list)
    new_paths: list[CredentialChain] = field(default_factory=list)
    new_targets_to_analyze: list[str] = field(default_factory=list)
    should_replan: bool = False


class Replanner:
    """
    Checks whether newly harvested credentials unlock additional attack
    paths, and produces a list of nodes that should be promoted to
    ANALYZED status for the next planning cycle.

    Usage::

        replanner = Replanner(graph)
        result = replanner.check_new_paths(since=last_plan_time)
        if result.should_replan:
            # promote new targets, re-run AttackPlanner
            replanner.promote_targets(result)
    """

    def __init__(self, graph: TargetGraph) -> None:
        self.graph = graph

    def check_new_paths(
        self,
        since: str | None = None,
    ) -> ReplanResult:
        """
        Check if credentials discovered since ``since`` unlock new paths.

        Args:
            since: ISO timestamp. If None, checks all credentials.

        Returns:
            ReplanResult indicating whether replanning is needed.
        """
        result = ReplanResult()

        # Get new credentials
        if since:
            new_creds = self.graph.get_credentials_since(since)
        else:
            rows = self.graph.conn.execute(
                "SELECT * FROM credentials"
            ).fetchall()
            new_creds = [dict(r) | {"node_type": NodeType.CREDENTIAL.value} for r in rows]

        if not new_creds:
            logger.debug("replanner.no_new_credentials")
            return result

        result.new_credentials = new_creds

        # For each credential, trace ENABLES edges to find reachable targets
        for cred in new_creds:
            cred_id = cred["id"]

            # Find the source vulnerability (what ENABLES edge points to this cred)
            source_edges = self.graph.get_edges_to(cred_id, edge_type=EdgeType.ENABLES)
            source_vuln_id = source_edges[0]["source_id"] if source_edges else ""

            # Find targets this credential unlocks
            unlocked = self.graph.get_unlocked_targets(cred_id)

            if not unlocked:
                continue

            # Filter to targets that haven't been fully exploited
            reachable_ids: list[str] = []
            for target in unlocked:
                status = target.get("status", "")
                if status not in (
                    AttackStatus.EXPLOITED.value,
                    AttackStatus.CHAINED.value,
                    AttackStatus.HARDENED.value,
                ):
                    reachable_ids.append(target["id"])
                    if target["id"] not in result.new_targets_to_analyze:
                        result.new_targets_to_analyze.append(target["id"])

            if reachable_ids:
                chain = CredentialChain(
                    credential_id=cred_id,
                    credential_username=cred.get("username", ""),
                    source_vuln_id=source_vuln_id,
                    reachable_target_ids=reachable_ids,
                    depth=1,
                    score=self._score_chain(cred, reachable_ids),
                )
                result.new_paths.append(chain)

        result.should_replan = len(result.new_targets_to_analyze) > 0

        logger.info(
            "replanner.check_complete",
            new_credentials=len(new_creds),
            new_chains=len(result.new_paths),
            new_targets=len(result.new_targets_to_analyze),
            should_replan=result.should_replan,
        )

        return result

    def promote_targets(self, replan_result: ReplanResult) -> int:
        """
        Promote newly reachable targets to ANALYZED status so they
        appear in the next planning cycle's ready set.

        Returns the count of nodes promoted.
        """
        promoted = 0

        for node_id in replan_result.new_targets_to_analyze:
            node = self.graph.get_node(node_id)
            if node is None:
                continue

            status = node.get("status", "")

            # Only promote DISCOVERED nodes to ANALYZED (via RECOND intermediate)
            if status == AttackStatus.DISCOVERED.value:
                try:
                    self.graph.update_status(node_id, AttackStatus.RECOND)
                    self.graph.update_status(node_id, AttackStatus.ANALYZED)
                    promoted += 1
                except Exception as exc:
                    logger.warning(
                        "replanner.promote_failed",
                        node_id=node_id,
                        error=str(exc),
                    )
            elif status == AttackStatus.RECOND.value:
                try:
                    self.graph.update_status(node_id, AttackStatus.ANALYZED)
                    promoted += 1
                except Exception as exc:
                    logger.warning(
                        "replanner.promote_failed",
                        node_id=node_id,
                        error=str(exc),
                    )
            # ANALYZED nodes are already ready, no promotion needed
            elif status == AttackStatus.ANALYZED.value:
                promoted += 1

        logger.info(
            "replanner.promoted",
            count=promoted,
            total_candidates=len(replan_result.new_targets_to_analyze),
        )

        return promoted

    def find_credential_chains(self) -> list[CredentialChain]:
        """
        Find all multi-hop credential chains in the graph.

        A credential chain is: vuln -> (ENABLES) -> credential -> (ENABLES) -> target
        """
        chains: list[CredentialChain] = []

        rows = self.graph.conn.execute("SELECT * FROM credentials").fetchall()

        for row in rows:
            cred = dict(row)
            cred_id = cred["id"]

            # Find source vuln
            source_edges = self.graph.get_edges_to(cred_id, edge_type=EdgeType.ENABLES)
            source_vuln_id = source_edges[0]["source_id"] if source_edges else ""

            # Find unlocked targets
            unlocked = self.graph.get_unlocked_targets(cred_id)
            reachable_ids = [t["id"] for t in unlocked]

            if reachable_ids:
                chain = CredentialChain(
                    credential_id=cred_id,
                    credential_username=cred.get("username", ""),
                    source_vuln_id=source_vuln_id,
                    reachable_target_ids=reachable_ids,
                    depth=1,
                    score=self._score_chain(cred, reachable_ids),
                )
                chains.append(chain)

        chains.sort(key=lambda c: c.score, reverse=True)
        return chains

    def _score_chain(
        self,
        credential: dict[str, Any],
        reachable_ids: list[str],
    ) -> float:
        """
        Score a credential chain based on:
        - Number of reachable targets (breadth)
        - Access level of the credential (privilege gained)
        - Target node severity/value
        """
        # Breadth factor: more targets = higher score
        breadth = min(1.0, len(reachable_ids) / 5.0)

        # Privilege factor: higher access level = higher score
        access_level = credential.get("access_level", "")
        privilege_scores = {
            "root": 1.0,
            "admin": 0.8,
            "user": 0.4,
            "anonymous": 0.1,
        }
        privilege = privilege_scores.get(access_level, 0.3)

        # Target value: average severity of reachable nodes
        total_severity = 0.0
        severity_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}
        counted = 0
        for target_id in reachable_ids:
            node = self.graph.get_node(target_id)
            if node and node.get("severity"):
                total_severity += severity_map.get(node["severity"], 0.3)
                counted += 1

        target_value = (total_severity / counted) if counted > 0 else 0.3

        # Composite: 40% breadth, 35% privilege, 25% target value
        return round(breadth * 0.40 + privilege * 0.35 + target_value * 0.25, 3)
