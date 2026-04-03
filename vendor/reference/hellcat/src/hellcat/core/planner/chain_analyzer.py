"""
ChainAnalyzer for multi-step exploit chain scoring.

Analyzes the TargetGraph's chains_to edges to find and score
multi-step attack paths. Used by the AttackScorer to compute
chain_potential for individual nodes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import structlog

from hellcat.offensive.target_graph.graph import TargetGraph
from hellcat.offensive.target_graph.models import AttackStatus, Severity

logger = structlog.get_logger()


# Severity -> chain value weight
_SEVERITY_VALUES: dict[Severity, float] = {
    Severity.INFO: 0.1,
    Severity.LOW: 0.3,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.8,
    Severity.CRITICAL: 1.0,
}


@dataclass
class ExploitChain:
    """A scored multi-step exploit chain."""

    node_ids: list[str] = field(default_factory=list)
    value: float = 0.0
    length: int = 0


class ChainAnalyzer:
    """
    Analyzes exploit chains in the TargetGraph.

    Traverses chains_to edges to find multi-step attack paths and
    scores them by cumulative severity value.
    """

    def analyze_chains(self, graph: TargetGraph, from_node_id: str) -> list[ExploitChain]:
        """
        Find all exploit chains starting from a node.

        Uses graph.get_exploit_chains() and scores each chain's value.
        """
        raw_chains = graph.get_exploit_chains(from_node_id)
        chains: list[ExploitChain] = []

        for node_ids in raw_chains:
            value = self.chain_value(graph, node_ids)
            chain = ExploitChain(
                node_ids=node_ids,
                value=round(value, 3),
                length=len(node_ids),
            )
            chains.append(chain)

        # Sort by value descending
        chains.sort(key=lambda c: c.value, reverse=True)

        logger.debug(
            "planner.chains_analyzed",
            from_node=from_node_id,
            chain_count=len(chains),
            best_value=chains[0].value if chains else 0.0,
        )

        return chains

    def chain_value(self, graph: TargetGraph, node_ids: list[str]) -> float:
        """Compute the value of a chain as the sum of severity scores of all nodes."""
        total = 0.0

        for node_id in node_ids:
            node = graph.get_node(node_id)
            if node is None:
                continue

            sev_str = node.get("severity", "")
            if sev_str:
                try:
                    sev = Severity(sev_str)
                    total += _SEVERITY_VALUES.get(sev, 0.0)
                except ValueError:
                    pass

        return total

    def get_chain_potential(self, graph: TargetGraph, node_id: str) -> float:
        """
        Return a 0.0-1.0 normalized score for how many/valuable chains this node enables.

        Looks at outgoing chains_to edges and scores based on count and
        aggregate chain value.
        """
        chains = graph.get_exploit_chains(node_id)

        if not chains:
            return 0.0

        # Count of chains this node participates in
        chain_count = len(chains)

        # Total value across all chains
        total_value = 0.0
        for chain_node_ids in chains:
            total_value += self.chain_value(graph, chain_node_ids)

        # Normalize: chain count factor (cap at 5 chains for 1.0)
        count_factor = min(1.0, chain_count / 5.0)

        # Value factor: average chain value normalized (cap at 3.0 total for 1.0)
        avg_value = total_value / chain_count if chain_count > 0 else 0.0
        value_factor = min(1.0, avg_value / 3.0)

        # Combine: 60% count, 40% value
        potential = count_factor * 0.6 + value_factor * 0.4

        logger.debug(
            "planner.chain_potential",
            node_id=node_id,
            chain_count=chain_count,
            total_value=round(total_value, 3),
            potential=round(potential, 3),
        )

        return round(potential, 3)

    def find_critical_chain(self, graph: TargetGraph) -> ExploitChain | None:
        """
        Find the highest-value chain across all EXPLOITED nodes in the graph.

        Returns the best ExploitChain, or None if no chains exist.
        """
        best: ExploitChain | None = None

        # Get all exploited nodes as chain starting points
        stats = graph.get_stats()
        exploited_nodes: list[str] = []

        for node_type_info in stats.values():
            if not isinstance(node_type_info, dict):
                continue
            by_status = node_type_info.get("by_status", {})
            if AttackStatus.EXPLOITED.value in by_status:
                # Need to query actual node IDs
                pass

        # Query each table for exploited nodes
        for table in ("targets", "vulnerabilities", "credentials", "access_levels", "defenses"):
            rows = graph.conn.execute(
                f"SELECT id FROM {table} WHERE status = ?",  # noqa: S608
                (AttackStatus.EXPLOITED.value,),
            ).fetchall()
            exploited_nodes.extend(r["id"] for r in rows)

        if not exploited_nodes:
            logger.debug("planner.no_exploited_nodes_for_chains")
            return None

        for node_id in exploited_nodes:
            chains = self.analyze_chains(graph, node_id)
            for chain in chains:
                if best is None or chain.value > best.value:
                    best = chain

        if best:
            logger.info(
                "planner.critical_chain_found",
                chain_length=best.length,
                chain_value=best.value,
                start_node=best.node_ids[0] if best.node_ids else "",
            )

        return best
