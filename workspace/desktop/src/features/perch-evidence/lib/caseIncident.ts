import type {
  PerchIncidentMember,
  PerchIncidentRead,
} from "@/shared/api/tauriPerch";

import type {
  IncidentGraphEdge,
  IncidentMemberDecision,
} from "./killChainLayout";

/** What the kill-chain figure draws, from what the daemon served. */
export type CaseKillChain = {
  included: IncidentMemberDecision[];
  rejected: IncidentMemberDecision[];
  edges: IncidentGraphEdge[];
};

/** The incident id the daemon mints for a case channel. */
export function caseIncidentId(caseChannelId: string): string {
  return `incident:perch-case:${caseChannelId}`;
}

/**
 * A member's host and strategy are what the daemon could say, or nothing:
 * `—` is rendered where the daemon recorded no host, and never a guess.
 */
function decision(
  member: PerchIncidentMember,
  seedFindingId: string | null,
): IncidentMemberDecision {
  return {
    findingId: member.finding_id,
    strategyId: member.strategy_id ?? "—",
    host: member.host_id ?? "—",
    confidence: member.confidence_score,
    reason: member.reason,
    seed: seedFindingId !== null && member.finding_id === seedFindingId,
  };
}

/**
 * Edges come from evidence links: each link on a joined member is an edge
 * from the seed to that member on the link's dimension. A member with no
 * links is joined but unexplained, which the figure shows as a node with no
 * edge rather than an invented one. Rejected members get no edges: the
 * figure's rule is that a refused member sits below the line with its reason.
 */
export function killChainFromIncident(read: PerchIncidentRead): CaseKillChain {
  const seed =
    read.trigger_finding_id ?? read.included_members[0]?.finding_id ?? null;
  const included = read.included_members.map((member) =>
    decision(member, seed),
  );
  const rejected = read.rejected_members.map((member) =>
    decision(member, seed),
  );
  const edges: IncidentGraphEdge[] = [];
  const seen = new Set<string>();
  if (seed !== null) {
    for (const member of read.included_members) {
      if (member.finding_id === seed) continue;
      for (const link of member.evidence_links) {
        const key = `${member.finding_id}:${link.dimension}`;
        if (seen.has(key)) continue;
        seen.add(key);
        edges.push({
          from: seed,
          to: member.finding_id,
          dimension: link.dimension,
        });
      }
    }
  }
  return { included, rejected, edges };
}
