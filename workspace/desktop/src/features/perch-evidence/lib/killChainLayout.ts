/**
 * The kill-chain graph's layout, computed once from the member list.
 *
 * A fixed column/row grid, not a force layout. A force layout moves nodes
 * between renders for reasons that have nothing to do with the data, and an
 * operator comparing two screenshots of the same incident must see the same
 * picture. Determinism here is a correctness property, not a performance one.
 */

export type IncidentMemberDecision = {
  findingId: string;
  strategyId: string;
  host: string;
  confidence: number;
  reason: string;
  /** Seed member of the correlation. Kept when the drawing is truncated. */
  seed?: boolean;
};

export type IncidentGraphDimension =
  | "temporal"
  | "causal"
  | "entity"
  | "semantic";

export type IncidentGraphEdge = {
  from: string;
  to: string;
  dimension: IncidentGraphDimension;
};

export const NODE_WIDTH = 232;
export const NODE_HEIGHT = 56;
const COLUMN_GAP = 48;
const ROW_GAP = 24;

/**
 * Above this many nodes the drawing keeps the seed plus its direct links and
 * everything else goes to the table. A graph nobody can read is not a graph;
 * the table is the complete record either way.
 */
export const DRAWN_NODE_CAP = 12;

/** Reasons are truncated in the node and printed in full in the table. */
export const REASON_NODE_CHARS = 33;

export type PlacedNode = {
  findingId: string;
  x: number;
  y: number;
};

export type KillChainLayout = {
  nodes: PlacedNode[];
  /** Members the drawing left out. Never dropped — they are in the table. */
  omitted: IncidentMemberDecision[];
  width: number;
  height: number;
};

/** `reason` as it appears inside a node: whole, or cut with an ellipsis. */
export function nodeReason(reason: string): string {
  const chars = [...reason];
  if (chars.length <= REASON_NODE_CHARS) return reason;
  return `${chars.slice(0, REASON_NODE_CHARS - 1).join("")}…`;
}

/**
 * Which members the drawing shows.
 *
 * Under the cap, all of them. Over it, the seed plus every member directly
 * linked to the seed — the subgraph an operator is actually tracing — and the
 * rest are `omitted` rather than deleted.
 */
export function drawnMembers(
  members: IncidentMemberDecision[],
  edges: IncidentGraphEdge[],
): { drawn: IncidentMemberDecision[]; omitted: IncidentMemberDecision[] } {
  if (members.length <= DRAWN_NODE_CAP) {
    return { drawn: members, omitted: [] };
  }
  const seed = members.find((member) => member.seed) ?? members[0];
  const linked = new Set<string>([seed.findingId]);
  for (const edge of edges) {
    if (edge.from === seed.findingId) linked.add(edge.to);
    if (edge.to === seed.findingId) linked.add(edge.from);
  }
  const drawn = members.filter((member) => linked.has(member.findingId));
  const omitted = members.filter((member) => !linked.has(member.findingId));
  return { drawn, omitted };
}

/**
 * Place the drawn members on a fixed grid, column-major by strategy.
 *
 * Members sharing a strategy stack in one column, so the columns read as the
 * stages of the chain and a member's position carries meaning. Column order is
 * first-appearance, which is the order the correlation produced them.
 */
export function killChainLayout(
  members: IncidentMemberDecision[],
  edges: IncidentGraphEdge[],
): KillChainLayout {
  const { drawn, omitted } = drawnMembers(members, edges);
  const columns: string[] = [];
  for (const member of drawn) {
    if (!columns.includes(member.strategyId)) columns.push(member.strategyId);
  }
  const rowCounts = new Map<string, number>();
  const nodes = drawn.map((member) => {
    const column = columns.indexOf(member.strategyId);
    const row = rowCounts.get(member.strategyId) ?? 0;
    rowCounts.set(member.strategyId, row + 1);
    return {
      findingId: member.findingId,
      x: column * (NODE_WIDTH + COLUMN_GAP),
      y: row * (NODE_HEIGHT + ROW_GAP),
    };
  });
  const tallest = Math.max(0, ...rowCounts.values());
  return {
    nodes,
    omitted,
    width: Math.max(0, columns.length * (NODE_WIDTH + COLUMN_GAP) - COLUMN_GAP),
    height: Math.max(0, tallest * (NODE_HEIGHT + ROW_GAP) - ROW_GAP),
  };
}

/**
 * The dash pattern for one dimension.
 *
 * Four patterns, never four colours: dimension is not severity, and a reader
 * with a colour-vision difference must be able to tell a causal edge from a
 * temporal one. The patterns are also distinguishable in a greyscale print of
 * a screenshot, which is how these end up in an incident report.
 */
export function edgeDash(
  dimension: IncidentGraphDimension,
): string | undefined {
  switch (dimension) {
    case "temporal":
      return undefined;
    case "causal":
      return "4 2";
    case "entity":
      return "2 2";
    case "semantic":
      return "6 3";
  }
}
