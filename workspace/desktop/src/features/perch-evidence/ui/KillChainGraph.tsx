import * as React from "react";

import {
  DRAWN_NODE_CAP,
  type IncidentGraphEdge,
  type IncidentMemberDecision,
  NODE_HEIGHT,
  NODE_WIDTH,
  edgeDash,
  killChainLayout,
  nodeReason,
} from "../lib/killChainLayout";

export type KillChainGraphProps = {
  incidentId: string;
  included: IncidentMemberDecision[];
  /**
   * Members the correlation considered and rejected. No default and no
   * optional marker: a caller that has not decided what to pass has not
   * decided whether this incident rejected anything, and defaulting to `[]`
   * would render "nothing was rejected" for "we did not ask".
   */
  rejected: IncidentMemberDecision[];
  edges: IncidentGraphEdge[];
};

/**
 * VIZ-3. What the correlation joined, and what it refused to join.
 *
 * Two rules the picture turns on. Dimension is carried by dash pattern, never
 * by colour, because dimension is not severity and the graph must survive a
 * greyscale print and a colour-vision difference. And the table is mandatory,
 * not a progressive enhancement: above twelve nodes the drawing keeps only the
 * seed's neighbourhood, so the table is the only complete record of the
 * incident and it carries the FULL finding id, which the nodes cannot.
 */
export function KillChainGraph({
  incidentId,
  included,
  rejected,
  edges,
}: KillChainGraphProps): React.ReactElement {
  const [tableOpen, setTableOpen] = React.useState(false);
  const layout = React.useMemo(
    () => killChainLayout(included, edges),
    [included, edges],
  );
  const positions = React.useMemo(
    () => new Map(layout.nodes.map((node) => [node.findingId, node])),
    [layout.nodes],
  );
  const byId = React.useMemo(
    () => new Map(included.map((member) => [member.findingId, member])),
    [included],
  );

  const truncated = layout.omitted.length > 0;
  const description = truncated
    ? `${included.length} correlated findings; ${layout.nodes.length} drawn around the seed, ${layout.omitted.length} in the table below. ${rejected.length} rejected.`
    : `${included.length} correlated findings across ${new Set(included.map((m) => m.strategyId)).size} strategies. ${rejected.length} rejected.`;

  return (
    <figure data-testid="perch-kill-chain" className="mt-4">
      <svg
        role="img"
        aria-label={description}
        width={layout.width || 1}
        height={layout.height || 1}
        viewBox={`0 0 ${layout.width || 1} ${layout.height || 1}`}
        className="perch-kill-chain-svg max-w-full"
      >
        <title>{`Kill chain for incident ${incidentId}`}</title>
        {edges.map((edge) => {
          const from = positions.get(edge.from);
          const to = positions.get(edge.to);
          if (!from || !to) return null;
          return (
            <line
              key={`${edge.from}-${edge.to}-${edge.dimension}`}
              className="perch-kill-chain-edge"
              strokeDasharray={edgeDash(edge.dimension)}
              x1={from.x + NODE_WIDTH}
              y1={from.y + NODE_HEIGHT / 2}
              x2={to.x}
              y2={to.y + NODE_HEIGHT / 2}
            />
          );
        })}
        {layout.nodes.map((node) => {
          const member = byId.get(node.findingId);
          if (!member) return null;
          return (
            <g
              key={node.findingId}
              transform={`translate(${node.x},${node.y})`}
            >
              <rect
                className="perch-kill-chain-node"
                width={NODE_WIDTH}
                height={NODE_HEIGHT}
                rx={6}
              />
              <rect
                className="perch-kill-chain-rail"
                width={NODE_WIDTH}
                height={2.5}
              />
              <text className="perch-kill-chain-strategy" x={8} y={20}>
                {member.strategyId}
              </text>
              <text className="perch-kill-chain-meta" x={8} y={34}>
                {`${member.host} · ${member.findingId.slice(0, 8)} · ${member.confidence.toFixed(2)}`}
              </text>
              <text className="perch-kill-chain-reason" x={8} y={48}>
                {nodeReason(member.reason)}
              </text>
            </g>
          );
        })}
      </svg>

      <figcaption className="mt-2 text-xs text-muted-foreground">
        {description}
        {truncated
          ? ` Above ${DRAWN_NODE_CAP} nodes the drawing keeps the seed and its direct links; the table is the whole incident.`
          : null}
      </figcaption>

      <button
        type="button"
        data-testid="perch-kill-chain-table-toggle"
        aria-expanded={tableOpen}
        className="mt-2 rounded border border-border px-2 py-1 text-xs"
        onClick={() => setTableOpen((open) => !open)}
      >
        {tableOpen ? "Hide the table" : "Show the table"}
      </button>

      {tableOpen ? (
        <div className="mt-2 overflow-x-auto">
          <table data-testid="perch-kill-chain-table" className="text-xs">
            <thead>
              <tr>
                <th className="pr-3 text-left">In</th>
                <th className="pr-3 text-left">Strategy</th>
                <th className="pr-3 text-left">Host</th>
                <th className="pr-3 text-left">Finding</th>
                <th className="pr-3 text-left">Confidence</th>
                <th className="text-left">Reason</th>
              </tr>
            </thead>
            <tbody>
              {[
                ...included.map((m) => ({ member: m, included: true })),
                ...rejected.map((m) => ({ member: m, included: false })),
              ].map(({ member, included: isIncluded }) => (
                <tr
                  key={`${isIncluded ? "in" : "out"}-${member.findingId}`}
                  data-included={isIncluded ? "1" : "0"}
                >
                  <td className="pr-3">
                    {isIncluded ? "included" : "rejected"}
                  </td>
                  <td className="pr-3">{member.strategyId}</td>
                  <td className="pr-3">{member.host}</td>
                  <td className="pr-3 font-mono">{member.findingId}</td>
                  <td className="pr-3">{member.confidence.toFixed(2)}</td>
                  <td>{member.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </figure>
  );
}
