import type * as React from "react";

import { linearScale } from "./scales";
import { DerivedMarker } from "./markers";
import { TableToggle } from "./TableToggle";
import { attributionText } from "./sourceAttribution";
import { type HostHeatRow, unattributedLabel } from "./hostHeat";

const BAR_WIDTH = 480;
const BAR_HEIGHT = 14;
const ROW_GAP = 6;

export type HostHeatProps = {
  rows: HostHeatRow[];
  /** The alert threshold, drawn as a tick at the same x on every bar. */
  threshold: number;
};

/**
 * VIZ-2. Which hosts carry the concentration.
 *
 * One derived marker for the whole plate rather than one per bar: every number
 * here is the console's own per-host sum, because the runtime concentrates by
 * threat class and has no per-host figure at all. Marking each bar would imply
 * some other bar might be served.
 *
 * The threshold tick sits at the same x on every bar, so bars are comparable
 * against one number by eye. Bars past it change series rather than colour
 * family, and the table carries the values either way.
 */
export function HostHeat({
  rows,
  threshold,
}: HostHeatProps): React.ReactElement {
  const max = Math.max(threshold, ...rows.map((r) => r.strength), 1);
  const x = linearScale([0, max], [0, BAR_WIDTH]);
  const height = rows.length * (BAR_HEIGHT + ROW_GAP);

  return (
    <figure data-testid="perch-host-heat" className="mt-3">
      <figcaption className="flex items-baseline gap-2 text-xs text-muted-foreground">
        <span>Concentration by host</span>
        <DerivedMarker />
        <span>per-host sum; the runtime has no per-host concentration</span>
      </figcaption>
      <svg
        role="img"
        aria-label={`${rows.length} hosts, highest ${rows[0]?.strength.toFixed(2) ?? "0.00"} against an alert threshold of ${threshold.toFixed(2)}`}
        width={BAR_WIDTH}
        height={Math.max(height, 1)}
        viewBox={`0 0 ${BAR_WIDTH} ${Math.max(height, 1)}`}
        className="max-w-full"
      >
        <title>Concentration by host</title>
        {rows.map((row, index) => {
          const y = index * (BAR_HEIGHT + ROW_GAP);
          const filled = x(row.strength);
          return (
            <g key={row.host} transform={`translate(0,${y})`}>
              <rect
                className="viz-unfilled"
                width={BAR_WIDTH}
                height={BAR_HEIGHT}
              />
              <rect
                className={
                  row.strength > threshold ? "viz-series-3" : "viz-series-1"
                }
                width={filled}
                height={BAR_HEIGHT}
              />
              <line
                className="viz-threshold"
                x1={x(threshold)}
                y1={0}
                x2={x(threshold)}
                y2={BAR_HEIGHT}
              />
            </g>
          );
        })}
      </svg>
      <ul className="mt-1 space-y-0.5">
        {rows.map((row) => (
          <li key={row.host} className="text-xs">
            <span className="font-mono">
              {row.unattributed ? unattributedLabel(row) : row.host}
            </span>
            {" · "}
            {row.strength.toFixed(2)}
            {" · "}
            {attributionText({ kind: "ids", sourceIds: row.sourceIds })}
            {" · "}
            {row.dominantThreatClass}
          </li>
        ))}
      </ul>
      <TableToggle
        label="Show the table"
        caption="Per-host concentration, summed by this console from the served deposits."
        rows={rows.map((row) => ({
          host: row.host,
          strength: row.strength.toFixed(4),
          deposits: row.depositCount,
          sources: attributionText({ kind: "ids", sourceIds: row.sourceIds }),
          dominant_threat_class: row.dominantThreatClass,
        }))}
      />
    </figure>
  );
}
