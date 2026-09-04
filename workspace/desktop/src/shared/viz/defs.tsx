import type * as React from "react";

/**
 * The SVG defs every Perch chart references, mounted once per screen.
 *
 * A `<defs>` block per chart would give each chart its own gradient id, and
 * two charts on one screen would then paint from two definitions that are
 * meant to be identical. One mount, one id, one definition.
 */
export function VizDefs(): React.ReactElement {
  return (
    <svg width="0" height="0" aria-hidden="true" focusable="false">
      <defs>
        {/* Suppressed regions are hatched, not tinted: a tint reads as a
            different severity, a hatch reads as "this was removed". */}
        <pattern
          id="perchHatch"
          width="6"
          height="6"
          patternUnits="userSpaceOnUse"
          patternTransform="rotate(45)"
        >
          <line
            className="viz-hatch"
            x1="0"
            y1="0"
            x2="0"
            y2="6"
            strokeWidth="1"
          />
        </pattern>
        <linearGradient id="perchAreaGrad" x1="0" y1="0" x2="0" y2="1">
          <stop className="stop-series-1" offset="0" stopOpacity="0.30" />
          <stop className="stop-series-1" offset="1" stopOpacity="0.02" />
        </linearGradient>
      </defs>
    </svg>
  );
}
