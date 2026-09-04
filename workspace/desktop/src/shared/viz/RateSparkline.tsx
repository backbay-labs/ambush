import * as React from "react";

import { sparkScale } from "./scales";

export type RateSparklineProps = {
  values: number[];
  seriesClass: "viz-series-1" | "viz-series-2" | "viz-series-3";
  /** The stream stopped. The line STOPS; it does not continue flat. */
  stale?: boolean;
  label: string;
  /** The magnitude, rendered as text. The line carries only shape. */
  value: string;
  width?: number;
  height?: number;
};

/**
 * VIZ-6. A rate's shape beside its number.
 *
 * The scale is the window's min–max, never zero-based, which is the only way a
 * rate varying between 900 and 1000 shows any shape at all. The cost is that
 * the baseline is not zero, so the line NEVER carries magnitude: the number
 * beside it does, and the path is `aria-hidden` because the number is the
 * announcement.
 *
 * A stale series stops rather than flat-lining. A flat line at the last value
 * is indistinguishable from a genuinely steady rate, which is the one reading
 * a stopped stream must not produce.
 */
export function RateSparkline({
  values,
  seriesClass,
  stale = false,
  label,
  value,
  width = 60,
  height = 16,
}: RateSparklineProps): React.ReactElement {
  const points = React.useMemo(() => {
    if (values.length === 0) return "";
    const y = sparkScale(values, height);
    const step = values.length === 1 ? 0 : width / (values.length - 1);
    return values
      .map((v, i) => `${(i * step).toFixed(2)},${y(v).toFixed(2)}`)
      .join(" ");
  }, [values, width, height]);

  const last = values.length > 0 ? values[values.length - 1] : null;

  return (
    <span
      data-testid="perch-rate-sparkline"
      data-stale={stale ? "1" : "0"}
      className="inline-flex items-center gap-2"
    >
      <span className="text-2xs text-muted-foreground">{label}</span>
      <span className="text-sm tabular-nums">{value}</span>
      <svg
        aria-hidden="true"
        focusable="false"
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
      >
        {points ? (
          <polyline
            className={seriesClass}
            fill="none"
            strokeWidth={1.5}
            points={points}
          />
        ) : null}
        {last !== null && !stale ? (
          <circle
            className={seriesClass}
            r={1.5}
            cx={width}
            cy={sparkScale(values, height)(last)}
          />
        ) : null}
      </svg>
      {stale ? (
        <span className="text-2xs text-muted-foreground">stopped</span>
      ) : null}
      <span className="text-2xs text-muted-foreground">min–max</span>
    </span>
  );
}
