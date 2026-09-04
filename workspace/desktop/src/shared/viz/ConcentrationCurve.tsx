import * as React from "react";

import {
  CURVE_PLOT_BOTTOM,
  CURVE_PLOT_LEFT,
  CURVE_PLOT_RIGHT,
  CURVE_PLOT_TOP,
  CURVE_VIEW_HEIGHT,
  CURVE_VIEW_WIDTH,
  clockSkewed,
  curvePoints,
  polylinePoints,
  resampleCurve,
  rulePlacement,
} from "./curveGeometry";
import { forwardSegmentNote } from "./concentration";
import { DerivedMarker, ServedMarker } from "./markers";
import { TableToggle } from "./TableToggle";
import { attributionText } from "./sourceAttribution";
import type {
  ConcentrationSample,
  DepositView,
  SourceAttribution,
  SuppressionMarker,
  ThreatClassPolicy,
  VizState,
} from "./types";

export type ConcentrationCurveProps = {
  threatClass: string;
  policy: ThreatClassPolicy;
  samples: ConcentrationSample[];
  /**
   * Regime A: the deposits behind the curve. `null` is regime B — a
   * snapshot-only view whose curve is interpolated between samples. The two
   * regimes are not the same claim and the caption says which is on screen.
   */
  deposits: DepositView[] | null;
  suppressions: SuppressionMarker[];
  now: number;
  nowFromDaemon: number;
  attribution: SourceAttribution;
  state: VizState;
};

function hhmm(seconds: number): string {
  const d = new Date(seconds * 1000);
  return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
}

/**
 * VIZ-1. One threat class's concentration over time.
 *
 * The chart's job is to be trustworthy about three things it could easily lie
 * about. The y axis is never zero-suppressed, because a suppressed axis turns
 * a three percent rise into an apparent doubling on the one chart where a
 * threshold crossing is the decision. A threshold above the visible range is
 * pinned to the top AND labelled off-scale, never drawn at the top silently. A
 * suppression is hatched and stepped rather than smoothed away, because a
 * suppression subtracts retroactively and is the only non-monotone event here.
 *
 * The caption carries both provenance markers, always: the curve is derived by
 * this console and the header number is served by the daemon, and when they
 * disagree an operator has to know which is which without opening a table.
 */
export function ConcentrationCurve({
  threatClass,
  policy,
  samples,
  deposits,
  suppressions,
  now,
  nowFromDaemon,
  attribution,
  state,
}: ConcentrationCurveProps): React.ReactElement {
  const newest = samples.length > 0 ? samples[samples.length - 1] : null;
  const geometry = React.useMemo(
    () => curvePoints(resampleCurve(samples), policy),
    [samples, policy],
  );
  const alertRule = rulePlacement(policy.alert_threshold, geometry.yDomain);
  const incidentRule = rulePlacement(
    policy.incident_threshold,
    geometry.yDomain,
  );
  const skewed = clockSkewed(now, nowFromDaemon);

  const regime =
    deposits === null ? "regime B · snapshot-only" : "regime A · deposits";
  const description =
    newest === null
      ? `No concentration samples for ${threatClass}.`
      : `${threatClass}: concentration ${newest.total_strength.toFixed(2)} against an alert threshold of ${policy.alert_threshold.toFixed(2)}, from ${attributionText(attribution)}.`;

  return (
    <figure
      data-testid="perch-concentration-curve"
      data-threat-class={threatClass}
      data-viz-state={state.kind}
      className="mt-2"
    >
      <svg
        role="img"
        aria-label={description}
        viewBox={`0 0 ${CURVE_VIEW_WIDTH} ${CURVE_VIEW_HEIGHT}`}
        className="w-full"
        style={{ maxWidth: CURVE_VIEW_WIDTH }}
      >
        <title>{`Concentration decay — ${threatClass}`}</title>
        <rect
          className="viz-plot-ground"
          x={CURVE_PLOT_LEFT}
          y={CURVE_PLOT_TOP}
          width={CURVE_PLOT_RIGHT - CURVE_PLOT_LEFT}
          height={CURVE_PLOT_BOTTOM - CURVE_PLOT_TOP}
        />
        <text className="text-sm viz-axis" x={0} y={CURVE_PLOT_TOP + 14}>
          {threatClass}
        </text>

        <line
          className="viz-threshold"
          x1={CURVE_PLOT_LEFT}
          y1={alertRule.y}
          x2={CURVE_PLOT_RIGHT}
          y2={alertRule.y}
        />
        <text
          className="text-2xs viz-rule-label"
          x={CURVE_PLOT_LEFT}
          y={alertRule.y - 8}
        >
          {alertRule.kind === "off-scale"
            ? `alert_threshold ${policy.alert_threshold.toFixed(2)} — above this view`
            : `alert_threshold ${policy.alert_threshold.toFixed(2)}`}
        </text>

        <line
          className="viz-incident"
          x1={CURVE_PLOT_LEFT}
          y1={incidentRule.y}
          x2={CURVE_PLOT_RIGHT}
          y2={incidentRule.y}
        />
        <text
          className="text-2xs viz-rule-label"
          x={CURVE_PLOT_LEFT}
          y={incidentRule.y - 8}
        >
          {incidentRule.kind === "off-scale"
            ? `incident_threshold ${policy.incident_threshold.toFixed(2)} — above this view`
            : `incident_threshold ${policy.incident_threshold.toFixed(2)}`}
        </text>

        {geometry.points.length > 0 ? (
          <polyline
            className="viz-series-1"
            fill="none"
            strokeWidth={2}
            strokeLinejoin="round"
            points={polylinePoints(geometry.points)}
          />
        ) : null}

        {suppressions.map((suppression) => {
          const at = samples.findIndex((s) => s.at >= suppression.at);
          const point = at === -1 ? null : geometry.points[at];
          if (!point) return null;
          return (
            <g key={`${suppression.at}-${suppression.reason}`}>
              <line
                className="viz-danger-mark"
                x1={point.x}
                y1={CURVE_PLOT_TOP}
                x2={point.x}
                y2={CURVE_PLOT_BOTTOM}
              />
              <text
                className="text-2xs viz-rule-label"
                x={point.x + 4}
                y={CURVE_PLOT_TOP + 12}
              >
                {`DISMISSED ${hhmm(suppression.at)}`}
              </text>
            </g>
          );
        })}

        {samples.length > 0 ? (
          <>
            <text
              className="text-2xs viz-axis"
              x={CURVE_PLOT_LEFT}
              y={CURVE_PLOT_BOTTOM + 16}
            >
              {hhmm(samples[0].at)}
            </text>
            <text
              className="text-2xs viz-axis"
              x={CURVE_PLOT_RIGHT - 32}
              y={CURVE_PLOT_BOTTOM + 16}
            >
              {hhmm(samples[samples.length - 1].at)}
            </text>
          </>
        ) : null}
      </svg>

      <figcaption className="text-xs text-muted-foreground">
        {newest !== null ? (
          <span>
            {`total_strength ${newest.total_strength.toFixed(2)} · ${attributionText(attribution)} · peak_confidence ${newest.peak_confidence.toFixed(2)} `}
            <ServedMarker route="GET /v1/operator/pheromone/deposits" />{" "}
            <DerivedMarker />
          </span>
        ) : (
          <span>{description}</span>
        )}
        <span className="block">{regime}</span>
        {deposits === null ? (
          <span className="block">
            {`assumes every live deposit carries half_life_secs ${policy.half_life_secs}`}
          </span>
        ) : null}
        <span className="block">{forwardSegmentNote()}</span>
        {skewed ? (
          <span data-testid="perch-curve-skew" className="block">
            {`this console's clock and the daemon's differ by ${Math.abs(now - nowFromDaemon)}s; times on this chart are the daemon's`}
          </span>
        ) : null}
      </figcaption>

      {deposits !== null ? (
        <TableToggle
          label="Show the table"
          caption={`Deposits behind ${threatClass}, as served.`}
          rows={deposits.map((deposit) => ({
            agent: deposit.agent_id,
            strategy_id: deposit.strategy_id,
            timestamp: deposit.timestamp,
            confidence: deposit.confidence.toFixed(2),
          }))}
        />
      ) : null}
    </figure>
  );
}
