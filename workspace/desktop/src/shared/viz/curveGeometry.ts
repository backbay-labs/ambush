import { linearScale } from "./scales";
import type {
  ConcentrationSample,
  DepositView,
  ThreatClassPolicy,
} from "./types";
import { strengthAt } from "./concentration";

/**
 * The concentration curve's geometry, computed apart from React.
 *
 * All of the ways this chart can lie are arithmetic, so the arithmetic is
 * testable on its own: a y-domain that suppresses zero, a threshold rule drawn
 * off-plot without saying so, a resampling that drops the newest point.
 */

export const CURVE_VIEW_WIDTH = 960;
export const CURVE_VIEW_HEIGHT = 260;
export const CURVE_PLOT_LEFT = 186;
export const CURVE_PLOT_RIGHT = 940;
export const CURVE_PLOT_TOP = 16;
export const CURVE_PLOT_BOTTOM = 210;
/** Above this many samples the series is resampled. */
export const CURVE_MAX_POINTS = 120;
/** Beyond this many seconds of skew the caption warns. */
export const CLOCK_SKEW_WARN_SECONDS = 30;

/**
 * The y domain.
 *
 * Always starts at zero — a zero-suppressed axis makes a 3 % rise look like a
 * doubling, which on this chart is the difference between "quiet" and
 * "escalating". The top leaves headroom above whichever is larger, the alert
 * threshold or the observed peak, so the threshold rule is never drawn at the
 * very edge where it reads as the ceiling.
 */
export function curveYDomain(
  policy: ThreatClassPolicy,
  peak: number,
): [number, number] {
  return [0, Math.max(policy.alert_threshold * 1.35, peak) * 1.08];
}

/**
 * Resample to at most `CURVE_MAX_POINTS`, ALWAYS keeping the newest sample.
 *
 * A stride that drops the last point makes the curve end in the past while the
 * caption reports the present, and the gap is invisible.
 */
export function resampleCurve(
  samples: readonly ConcentrationSample[],
  max: number = CURVE_MAX_POINTS,
): ConcentrationSample[] {
  if (samples.length <= max) return [...samples];
  const stride = Math.ceil(samples.length / max);
  const kept: ConcentrationSample[] = [];
  for (let i = 0; i < samples.length; i += stride) kept.push(samples[i]);
  const newest = samples[samples.length - 1];
  if (kept[kept.length - 1] !== newest) kept.push(newest);
  return kept;
}

export type CurvePoint = { x: number; y: number };

export function curvePoints(
  samples: readonly ConcentrationSample[],
  policy: ThreatClassPolicy,
): { points: CurvePoint[]; yDomain: [number, number] } {
  if (samples.length === 0)
    return { points: [], yDomain: curveYDomain(policy, 0) };
  const peak = Math.max(...samples.map((s) => s.total_strength));
  const yDomain = curveYDomain(policy, peak);
  const xs = samples.map((s) => s.at);
  const x = linearScale(
    [Math.min(...xs), Math.max(...xs)],
    [CURVE_PLOT_LEFT, CURVE_PLOT_RIGHT],
  );
  const y = linearScale(yDomain, [CURVE_PLOT_BOTTOM, CURVE_PLOT_TOP]);
  return {
    points: samples.map((s) => ({ x: x(s.at), y: y(s.total_strength) })),
    yDomain,
  };
}

/** An SVG polyline `points` string. Empty for no points, never `"NaN,NaN"`. */
export function polylinePoints(points: readonly CurvePoint[]): string {
  return points.map((p) => `${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(" ");
}

export type RulePlacement =
  | { kind: "on-scale"; y: number }
  | { kind: "off-scale"; y: number };

/**
 * Where a threshold rule goes.
 *
 * A threshold above the y domain is drawn pinned to the top and REPORTED as
 * off-scale. Drawing it at the top silently would tell an operator the
 * concentration is at the incident threshold when it is nowhere near it.
 */
export function rulePlacement(
  value: number,
  yDomain: readonly [number, number],
): RulePlacement {
  const y = linearScale(yDomain, [CURVE_PLOT_BOTTOM, CURVE_PLOT_TOP])(value);
  if (value > yDomain[1]) return { kind: "off-scale", y: CURVE_PLOT_TOP };
  return { kind: "on-scale", y };
}

/** A deposit dot's radius and opacity. Both carry meaning; neither is decoration. */
export function depositDot(
  deposit: Pick<DepositView, "confidence" | "timestamp" | "decay_half_life">,
  now: number,
): { radius: number; opacity: number } {
  const strength = strengthAt(deposit, now);
  const remaining =
    deposit.confidence === 0 ? 0 : strength / deposit.confidence;
  return {
    radius: 2.6 + 2.2 * deposit.confidence,
    opacity: 0.35 + 0.55 * remaining,
  };
}

/** True when the console's clock and the daemon's disagree enough to matter. */
export function clockSkewed(
  nowSeconds: number,
  nowFromDaemon: number,
): boolean {
  return Math.abs(nowSeconds - nowFromDaemon) > CLOCK_SKEW_WARN_SECONDS;
}
