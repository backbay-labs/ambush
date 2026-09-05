/**
 * The live numbers a lane header and the sidebar dot read.
 *
 * They come from the 26001 concentration frame, never from a channel topic.
 * The topic is edge-written and durable; these are ephemeral and per-second,
 * and reading a number off the topic would show whatever it said at the last
 * crossing rather than what is true now.
 */

import type { PerchTelemetryEntry } from "@/shared/api/perchEphemeralStore";

/** The policy the daemon actually applied, served beside the number. */
export type LanePolicy = {
  alertThreshold: number;
  incidentThreshold: number;
};

export type LaneLiveNumbers = {
  totalStrength: number;
  distinctSources: number;
  peakConfidence: number;
  alertThreshold: number;
  incidentThreshold: number;
  /**
   * Age of the newest 26001 frame. Rendered as a number: a header that hid
   * staleness would present a frozen reading as a live one.
   */
  ageMs: number;
  aboveAlert: boolean;
};

/** Past this, the header says the telemetry is stale rather than showing it plain. */
export const LANE_STALE_AFTER_MS = 5_000;

function asNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

/**
 * The numbers for one threat class, or `null` when no frame has arrived.
 *
 * `null` is not zero. A lane with no frame yet and a lane whose concentration
 * really is zero are different states, and only one of them means the console
 * has been told anything.
 */
export function laneLiveNumbers(
  entry: PerchTelemetryEntry | undefined,
  slug: string,
  policy: LanePolicy,
  nowMs: number,
): LaneLiveNumbers | null {
  if (!entry) return null;
  const body = entry.body as Record<string, unknown>;
  const raw = Array.isArray(body.concentrations) ? body.concentrations : [];
  const found = raw.find((item) => {
    const record =
      typeof item === "object" && item !== null
        ? (item as Record<string, unknown>)
        : {};
    return record.threat_class === slug;
  });
  if (!found) return null;
  const record = found as Record<string, unknown>;
  const totalStrength = asNumber(record.total_strength);
  return {
    totalStrength,
    distinctSources: asNumber(record.distinct_sources),
    peakConfidence: asNumber(record.peak_confidence),
    alertThreshold: policy.alertThreshold,
    incidentThreshold: policy.incidentThreshold,
    ageMs: Math.max(0, nowMs - entry.receivedAtMs),
    aboveAlert: totalStrength >= policy.alertThreshold,
  };
}

/** Whether the newest frame is old enough that the header must say so. */
export function laneTelemetryIsStale(numbers: LaneLiveNumbers): boolean {
  return numbers.ageMs > LANE_STALE_AFTER_MS;
}
