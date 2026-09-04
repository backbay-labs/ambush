/**
 * Reading the Watchfloor's numbers off the ephemeral frames.
 *
 * Every reader here answers `null` for "no frame has arrived" and a number
 * only when a frame said so. A wall that renders absence as zero is the
 * failure mode this whole screen exists to avoid: it is read from across a
 * room by someone who will not check.
 */

import type { PerchTelemetryEntry } from "@/shared/api/perchEphemeralStore";
import type { ConcentrationSample } from "@/shared/viz/types";

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * One class's sample from a 26001 frame, or `null` when the frame carries no
 * row for it. A class absent from the frame is not a class at zero.
 */
export function sampleForClass(
  entry: PerchTelemetryEntry | undefined,
  threatClass: string,
): ConcentrationSample | null {
  if (!entry) return null;
  const body = entry.body as Record<string, unknown>;
  const rows = Array.isArray(body.concentrations) ? body.concentrations : [];
  const found = rows
    .map(asRecord)
    .find((row) => row?.threat_class === threatClass);
  if (!found) return null;
  const total = asNumber(found.total_strength);
  if (total === null) return null;
  return {
    at: Math.floor(entry.receivedAtMs / 1000),
    total_strength: total,
    distinct_sources: asNumber(found.distinct_sources) ?? 0,
    peak_confidence: asNumber(found.peak_confidence) ?? 0,
  };
}

/**
 * Append a sample to a bounded ring, dropping the OLDEST.
 *
 * The newest point is what the caption reports, so it can never be the one
 * evicted. The window is bounded because this screen runs for days.
 */
export function appendSample(
  history: readonly ConcentrationSample[],
  sample: ConcentrationSample,
  cap: number,
): ConcentrationSample[] {
  const last = history[history.length - 1];
  if (last && last.at === sample.at) return [...history];
  const next = [...history, sample];
  return next.length <= cap ? next : next.slice(next.length - cap);
}

/** Seconds since the newest frame of any kind, or `null` when none has come. */
export function frameAgeSeconds(
  entry: PerchTelemetryEntry | undefined,
  nowMs: number,
): number | null {
  if (!entry) return null;
  return Math.max(0, Math.floor((nowMs - entry.receivedAtMs) / 1000));
}

export type ColonyAgent = {
  agentId: string;
  role: string;
  healthy: boolean;
};

/** The agents a 26002 frame names. An absent frame is no agents KNOWN, not none alive. */
export function colonyAgents(
  entry: PerchTelemetryEntry | undefined,
): ColonyAgent[] | null {
  if (!entry) return null;
  const body = entry.body as Record<string, unknown>;
  const rows = Array.isArray(body.agents) ? body.agents : [];
  return rows.flatMap((row) => {
    const record = asRecord(row);
    if (!record || typeof record.agent_id !== "string") return [];
    return [
      {
        agentId: record.agent_id,
        role: typeof record.role === "string" ? record.role : "unknown role",
        healthy: record.healthy === true,
      },
    ];
  });
}

/** The escalation mode a 26003 frame names, or `null`. */
export function colonyMode(
  entry: PerchTelemetryEntry | undefined,
): string | null {
  if (!entry) return null;
  const body = entry.body as Record<string, unknown>;
  return typeof body.mode === "string" ? body.mode : null;
}
