/**
 * Which register the governance strip paints.
 *
 * A PROJECTION, and marked derived where it is shown. The daemon's 26004 frame
 * is authoritative; this only decides how to present it, and the strip names
 * the function so a reader can tell a reading from an interpretation.
 */
export type PerchGovernanceMode =
  | "healthy"
  | "degraded"
  | "partitioned"
  | "healing"
  | "fail-closed-no-transport"
  | "stale"
  | "bridge-down";

/**
 * Governance liveness is not restart-safe, so a strip that said `healthy` from
 * a stale snapshot would be worse than one that said nothing. Two missed 1 Hz
 * frames plus the pacer's own tick.
 */
export const GOVERNANCE_STALE_AFTER_MS = 3_000;

export type GovernanceInput = {
  partitionState: "healthy" | "degraded" | "partitioned" | "healing";
  totalGovernors: number;
  healthyGovernors: number;
  receivedAtMs: number | null;
  nowMs: number;
  bridgeShedding: boolean;
  staleAfterMs: number;
};

/**
 * The strip's register.
 *
 * Order matters and each step outranks the ones below it for a reason: with no
 * frame at all the console knows nothing, a stale frame is a reading about the
 * past, and a committee larger than one is a deployment that will veto every
 * destructive action until a networked transport exists — all three outrank
 * whatever the last frame's `partition_state` happened to say.
 */
export function derivePerchGovernanceMode(
  input: GovernanceInput,
): PerchGovernanceMode {
  if (input.receivedAtMs === null) return "bridge-down";
  if (input.nowMs - input.receivedAtMs > input.staleAfterMs) return "stale";
  // The solo transport serves a committee of one and refuses larger. A
  // deployment that admits peer governors without a networked transport fails
  // closed on every destructive action, so MORE governors is strictly worse
  // today, and the strip has to say so rather than read it as redundancy.
  if (input.totalGovernors > 1) return "fail-closed-no-transport";
  return input.partitionState;
}
