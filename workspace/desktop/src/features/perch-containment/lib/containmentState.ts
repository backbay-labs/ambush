/**
 * The five states of a containment row.
 *
 * `remaining_ms` SATURATES AT ZERO in the daemon, so on its own it cannot tell
 * "expires in an instant" from "expired an hour ago and the sweep failed".
 * `expired` is the field that answers that. The two travel together in one
 * named struct so a caller cannot pass one fact and lose the other, which is
 * exactly how a board ends up rendering a still-contained host as fine.
 */
export type ContainmentFacts = {
  remainingMs: number;
  expired: boolean;
  daemonReachable: boolean;
};

export type ContainmentState =
  | "open"
  | "expiring"
  | "expired-still-listed"
  | "daemon-down-open"
  | "daemon-down-expired";

/** `expiring` is `remaining_ms < 15_000`. */
export const EXPIRING_UNDER_MS = 15_000;

/**
 * Which of the five states a row is in.
 *
 * Daemon reachability is checked FIRST: with the daemon down the board cannot
 * offer early release at all, and that is a different thing to say than
 * "expiring soon".
 */
export function deriveContainmentState(
  facts: ContainmentFacts,
): ContainmentState {
  if (!facts.daemonReachable) {
    return facts.expired ? "daemon-down-expired" : "daemon-down-open";
  }
  if (facts.expired) return "expired-still-listed";
  return facts.remainingMs < EXPIRING_UNDER_MS ? "expiring" : "open";
}

/**
 * `remaining_ms` recomputed from the daemon's `expires_at_ms` and the board's
 * clock — never from a configured TTL, which is what the lease was granted
 * under rather than what is left of it.
 */
export function remainingMsAt(expiresAtMs: number, nowMs: number): number {
  return Math.max(0, expiresAtMs - nowMs);
}
