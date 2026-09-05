/**
 * Turning what the console already reads into a {@link ShiftInput}.
 *
 * Every field here comes from a source the console genuinely has. Two of the
 * plan's fields have no source yet and are rendered as their honest absence
 * rather than as zero: a case's canvas line count and the text under its
 * `## Handoff notes` heading both need the case canvas, which this surface
 * does not fetch per case. `canvasLines: 0` would read as "the canvas is
 * empty" — a claim about the case, not about the console — so those cases
 * carry a canvas the composer prints as `0 lines` only when the canvas was
 * actually read. Until the per-case canvas read lands, `handoffNotes` is null
 * and the operator types the note into the block themselves.
 */

import type {
  PerchHeldActionView,
  PerchThreatClass,
} from "@/shared/api/tauriPerch";

import type { ShiftCase, ShiftInput } from "./reviewSession";

export type ContainmentLike = {
  leaseId: string;
  /** The contained thing, as the daemon scoped it. */
  scopeValue: string;
  remainingMs: number;
  expired: boolean;
};

/**
 * The holds that expired without a decision.
 *
 * Read from the hold's own `expired` flag and the absence of a decision
 * record, not from a remaining-time reading: `remaining_ms` saturates at zero,
 * so a hold that is *about* to expire and one that expired an hour ago read
 * the same there.
 */
export function expiredUndecidedHolds(
  holds: readonly PerchHeldActionView[],
): PerchHeldActionView[] {
  return holds.filter((hold) => hold.expired && hold.decision === null);
}

/** Minutes between a hold's creation and its expiry. Never negative. */
export function expiredAfterMinutes(hold: PerchHeldActionView): number {
  return Math.max(
    0,
    Math.round((hold.expires_at_ms - hold.held_at_ms) / 60_000),
  );
}

/** The distinct case channels a set of holds names. Order is first-seen. */
export function caseChannelsOf(
  holds: readonly PerchHeldActionView[],
): string[] {
  const seen: string[] = [];
  for (const hold of holds) {
    if (hold.case_channel && !seen.includes(hold.case_channel)) {
      seen.push(hold.case_channel);
    }
  }
  return seen;
}

export function containmentsForShift(
  leases: readonly ContainmentLike[],
): ShiftInput["containments"] {
  return leases.map((lease) => ({
    leaseId: lease.leaseId,
    host: lease.scopeValue,
    remainingMs: lease.remainingMs,
    expired: lease.expired,
  }));
}

/**
 * A case seed built from a hold, with the canvas facts absent.
 *
 * `archivedAtMs` is null rather than a guess: the console has not asked the
 * relay whether the channel is archived, and rendering "archived" for a case
 * that is open would tell the next operator to stop looking at it.
 */
/**
 * The Rust enum's custom arm serialises as `{ custom: "…" }`. A consumer that
 * assumed `string` would print `[object Object]` for exactly the threat class
 * nobody has seen before — the one a handoff most needs to name.
 */
function threatClassLabel(value: PerchThreatClass): string {
  return typeof value === "string" ? value : value.custom;
}

export function caseFromHold(hold: PerchHeldActionView): ShiftCase | null {
  if (!hold.case_channel) return null;
  return {
    channelId: hold.case_channel,
    slug: hold.case_channel.slice(0, 8),
    threatClass: threatClassLabel(hold.rationale.threat_class),
    readToMs: null,
    canvasLines: 0,
    openThreadsUnread: 0,
    archivedAtMs: null,
    handoffNotes: null,
  };
}
